#!/usr/bin/env python3
"""
Discrete Event Simulation of sneakernet blockstore storage and eviction.

Models BadgerStore / FlatFileStore semantics:
  - Blocks NEVER expire naturally — they persist until evicted by storage pressure.
  - TTL (= 24h * (wf+1)) is only a priority metric: "logicalExpiry = createdAt + TTL".
    The block with the lowest logicalExpiry is "most overdue" and evicted first.
  - Eviction picks the tag furthest over its reservation, then that tag's
    soonest-logicalExpiry block.
  - StorageLimit triggers eviction after each Put (evictBatch=10 extra per trigger).
  - Tombstones block re-acceptance until the block's logical expiry (remaining
    TTL at eviction time). If a block is already overdue when evicted, no
    tombstone is written — a fresh copy with a new stamp is welcome.

Run:  python3 sim/blockstore_sim.py [scenario ...]
Available scenarios: default  reservation_pressure  high_load  high_pow  low_pow
"""

import heapq
import math
import random
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional

# ── constants matching blockstore ─────────────────────────────────────────────

BLOCK_SIZE_BYTES     = 17 + 4096           # blockValHeaderSize + PayloadSize
# Tombstone key: tombPrefix(1) + id(32) = 33 bytes. BadgerDB adds per-entry
# metadata (version, expiry timestamp, internal overhead) bringing the real
# on-disk cost to ~64 bytes. Tombstones live for TOMBSTONE_TTL_H and count
# against the storage limit just like blocks do (lsm+vlog includes them).
TOMBSTONE_SIZE_BYTES = 64
PHI                  = (1 + 5 ** 0.5) / 2  # golden ratio ≈ 1.618
EVICT_BATCH          = 10

MiB = 1024 * 1024
GiB = 1024 * MiB


class Tag(IntEnum):
    Physical = 0
    Lan      = 1
    Regional = 2
    Global   = 3


def ttl_hours(wf: int) -> float:
    """φ^(wf/2) days. Monotonically increasing — ordering is all that matters under pressure."""
    return PHI ** (wf / 2) * 24

def logical_expiry(created_at: float, wf: int) -> float:
    """Priority metric. Blocks past this age are 'overdue' but not removed."""
    return created_at + ttl_hours(wf)


# ── block ─────────────────────────────────────────────────────────────────────

@dataclass
class Block:
    id:         int
    wf:         int
    tag:        Tag
    created_at: float

    def logical_expiry(self) -> float:
        return logical_expiry(self.created_at, self.wf)


# ── event queue ───────────────────────────────────────────────────────────────

ARRIVE = 0

@dataclass(order=True)
class Event:
    time:     float
    kind:     int
    wf:       int  = field(default=0,          compare=False)
    tag:      Tag  = field(default=Tag.Global, compare=False)


# ── store ─────────────────────────────────────────────────────────────────────

class SimStore:
    """
    In-memory model of BadgerStore/FlatFileStore eviction semantics.

    Key invariant: blocks are NEVER removed by age alone. Only eviction
    (triggered when usage exceeds storage_limit) removes blocks.
    """

    def __init__(self, storage_limit: int, reservations: dict[Tag, int]):
        self.storage_limit = storage_limit
        self.reservations  = reservations
        self.blocks: dict[int, Block] = {}
        self.tombstones: dict[int, float] = {}      # id -> tombstone_expires_at

        self.arrivals_total  = 0
        self.evictions_total = 0
        self.rejects_total   = 0

        self.eviction_log: list[tuple[float, int, Tag]] = []
        self.arrival_log:  list[tuple[float, int, Tag]] = []

    # ── api ───────────────────────────────────────────────────────────────────

    def put(self, block: Block, now: float) -> bool:
        if block.id in self.tombstones and self.tombstones[block.id] > now:
            self.rejects_total += 1
            return False
        if block.id in self.blocks:
            if self.blocks[block.id].wf >= block.wf:
                return False

        self.blocks[block.id] = block
        self.arrivals_total += 1
        self.arrival_log.append((now, block.wf, block.tag))

        if self.storage_limit > 0 and self._usage() > self.storage_limit:
            needed = (self._usage() - self.storage_limit) // BLOCK_SIZE_BYTES + EVICT_BATCH + 1
            self._evict(int(needed), now)

        return True

    def prune_tombstones(self, now: float):
        self.tombstones = {k: v for k, v in self.tombstones.items() if v > now}

    # ── queries ───────────────────────────────────────────────────────────────

    def count(self) -> int:
        return len(self.blocks)

    def capacity(self) -> int:
        return self.storage_limit // BLOCK_SIZE_BYTES

    def fill_fraction(self) -> float:
        cap = self.capacity()
        return len(self.blocks) / cap if cap else 0.0

    def wf_histogram(self) -> dict[int, int]:
        h: dict[int, int] = defaultdict(int)
        for b in self.blocks.values():
            h[b.wf] += 1
        return dict(h)

    def tag_counts(self) -> dict[Tag, int]:
        h: dict[Tag, int] = defaultdict(int)
        for b in self.blocks.values():
            h[b.tag] += 1
        return dict(h)

    def pow_floor(self) -> int:
        """
        Median of a virtual capacity-sized array, empty slots treated as wf=0.

        Pad actual WF list with (capacity-N) leading zeros, sort, return index
        halfCapacity.  That index into the *actual* list is N - halfCapacity.

        The current Go code uses wfs[halfCapacity] (indexes the unpadded list),
        which equals the correct value only when N == capacity.  The fix is:
            return wfs[len(wfs)-halfCapacity], nil
        """
        cap      = self.capacity()
        half_cap = cap // 2
        n        = len(self.blocks)
        if n <= half_cap:
            return 0
        wfs = sorted(b.wf for b in self.blocks.values())
        median = wfs[n - half_cap]
        return max(0, median - 1)  # advertise one below so peers can ramp down

    def overdue_fraction(self, now: float) -> float:
        """Fraction of stored blocks past their logical TTL (overdue but still stored)."""
        if not self.blocks:
            return 0.0
        overdue = sum(1 for b in self.blocks.values() if b.logical_expiry() < now)
        return overdue / len(self.blocks)

    # ── internals ─────────────────────────────────────────────────────────────

    def _usage(self) -> int:
        return (len(self.blocks) * BLOCK_SIZE_BYTES
                + len(self.tombstones) * TOMBSTONE_SIZE_BYTES)

    def _evict(self, n: int, now: float) -> int:
        per_tag: dict[Tag, list[Block]] = defaultdict(list)
        tag_usage: dict[Tag, int]       = defaultdict(int)
        for b in self.blocks.values():
            per_tag[b.tag].append(b)
            tag_usage[b.tag] += BLOCK_SIZE_BYTES
        for t in per_tag:
            per_tag[t].sort(key=lambda b: b.logical_expiry())

        evicted = 0
        while evicted < n:
            target = None
            max_over = -float("inf")
            for t, usage in tag_usage.items():
                if not per_tag[t]:
                    continue
                over = usage - self.reservations.get(t, 0)
                if over > max_over:
                    max_over = over
                    target = t
            if target is None:
                break

            victim = per_tag[target].pop(0)
            tag_usage[target] -= BLOCK_SIZE_BYTES
            if victim.id in self.blocks:
                del self.blocks[victim.id]
                # Tombstone lives until the block's logical expiry so it
                # cannot be re-accepted before it would have naturally expired.
                # If already overdue, no tombstone — a fresh copy is welcome.
                remaining = victim.logical_expiry() - now
                if remaining > 0:
                    self.tombstones[victim.id] = victim.logical_expiry()
                self.evictions_total += 1
                self.eviction_log.append((now, victim.wf, victim.tag))
                evicted += 1

        return evicted


# ── wf samplers ───────────────────────────────────────────────────────────────

def geometric_sampler(rng: random.Random) -> Callable[[], int]:
    """Models random (unmined) stamps: P(wf=k) = (1/2)^(k+1). Mean ~1."""
    def sample() -> int:
        u = rng.random()
        return max(0, int(math.log(max(u, 1e-15)) / math.log(0.5)))
    return sample

def mined_sampler(rng: random.Random, target: int) -> Callable[[], int]:
    """Mined to at least `target` bits, geometric tail above."""
    def sample() -> int:
        wf = target
        while rng.random() < 0.5:
            wf += 1
        return wf
    return sample

def fixed_sampler(wf: int) -> Callable[[], int]:
    return lambda: wf


# ── scenario ──────────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    name:           str
    storage_limit:  int
    reservations:   dict[Tag, int]
    arrival_rates:  dict[Tag, float]   # blocks/hour
    wf_samplers:    dict[Tag, Callable]
    duration_hours: float
    description:    str = ""


def make_scenarios(rng: random.Random) -> dict[str, Scenario]:
    geo  = lambda: geometric_sampler(rng)
    mine = lambda t: mined_sampler(rng, t)

    # Steady-state block count ≈ sum(rate * avg_ttl).
    # At full store, new blocks evict old ones; fill stays near 100%.
    # Below capacity, the store just fills slowly and no eviction happens.
    # These scenarios are sized so steady-state >> capacity to force eviction.

    scenarios: dict[str, Scenario] = {}

    # 64 MiB store, balanced mix — fills up quickly, continuous eviction
    scenarios["default"] = Scenario(
        name="default",
        description="64 MiB store, balanced tag mix, geometric PoW — store fills, eviction kicks in",
        storage_limit=64 * MiB,
        reservations={},
        arrival_rates={Tag.Physical: 10, Tag.Lan: 20, Tag.Regional: 30, Tag.Global: 50},
        wf_samplers={Tag.Physical: mine(4), Tag.Lan: mine(2),
                     Tag.Regional: geo(),   Tag.Global: geo()},
        duration_hours=30 * 24,   # 30 days
    )

    # same load, explicit reservations favouring Physical/Lan over cheap Global blocks
    scenarios["reservation_pressure"] = Scenario(
        name="reservation_pressure",
        description="64 MiB, reservations Physical=40% Lan=30% Regional=20% Global=10%",
        storage_limit=64 * MiB,
        reservations={
            Tag.Physical: int(0.40 * 64 * MiB),
            Tag.Lan:      int(0.30 * 64 * MiB),
            Tag.Regional: int(0.20 * 64 * MiB),
            Tag.Global:   int(0.10 * 64 * MiB),
        },
        arrival_rates={Tag.Physical: 10, Tag.Lan: 20, Tag.Regional: 30, Tag.Global: 50},
        wf_samplers={Tag.Physical: mine(4), Tag.Lan: mine(2),
                     Tag.Regional: geo(),   Tag.Global: geo()},
        duration_hours=30 * 24,
    )

    # heavy global flood — can it squeeze out local content?
    scenarios["high_load"] = Scenario(
        name="high_load",
        description="64 MiB store, global flood (500 blk/h), no reservations",
        storage_limit=64 * MiB,
        reservations={},
        arrival_rates={Tag.Physical: 5, Tag.Lan: 10, Tag.Regional: 30, Tag.Global: 500},
        wf_samplers={Tag.Physical: mine(6), Tag.Lan: mine(4),
                     Tag.Regional: mine(2), Tag.Global: geo()},
        duration_hours=14 * 24,
    )

    # everyone mines hard — what's the steady-state wf floor?
    scenarios["high_pow"] = Scenario(
        name="high_pow",
        description="64 MiB store, all blocks mined to wf >= 6",
        storage_limit=64 * MiB,
        reservations={},
        arrival_rates={Tag.Physical: 10, Tag.Lan: 20, Tag.Regional: 20, Tag.Global: 50},
        wf_samplers={t: mine(6) for t in Tag},
        duration_hours=30 * 24,
    )

    # wf=0 flood — 1-day TTL blocks pile up and get recycled aggressively
    scenarios["low_pow"] = Scenario(
        name="low_pow",
        description="32 MiB store, all blocks wf=0 (24h logical TTL), high arrival rate",
        storage_limit=32 * MiB,
        reservations={},
        arrival_rates={t: 100 for t in Tag},
        wf_samplers={t: fixed_sampler(0) for t in Tag},
        duration_hours=7 * 24,
    )

    return scenarios


# ── simulation ────────────────────────────────────────────────────────────────

class Simulation:
    def __init__(self, scenario: Scenario, seed: int = 42):
        self.s     = scenario
        self.rng   = random.Random(seed)
        self.store = SimStore(scenario.storage_limit, scenario.reservations)

        self._queue: list[Event] = []
        self.now     = 0.0
        self.next_id = 0

        self.snapshots: list[dict] = []
        self._snap_interval = scenario.duration_hours / 200

        # Cohort: blocks that arrive in a 1-hour window at the simulation midpoint.
        mid = scenario.duration_hours / 2
        self._cohort_window = (mid - 0.5, mid + 0.5)
        self._cohort_ids: set[int] = set()
        self._cohort_log: list[tuple[float, int]] = []
        self._cohort_snap_interval = scenario.duration_hours / 100

        self._floor_rejects = 0   # blocks turned away because wf < pow_floor

    def run(self) -> list[dict]:
        for tag in self.s.arrival_rates:
            self._schedule_arrival(tag)

        last_snap        = -self._snap_interval
        last_cohort_snap = self._cohort_window[1]
        n_events = 0

        while self._queue:
            ev = heapq.heappop(self._queue)
            if ev.time > self.s.duration_hours:
                break
            self.now = ev.time
            n_events += 1

            if self.now - last_snap >= self._snap_interval:
                self.snapshots.append(self._snap())
                last_snap = self.now

            if self._cohort_ids and self.now - last_cohort_snap >= self._cohort_snap_interval:
                alive = sum(1 for bid in self._cohort_ids if bid in self.store.blocks)
                self._cohort_log.append((self.now - self._cohort_window[0], alive))
                last_cohort_snap = self.now

            # All events are ARRIVE — gate on pow_floor before storing
            if ev.wf < self.store.pow_floor():
                self._floor_rejects += 1
            else:
                bid   = self.next_id; self.next_id += 1
                block = Block(id=bid, wf=ev.wf, tag=ev.tag, created_at=self.now)
                stored = self.store.put(block, self.now)
                if stored and self._cohort_window[0] <= self.now <= self._cohort_window[1]:
                    self._cohort_ids.add(bid)
            self._schedule_arrival(ev.tag)

            if n_events % 50_000 == 0:
                self.store.prune_tombstones(self.now)

        self.snapshots.append(self._snap())
        if self._cohort_ids:
            alive = sum(1 for bid in self._cohort_ids if bid in self.store.blocks)
            self._cohort_log.append((self.now - self._cohort_window[0], alive))

        return self.snapshots

    def _schedule_arrival(self, tag: Tag):
        rate = self.s.arrival_rates.get(tag, 0.0)
        if rate <= 0:
            return
        dt = self.rng.expovariate(rate)
        t  = self.now + dt
        if t < self.s.duration_hours:
            wf = self.s.wf_samplers[tag]()
            heapq.heappush(self._queue, Event(t, ARRIVE, wf=wf, tag=tag))

    def _snap(self) -> dict:
        return {
            "time":          self.now,
            "blocks":        self.store.count(),
            "tombstones":    len(self.store.tombstones),
            "fill_pct":      self.store.fill_fraction() * 100,
            "evictions":     self.store.evictions_total,
            "arrivals":      self.store.arrivals_total,
            "rejects":       self.store.rejects_total,
            "floor_rejects": self._floor_rejects,
            "overdue_pct":   self.store.overdue_fraction(self.now) * 100,
            "wf_dist":       self.store.wf_histogram(),
            "tag_dist":      {t.name: n for t, n in self.store.tag_counts().items()},
            "pow_floor":     self.store.pow_floor(),
        }


# ── output helpers ────────────────────────────────────────────────────────────

BAR_WIDTH = 50

def sparkline(values: list[float], width: int = BAR_WIDTH) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    chars = " ▁▂▃▄▅▆▇█"
    out = []
    for v in values:
        idx = int((v - lo) / (hi - lo + 1e-9) * (len(chars) - 1))
        out.append(chars[idx])
    step = max(1, len(out) // width)
    return "".join(out[i] for i in range(0, len(out), step))[:width]

def print_fill_timeline(snapshots: list[dict], duration_hours: float):
    fills    = [s["fill_pct"]       for s in snapshots]
    overdues = [s["overdue_pct"]    for s in snapshots]
    floors = [s["pow_floor"]  for s in snapshots]
    tombs  = [s["tombstones"] for s in snapshots]
    cap    = snapshots[-1]["blocks"] + snapshots[-1]["tombstones"]  # approx
    print(f"\n  Fill % over {duration_hours/24:.0f} days  (0%{'─'*(BAR_WIDTH-4)}100%):")
    print(f"  fill:       {sparkline(fills)}")
    print(f"  overdue:    {sparkline(overdues)}")
    print(f"  pow_floor:  {sparkline(floors)}")
    print(f"  tombstones: {sparkline(tombs)}")
    print(f"  peak={max(fills):.1f}%  overdue@end={overdues[-1]:.1f}%  "
          f"pow_floor@end={floors[-1]}  tombs@end={tombs[-1]:,}")

def print_wf_distribution(label: str, wf_dist: dict[int, int]):
    total  = sum(wf_dist.values()) or 1
    max_wf = max(wf_dist.keys(), default=0)
    print(f"\n  {label}")
    for wf in range(max_wf + 1):
        n   = wf_dist.get(wf, 0)
        pct = n / total * 100
        bar = "█" * int(pct / 2)
        print(f"    wf={wf:2d}  TTL={ttl_hours(wf):5.0f}h  {bar:25s}  {pct:5.1f}%  ({n:,})")

def print_tag_distribution(label: str, tag_dist: dict[str, int]):
    total = sum(tag_dist.values()) or 1
    print(f"\n  {label}")
    for tag in Tag:
        n   = tag_dist.get(tag.name, 0)
        pct = n / total * 100
        bar = "█" * int(pct / 2)
        print(f"    {tag.name:10s}  {bar:25s}  {pct:5.1f}%  ({n:,})")

def print_eviction_breakdown(eviction_log: list[tuple[float, int, Tag]]):
    if not eviction_log:
        print("\n  No evictions occurred.")
        return
    by_wf:  dict[int, int] = defaultdict(int)
    by_tag: dict[Tag, int] = defaultdict(int)
    for _, wf, tag in eviction_log:
        by_wf[wf]   += 1
        by_tag[tag] += 1
    total = len(eviction_log)
    print(f"\n  Evictions by work factor (total {total:,}):")
    for wf in sorted(by_wf):
        pct = by_wf[wf] / total * 100
        bar = "█" * int(pct / 2)
        print(f"    wf={wf:2d}  {bar:25s}  {pct:5.1f}%  ({by_wf[wf]:,})")
    print(f"\n  Evictions by tag:")
    for tag in Tag:
        n = by_tag.get(tag, 0)
        print(f"    {tag.name:10s}  {n/total*100:5.1f}%  ({n:,})")

def print_survival_curve(cohort_log: list[tuple[float, int]], cohort_size: int):
    if not cohort_log or cohort_size == 0:
        print("\n  (no cohort data)")
        return
    print(f"\n  Cohort survival ({cohort_size} blocks at simulation midpoint):")
    print(f"  {'age':>7}  {'alive':>6}  curve")
    prev_age = -999.0
    for age, alive in cohort_log:
        if age - prev_age < 12 and age < cohort_log[-1][0]:
            continue
        pct = alive / cohort_size * 100
        bar = "█" * int(pct / 4)
        print(f"  {age:6.0f}h   {pct:5.1f}%  {bar}")
        prev_age = age


# ── main ──────────────────────────────────────────────────────────────────────

def run_scenario(sc: Scenario, seed: int = 42):
    cap_blocks = sc.storage_limit // BLOCK_SIZE_BYTES
    cap_mib    = sc.storage_limit / MiB
    total_rate = sum(sc.arrival_rates.values())

    print(f"\n{'═'*65}")
    print(f"  SCENARIO: {sc.name}")
    print(f"  {sc.description}")
    print(f"{'─'*65}")
    print(f"  Storage   : {cap_mib:.0f} MiB  ({cap_blocks:,} blocks)")
    print(f"  Duration  : {sc.duration_hours/24:.0f} days")
    print(f"  Arrivals  : {total_rate:.0f} blk/h  "
          f"({total_rate*sc.duration_hours:,.0f} total expected)")
    if sc.reservations:
        parts = "  ".join(f"{t.name}={sc.reservations.get(t,0)/MiB:.0f}MiB" for t in Tag)
        print(f"  Reserved  : {parts}")
    else:
        print(f"  Reserved  : none (no per-tag guarantees)")

    sim = Simulation(sc, seed=seed)
    print(f"\n  Simulating...", end="", flush=True)
    snaps = sim.run()
    print(f" done  ({sim.next_id:,} blocks processed)")

    store = sim.store
    final = snaps[-1]
    early = snaps[max(0, len(snaps) // 10)]
    mid   = snaps[len(snaps) // 2]

    print(f"\n  ── Summary ──")
    print(f"  Accepted  : {store.arrivals_total:,}")
    print(f"  Evicted   : {store.evictions_total:,}  "
          f"({store.evictions_total / max(store.arrivals_total, 1) * 100:.1f}% of arrivals)")
    print(f"  Tombstone rejects : {store.rejects_total:,}")
    print(f"  Live at end       : {final['blocks']:,}  ({final['fill_pct']:.1f}% full)")
    print(f"  Overdue at end    : {final['overdue_pct']:.1f}%  "
          f"(stored past logical TTL, awaiting eviction)")
    tomb_bytes = final['tombstones'] * TOMBSTONE_SIZE_BYTES
    print(f"  pow_floor at end  : {final['pow_floor']}")
    print(f"  Tombstones at end : {final['tombstones']:,}  "
          f"({tomb_bytes/MiB:.2f} MiB tombstone overhead)")
    print(f"  Floor rejects     : {final['floor_rejects']:,}")

    print_fill_timeline(snaps, sc.duration_hours)
    print_wf_distribution("WF distribution — early (10%):", early["wf_dist"])
    print_wf_distribution("WF distribution — midpoint:",    mid["wf_dist"])
    print_wf_distribution("WF distribution — final:",       final["wf_dist"])
    print_tag_distribution("Tag distribution — final:",      final["tag_dist"])
    print_eviction_breakdown(store.eviction_log)
    print_survival_curve(sim._cohort_log, len(sim._cohort_ids))
    print()


def main():
    rng = random.Random(0)
    scenarios = make_scenarios(rng)

    requested = sys.argv[1:] or list(scenarios.keys())
    unknown   = [n for n in requested if n not in scenarios]
    if unknown:
        print(f"Unknown scenario(s): {unknown}")
        print(f"Available: {list(scenarios.keys())}")
        sys.exit(1)

    for name in requested:
        run_scenario(scenarios[name])


if __name__ == "__main__":
    main()
