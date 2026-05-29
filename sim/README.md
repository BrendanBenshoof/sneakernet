# Blockstore DES — storage and eviction simulation

A discrete-event simulation of the sneakernet blockstore to understand how
storage fills, how the eviction policy behaves over time, and what the
advertised `pow_floor` converges to under different load conditions.

## Why this was run

The blockstore evicts blocks by logical priority (highest-wf blocks survive
longest) rather than by hard TTL deadlines. Blocks never leave the store
naturally — only eviction under storage pressure clears them. The simulation
was needed to answer:

- What does the WF distribution look like at steady state under various loads?
- Does the pow_floor signal stabilize, or does it ratchet up forever?
- Under a global relay flood, do locally-authored blocks get squeezed out?
- How long does a block at a given WF level actually survive?

## Bugs found and fixed in the process

**1. `computeMedianWorkFactor` indexes the wrong position**

The intent was "median of a virtual capacity-sized array where empty slots
count as wf=0." The correct index into the sorted actual-WF list is
`len(wfs) - halfCapacity` (the median of the padded array). The code used
`wfs[halfCapacity]` (unpadded list), which equals the correct value only when
the store is 100% full. At partial fill it returns a value deep into the upper
tail — approaching the 75th percentile when 75% full — and over-gates incoming
traffic.

Fix: `return wfs[len(wfs)-halfCapacity], nil`

**2. pow_floor should advertise one below the true median**

If the node advertises the exact median, every block that clears the floor has
wf ≥ median. The median then can only rise, never fall. Under reduced load
the floor gets permanently ratcheted up and the node becomes unreachable.

Advertising `median - 1` allows blocks just below the current median to enter,
be first in line for eviction, and let the floor drift back down if load drops.

Fix: subtract 1 from the computed median before returning.

**3. `TTLFromWorkFactor` used a linear placeholder**

The comment said "Linear for now: BaseTTL × (wf+1)." The intended formula is
φ^(wf/2) days (golden ratio base), giving each additional bit ~27% more
lifetime (√φ multiplier, doubling every ~3 bits). Under full-store pressure
the ordering is all that matters — any monotonically increasing function
produces the same eviction sequence — but the correct formula is used for
correctness and for reasoning about the non-full-store case.

Fix: `math.Pow(phi, float64(wf)/2)` days.

## Key simulation findings

- **The store self-selects for higher PoW under load.** When arrivals exceed
  capacity, wf=0 blocks are the first to be evicted and eventually disappear
  from the store entirely. The WF distribution shifts upward automatically.

- **Without reservations, all tags converge to equal share.** The eviction
  policy targets the tag most over its reservation; with no reservations all
  tags have reservation 0 so the tag with the most blocks gets evicted first,
  driving all tags toward equal count at equilibrium.

- **Reservations work precisely.** With Physical=40%/Lan=30%/Regional=20%/
  Global=10% reservations, the final tag distribution mirrors those ratios
  exactly regardless of relative arrival rates.

- **pow_floor stabilizes, not ratchets.** With the `-1` fix, the floor
  finds a stable level (typically 2–3 under moderate load) where incoming
  traffic is gated without permanently escalating the minimum.

- **High-PoW local blocks survive global floods.** Under a 500 blk/h global
  relay flood with no reservations, Physical blocks (mined to wf≥6) are never
  evicted — their high logical TTL keeps them above the eviction line
  indefinitely. Global blocks absorb 95% of evictions.

- **Cohort survival flattens quickly.** Blocks that survive the initial
  eviction churn tend to stay a long time. Under moderate load, ~60% of a
  midpoint cohort survives the full 15-day simulation window.

## Running

```
python3 sim/blockstore_sim.py [scenario ...]
```

Available scenarios: `default`, `reservation_pressure`, `high_load`,
`high_pow`, `low_pow`. Omit arguments to run all five.
