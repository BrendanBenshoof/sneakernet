# Todo

## Blockstore

- [ ] Lower tombstone TTL, but renew it whenever the same block is offered again — prevents re-acceptance of recently evicted blocks without holding tombstones longer than necessary

## Transport

- [ ] URL normalization for peer deduplication: the same relay reached via http vs https, trailing slash, or IP vs DNS occupies separate peer-table slots. Dedup is by exact map key and does not catch these variants.

- [ ] PoW floor should be contextual to transport medium: a bridging node serving both LAN and internet peers should apply a lower floor to LAN-origin blocks than to internet-origin blocks. A phone on LAN should not need to meet the same PoW bar as an internet relay submission.

## Protocol cleanup

- [ ] Remove fragmentation fields from v2 plaintext header: `frag_id`, `frag_index`, `frag_total`, `FlagIsFragment`
- [ ] Remove unused `MsgTypeBinary` and `MsgTypeSystem` constants (all messages are text; `msg_type` field may be removable entirely)
