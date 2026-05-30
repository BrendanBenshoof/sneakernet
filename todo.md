# Todo

## Transport

- [ ] PoW floor should be contextual to transport medium: a bridging node serving both LAN and internet peers should apply a lower floor to LAN-origin blocks than to internet-origin blocks. A phone on LAN should not need to meet the same PoW bar as an internet relay submission.

## Protocol cleanup

- [ ] Remove fragmentation fields from v2 plaintext header: `frag_id`, `frag_index`, `frag_total`, `FlagIsFragment`
- [ ] Remove unused `MsgTypeBinary` and `MsgTypeSystem` constants (all messages are text; `msg_type` field may be removable entirely)
