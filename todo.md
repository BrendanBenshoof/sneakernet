# Todo

## Protocol cleanup

- [ ] Remove fragmentation fields from v2 plaintext header: `frag_id`, `frag_index`, `frag_total`, `FlagIsFragment`
- [ ] Remove unused `MsgTypeBinary` and `MsgTypeSystem` constants (all messages are text; `msg_type` field may be removable entirely)
