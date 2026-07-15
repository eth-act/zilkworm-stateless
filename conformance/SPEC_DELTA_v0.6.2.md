# Contract delta: guest (ere-guests v0.13.0) → tests-zkevm@v0.6.2

The guest currently implements the ere-guests v0.13.0 wire contract; the
EEST fixtures (`tests-zkevm@v0.6.2`) encode a newer spec. This is the exact
realignment work queue, derived from
`src/ethereum/forks/amsterdam/stateless_ssz.py` at the release tag (a copy
of the relevant definitions is kept alongside the conformance tooling).

## 1. Schema prefix — BREAKING

| | v0.13.0 (current guest) | v0.6.2 fixtures |
|---|---|---|
| prefix | `0x0001`, fork-agnostic | `fork_index << 8 \| revision`, big-endian — Amsterdam = `0x1501` |
| payload shape | selected by `chain_config.active_fork.fork` | **fixed by the schema id** (one schema per fork; rev `0x01` = SSZ `SszStatelessInput`) |

→ Guest should dispatch on schema id: keep `0x0001` (legacy, zkboost/
ere-guests v0.13.0) and add `0x1501` (Amsterdam rev 1). Unknown ids →
canonical failure output.

## 2. ChainConfig — SIMPLIFIED (breaking for decode + echo + htr-free)

v0.6.2: `SszChainConfig{ chain_id: u64, active_fork: SszForkConfig }`,
`SszForkConfig{ activation: SszForkActivation }` — **no `fork` field, no
`blob_schedule`**. Fork identity lives in the schema id; blob parameters are
the spec's Amsterdam constants (not carried in the input).
`SszForkActivation` unchanged (`block_number`/`timestamp` as `List[u64,1]`).

→ New decode + byte-exact echo for the smaller config; execution config =
Amsterdam rules; blob params from the spec (silkworm's per-fork table).

## 3. ExecutionRequests — 5 lists now (breaking for decode + htr)

Adds after `consolidations`:
- `builder_deposits: List[SszBuilderDepositRequest, 2^6]` — fixed 184 B:
  `pubkey[48] ‖ withdrawal_credentials[32] ‖ amount u64 ‖ signature[96]`
- `builder_exits: List[SszBuilderExitRequest, 2^4]` — fixed 68 B:
  `source_address[20] ‖ pubkey[48]`

→ Container fixed part 12→20 bytes (5 offsets); htr = 5 leaves (padded to
8); two new item decoders + item htrs.

## 4. ExecutionPayload — matches our Gloas/V4 shape, one htr limit change

19 fields incl. `block_access_list` + `slot_number` (Amsterdam-fixed — no
17-field variant under this schema). **`block_access_list` limit is now
`MAX_BYTES_PER_TRANSACTION` (2^30)**, previously 2^24 — changes the BAL
leaf's merkle depth.

## 5. public_keys — encoding change (breaking for decode)

`SszList[ByteVector[65], 2^15]`: items are **fixed-size 65** → the list is
packed fixed-size items (no per-item offset table). Current guest decodes it
as a bytelist-list (offset table). Also max 2^15 (was 2^20).

## 6. SSZ maxima (decode-bounds / htr where noted)

| Constant | guest today | v0.6.2 |
|---|---|---|
| MAX_WITHDRAWALS_PER_PAYLOAD | 16 ✓ | 2^4 = 16 |
| MAX_BLOCK_ACCESS_LIST bytes | 2^24 | **2^30** (htr!) |
| MAX_WITNESS_NODES | 2^20 | **2^22** |
| MAX_BYTES_PER_WITNESS_NODE | 2^20 | **2^10** |
| MAX_WITNESS_CODES | 2^16 | **2^18** |
| MAX_BYTES_PER_CODE | 2^24 | **2^16** |
| MAX_PUBLIC_KEYS | 2^20 | **2^15** |
| builder deposits / exits | — | 2^6 / 2^4 |

(Witness/pubkey maxima don't enter any hash the guest computes — decode
bounds only — but the BAL limit does.)

## 7. Output

`SszStatelessValidationResult{root, success, chain_config}` — same 3-field
shape; `chain_config` echo is the new simpler config. Offset stays 37.

## 8. ProtocolFork numbering — CHANGED

Amsterdam = `0x15` (21) in this spec (was 24 in ere-guests v0.13.0's enum).
Under the new schema the guest no longer needs the enum for decoding (the
schema id carries the fork), but any internal mapping must not reuse the old
discriminants.

## Compatibility strategy

Dual-schema guest: `0x0001` → existing v0.13.0 path (zkboost today),
`0x1501` → new Amsterdam path (EEST conformance). Drop the legacy path when
ere-guests/zkboost move to the schema-id-versioned contract.
