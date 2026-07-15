# Amsterdam EVM port plan — silkworm (zilkworm) + evmone (zvm1)

Status: **design + foundation**. The 0x1501 wire path is done and byte-exact;
the remaining 20,983/24,586 EEST failures are all "block should validate,
silkworm says no" — the execution engine lacks the Amsterdam EIP set.
Authoritative reference: `ethereum/execution-specs` branch `forks/amsterdam`
(sparse clone under the session scratchpad, `eels/src/ethereum/forks/amsterdam`).

## The core model change: two gas dimensions

Amsterdam is not a repricing patch. EIP-8037/8038 split gas into **regular
gas** and **state gas** (state-creation priced per byte: `COST_PER_STATE_BYTE
= 1530`), and EIP-7778 makes the header's `gas_used` =
`max(block_regular_gas, block_state_gas)` with refunds excluded from block
accounting. Every EVM frame carries two pools:

- `gas_left` (regular) and `state_gas_left` (reservoir).
- `tx.gas` may exceed `TX_MAX_GAS_LIMIT` (16,777,216 = EIP-7825 cap): the
  regular dimension is capped at `TX_MAX_GAS_LIMIT - intrinsic.regular`; the
  excess seeds the frame's `state_gas_reservoir`.
- `charge_state_gas`: draw from the reservoir first, spill into `gas_left`
  when empty (tracked as `state_gas_spilled`).
- On revert/halt of a frame: `refill_frame_state_gas` — state gas is
  credited BACK (LIFO: spilled → gas_left first, then reservoir), because the
  state it paid for rolls back with the frame.
- EIP-7702 delegations applied at the top frame survive dispatch failure, so
  their state gas is pinned via `commit_frame_state_gas`.
- Child frames: parent passes both pools; on success the parent reabsorbs
  both + `state_gas_spilled`; on error only `gas_left` + reservoir (child
  already refilled).
- Receipts: `cumulative_gas_used` uses the post-refund, post-floor tx gas.
- Refund rule unchanged (min(used/5, counter)), but applied only to the
  user-paid dimension, never to block accounting.

State gas charges (per EELS `StateGasCosts` / call sites):
- New account (tx target creation, value transfer to dead account, CALL to
  dead account with value, CREATE target): `120 * 1530 = 183,600`.
- New storage slot (SSTORE zero→nonzero): `64 * 1530 = 97,920`.
- EIP-7702 auth tuple base: `23 * 1530 = 35,190` (plus regular
  `REGULAR_PER_AUTH_BASE_COST`).
- Code deposit: `len(code) * 1530` state gas + keccak-per-word regular gas
  (replaces the flat 200/byte deposit charge... note: `CODE_DEPOSIT_PER_BYTE
  = 200` remains in GasCosts but deposit charging in
  `process_create_message` uses keccak words regular + per-byte state gas).

## Key regular-gas constants (EELS amsterdam `GasCosts`)

| Constant | Value | Replaces |
|---|---|---|
| TX_BASE | 12,000 | 21,000 (EIP-2780) |
| TX_VALUE_COST | 4,244 | — |
| TRANSFER_LOG_COST | 1,756 | — (EIP-7708) |
| TX_DATA_TOKEN_STANDARD | 4 | 4 |
| TX_DATA_TOKEN_FLOOR | 16 | 10 (EIP-7976) |
| COLD_ACCOUNT_ACCESS | 3,000 | 2,600 (EIP-8038) |
| COLD_STORAGE_ACCESS | 3,000 | 2,100 (EIP-8038) |
| WARM_ACCESS | 100 | 100 |
| STORAGE_WRITE | 10,000 | SSTORE 2,900/5,000 net schedule |
| CALL_VALUE | 10,300 (ACCOUNT_WRITE 8,000 + stipend 2,300) | 9,000 |
| ACCOUNT_WRITE | 8,000 | — |
| CREATE_ACCESS | ACCOUNT_WRITE + COLD_STORAGE_ACCESS = 11,000 | 32,000 TX_CREATE stays for tx-level? (TX_CREATE = 32,000 remains) |
| TX_ACCESS_LIST_ADDRESS | = COLD_ACCOUNT_ACCESS = 3,000 (+16/token floor) | 2,400 (EIP-7981) |
| TX_ACCESS_LIST_STORAGE_KEY | = COLD_STORAGE_ACCESS = 3,000 | 1,900 |
| MAX_CODE_SIZE | 0x10000 (64 KiB) | 24,576 (EIP-7954) |
| MAX_INIT_CODE_SIZE | 0x20000 | 49,152 |
| PRECOMPILE_* | several repriced (e.g. ECMUL 6,000→? see gas.py; P256VERIFY 6,900) | — |
| Blob schedule | {14, 21, 11684671} | = silkworm bpo2 entry |
| REFUND_STORAGE_CLEAR | see gas.py expr | 4,800 |

Intrinsic gas (EELS `calculate_intrinsic_cost`, verified against fixture
`multi_transaction_gas_accounting__t3_b0` tx2 = 15,064):

```
regular = TX_BASE
        + recipient_gas          # create: CREATE_ACCESS (+TRANSFER_LOG if value)
                                 # call:   COLD_ACCOUNT_ACCESS
                                 #         (+TRANSFER_LOG+TX_VALUE_COST if value)
                                 # self-transfer: 0
        + init_code_cost         # creates only (2/word)
        + tokens(data) * 4
        + access_list: n_addr*3000 + n_key*3000 + floor_tokens*16
        + n_auth * REGULAR_PER_AUTH_BASE_COST
floor   = (len(data)*4 + access_list_floor_tokens) * 16 + TX_BASE + recipient_gas
charged = max at settlement: tx_gas_used = max(after_refund, floor)
validate: intrinsic.regular <= TX_MAX_GAS_LIMIT, floor <= TX_MAX_GAS_LIMIT,
          tx.gas >= regular AND tx.gas >= floor (see validate_transaction)
```

NEW_ACCOUNT state gas for the tx recipient is charged **at the top frame**
(`prepare_dispatch`), not in intrinsic: creation target not in pre-state, or
value transfer to a not-alive recipient.

## EIP-7708 transfer logs

`emit_transfer_log(sender, recipient, amount)` — LOG3 from
`SYSTEM_ADDRESS = 0xfff...ffe` (20 bytes, `0xfffffffffffffffffffffffffffffffffffffffe`),
topics = [keccak("Transfer(address,address,uint256)"), pad32(sender),
pad32(recipient)], data = amount as be-bytes32. Emitted at exactly two sites:
1. `process_message`: any value move where `caller != current_target`
   (includes the tx-level top frame transfer).
2. SELFDESTRUCT: originator → beneficiary sweep.
NOT for: withdrawals, fee payments, gas refunds (those use `create_ether`).
These logs join the frame's log list (revert discards them) and therefore
change receipts root + bloom of every value-moving tx.

## EIP-8246: selfdestruct no burn

`accounts_to_delete` processing becomes `clear_account_preserving_balance`
(code/nonce/storage cleared, balance kept — even when beneficiary == self).

## Block-level (silkworm processor / rule set)

- `block_output.block_gas_used += max(tx_gas_before_refund - state_gas,
  floor)`; `block_state_gas_used += state_gas`; header check:
  `max(block_gas_used, block_state_gas_used) == header.gas_used`.
- Per-tx block-budget checks BOTH dimensions
  (fork.py `check_transaction` 570-585).
- Gas limit min 5,000, adjustment factor 1,024 (unchanged).
- EIP-7928 BAL: header `block_access_list_hash` must equal keccak(rlp(BAL));
  the BAL contents must match execution (builder in EELS
  `block_access_lists.py` + `state_tracker.py`: per-tx touched accounts /
  slots / code / balance / nonce changes with strict ordering and
  block_access_index numbering incl. withdrawals as a final pseudo-tx).
- EIP-7843: SLOTNUM opcode pushes `block_env.slot_number` (from the payload's
  `slot_number`); needs plumbing silkworm → evmc tx_context (no standard
  field — zvm1 evmc extension or side channel) + new evmone instruction.
- EIP-8282: builder deposit/exit requests — general-purpose requests
  processing extended (fork.py `process_general_purpose_requests`).
- EIP-7997: deterministic factory predeploy — state-level, comes in via
  witness; no engine change expected.
- EIP-7934: block RLP limit — n/a to stateless guest? (engine payload
  already SSZ; check fixtures under osaka/eip7934.)

## Repo mapping

| Piece | Where |
|---|---|
| amsterdam_time switch, revision → EVMC_AMSTERDAM, blob params | zilkworm `zilk_core/core/chain/config.{hpp,cpp}` — **DONE** |
| Amsterdam header fields (BAL hash, slot number) | zilkworm `core/types/block.{hpp,cpp}` — **DONE** (fa7255f) |
| Intrinsic gas + floor | zilkworm `core/protocol/intrinsic_gas.{hpp,cpp}` + processor floor settle |
| Tx settlement, dual counters, receipts, EIP-7778 | zilkworm `core/execution/processor.cpp` |
| Transfer logs (tx-level + host) | processor + `core/execution/evm.cpp` host (call value transfer path) |
| Selfdestruct no burn | evm.cpp host selfdestruct + processor destruct pass |
| Dual gas pools in frames | zvm1 `lib/evmone/execution_state.hpp`, `baseline_execution.cpp`, call/create instr — the big one; needs an evmc extension to pass reservoir/spill across Host::call |
| SSTORE/COLD repricing tables | zvm1 `instructions_traits.hpp`, `instructions_storage.cpp` (Amsterdam rows currently inherit London) |
| DUPN/SWAPN/EXCHANGE | zvm1 — **already implemented upstream** (cost 3, legacy at AMSTERDAM) |
| SLOTNUM | zvm1 new opcode + context plumbing |
| MAX_CODE_SIZE 64 KiB | zvm1 limits + silkworm param.hpp |
| BAL build/validate | new zilkworm module (order-sensitive; EELS block_access_lists.py is the reference) + guest wiring of payload BAL bytes |
| Precompile repricings | zvm1 precompiles cost tables / silkworm precompile.cpp |

## Staging (fixture-leverage order)

1. **Stage 1 — tx-level gas w/o dual-dimension frames**: intrinsic formula,
   floor, EIP-7825-as-regular-cap, transfer logs, selfdestruct-no-burn,
   receipts/7778 dual counters, evmone Amsterdam gas-table rows (cold 3000,
   SSTORE 10000 flat write, CALL_VALUE 10300, access-list costs), code size.
   State gas approximated as regular spill-only (reservoir = tx.gas excess)
   — correct for txs whose gas ≤ 16,777,216 and that don't revert after
   state creation (the refill asymmetry). Expect the bulk of ported_static/
   frontier/… suites to flip.
2. **Stage 2 — faithful dual pools in evmone** (spill/refill/commit,
   child-frame flows), NEW_ACCOUNT/STORAGE_SET/AUTH/code-deposit state gas.
3. **Stage 3 — BAL** (7928) build+validate, SLOTNUM (7843), builder requests
   (8282), remaining precompile reprice audits, 7934 if applicable.

Each stage: rebuild native runner → `z6m_conformance --pairs … --fail-log` →
per-category attribution (script in session scratchpad) → fix → repeat.
