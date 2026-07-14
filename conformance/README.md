# Conformance vectors

Golden-vector generator for the zilkworm-stateless C++ guest, built on
`eth-act/ere-guests` **v0.13.0** — the exact crate zkboost pins — so the C++
guest is tested for byte-identical wire-contract conformance against the
canonical Rust host encoder rather than hand-rolled fixtures.

```bash
# Minimal synthetic Prague (ElectraFulu-shape) block — replaces gen_mock_input.py
cargo run --release -- mock --out-dir vectors --name mock

# Real block from fixture files (e.g. zkboost's crates/server/tests/fixture/)
cargo run --release -- real \
    --npr new_payload_request.ssz \
    --chain-config chain_config.ssz \
    --witness-json execution_witness.json \
    --out-dir vectors --name real

# Diagnostic sub-roots for bisecting hash-tree-root mismatches
cargo run --release -- debug-roots
```

Each run emits:

| File | Contents |
|---|---|
| `<name>_input.bin` | schema-prefixed SSZ `StatelessInput` (guest stdin) |
| `<name>_expected_success.bin` | SSZ `StatelessValidationResult{root, true, chain_config}` |
| `<name>_expected_failure.bin` | SSZ `StatelessValidationResult{root, false, chain_config}` |
| `<name>_root.hex` | hash-tree-root of the `NewPayloadRequest` |

The int-test harnesses (`../int-test`, `../zisk-int-test`,
`../int-test-openvm`) consume these via `execute --expected <file>`, which
byte-verifies the guest's public values (prefix identical + padding zero) and
exits non-zero on mismatch. Their `make mock-input` targets regenerate the
fixtures through this crate.

The mock block carries a synthetic witness, so guests are expected to produce
the `failure` variant; `success` requires real witness ingestion.
