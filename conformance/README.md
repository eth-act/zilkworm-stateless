# Conformance

```bash
# Minimal synthetic Prague (ElectraFulu-shape) block
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

Output:

| File | Contents |
|---|---|
| `<name>_input.bin` | schema-prefixed SSZ `StatelessInput` (guest stdin) |
| `<name>_expected_success.bin` | SSZ `StatelessValidationResult{root, true, chain_config}` |
| `<name>_expected_failure.bin` | SSZ `StatelessValidationResult{root, false, chain_config}` |
| `<name>_root.hex` | hash-tree-root of the `NewPayloadRequest` |

The int-test harnesses (`../int-tests/{sp1,zisk,openvm}`) consume these via `execute --expected <file>`, which
byte-verifies the guest's public values (prefix identical + padding zero) and
exits non-zero on mismatch. Their `make mock-input` targets regenerate the
fixtures through this crate.

The mock block carries a synthetic witness, so guests are expected to produce
the `failure` variant; `success` requires real witness ingestion.

## EEST conformance (tests-zkevm releases)

Extract `statelessInputBytes`/`statelessOutputBytes` pairs from an EEST
fixture release and run them through the native guest build:

```bash
# 1. Download + unpack fixtures_zkevm.tar.gz from a tests-zkevm release
# 2. Extract byte pairs (inputs are written verbatim — no host manipulation)
cargo run --release -- eest --fixtures fixtures/blockchain_tests --out-dir pairs/

# 3. Run the native tier (builds conformance/native on first use)
make -C .. conformance PAIRS=$PWD/pairs
```