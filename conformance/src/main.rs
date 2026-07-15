//! Golden-vector generator for the zilkworm-stateless C++ guest.
//!
//! Emits canonical wire-contract bytes from `eth-act/ere-guests` v0.13.0 — the
//! exact crate zkboost pins — so the C++ guest can be tested for byte-identical
//! conformance without hand-rolled encoders:
//!
//!   * `<name>_input.bin`            schema-prefixed SSZ `StatelessInput` (guest stdin)
//!   * `<name>_expected_success.bin` SSZ `StatelessValidationResult{root, true,  chain_config}`
//!   * `<name>_expected_failure.bin` SSZ `StatelessValidationResult{root, false, chain_config}`
//!   * `<name>_root.hex`             hash-tree-root of the `NewPayloadRequest`
//!
//! Subcommands:
//!   `mock` — minimal synthetic Prague/ElectraFulu block (replaces gen_mock_input.py)
//!   `real` — from zkboost-style fixture files (payload SSZ + chain-config SSZ + witness JSON)

use std::{fs, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use stateless_validator_common::{
    guest::{
        input::{
            new_payload_request::{
                ExecutionPayloadV3, ExecutionRequests, NewPayloadRequest,
                NewPayloadRequestElectraFulu,
            },
            BlobSchedule, ChainConfig, ExecutionWitness, ForkActivation, ForkConfig, ProtocolFork,
            PUBLIC_KEY_BYTES,
        },
        StatelessInput, StatelessValidationResult,
    },
    HashTreeRoot, Sha2Hasher, SszDecode, SszEncode, SszList,
};

#[derive(Parser)]
#[command(name = "vector-gen", about = "zilkworm-stateless conformance vector generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Minimal synthetic Prague (ElectraFulu-shape) input, zeroed payload, empty witness.
    Mock {
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        #[arg(long, default_value = "mock")]
        name: String,
    },
    /// Diagnostic: print candidate NPR roots for the mock block under
    /// different payload shapes, to bisect C++ htr mismatches.
    DebugRoots,
    /// Extract statelessInputBytes/statelessOutputBytes pairs from EEST
    /// blockchain-test fixtures (tests-zkevm releases) into
    /// `<name>.input.bin` / `<name>.expected.bin` files consumable by the
    /// native runner (`conformance/native`) and the zkVM int-test harnesses.
    Eest {
        /// Directory containing extracted EEST fixture JSONs (searched
        /// recursively), e.g. `fixtures/blockchain_tests`.
        #[arg(long)]
        fixtures: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Vectors from fixture files (e.g. zkboost's crates/server/tests/fixture/).
    Real {
        /// SSZ-encoded NewPayloadRequest (fork shape auto-detected newest-first).
        #[arg(long)]
        npr: PathBuf,
        /// SSZ-encoded canonical ChainConfig.
        #[arg(long)]
        chain_config: PathBuf,
        /// debug_executionWitness-style JSON with state/codes/headers hex arrays.
        #[arg(long)]
        witness_json: PathBuf,
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        #[arg(long, default_value = "real")]
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Mock { out_dir, name } => {
            let (input, chain_config) = mock_input()?;
            emit(&out_dir, &name, &input, &chain_config)
        }
        Command::DebugRoots => debug_roots(),
        Command::Eest { fixtures, out_dir } => extract_eest(&fixtures, &out_dir),
        Command::Real {
            npr,
            chain_config,
            witness_json,
            out_dir,
            name,
        } => {
            let (input, chain_config) = real_input(&npr, &chain_config, &witness_json)?;
            emit(&out_dir, &name, &input, &chain_config)
        }
    }
}

/// Minimal structurally-valid Prague input. Execution is expected to FAIL
/// validation (synthetic state), so int-tests assert `expected_failure`.
fn mock_input() -> anyhow::Result<(StatelessInput, ChainConfig)> {
    let payload = ExecutionPayloadV3 {
        parent_hash: [0; 32],
        fee_recipient: [0; 20],
        state_root: [0; 32],
        receipts_root: [0; 32],
        logs_bloom: [0; 256],
        prev_randao: [0; 32],
        block_number: 0,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 0,
        extra_data: SszList::try_from(Vec::new()).unwrap(),
        base_fee_per_gas: [0; 32],
        block_hash: [0; 32],
        transactions: SszList::try_from(Vec::new()).unwrap(),
        withdrawals: SszList::try_from(Vec::new()).unwrap(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
    };
    let new_payload_request = NewPayloadRequest::ElectraFulu(NewPayloadRequestElectraFulu {
        execution_payload: payload,
        versioned_hashes: SszList::try_from(Vec::new()).unwrap(),
        parent_beacon_block_root: [0; 32],
        execution_requests: ExecutionRequests::default(),
    });
    // Mainnet-Prague-style config, timestamp activation 0 (always active).
    let chain_config = ChainConfig {
        chain_id: 1,
        active_fork: ForkConfig::new(
            ProtocolFork::Prague,
            ForkActivation::new(None, Some(0)),
            Some(BlobSchedule {
                target: 6,
                max: 9,
                base_fee_update_fraction: 5_007_716,
            }),
        ),
    };
    let input = StatelessInput {
        new_payload_request,
        witness: ExecutionWitness::default(),
        chain_config: chain_config.clone(),
        public_keys: SszList::try_from(Vec::<[u8; PUBLIC_KEY_BYTES]>::new()).unwrap(),
    };
    Ok((input, chain_config))
}

/// Prints per-component roots of the mock block for both payload shapes so a
/// mismatching C++ implementation can be located by comparing sub-roots.
fn debug_roots() -> anyhow::Result<()> {
    use stateless_validator_common::guest::input::new_payload_request::{
        ExecutionPayloadV4, NewPayloadRequestGloas,
    };

    let (input, _) = mock_input()?;
    let NewPayloadRequest::ElectraFulu(npr) = &input.new_payload_request else {
        unreachable!()
    };
    let h = Sha2Hasher;

    println!("payload_v3 root      : {}", hex::encode(npr.execution_payload.hash_tree_root(&h)));
    println!("exec_requests root   : {}", hex::encode(npr.execution_requests.hash_tree_root(&h)));
    println!("npr(ElectraFulu) root: {}", hex::encode(npr.hash_tree_root(&h)));

    // Same block forced into the Gloas (V4) shape: empty BAL, slot 0.
    let v3 = &npr.execution_payload;
    let v4 = ExecutionPayloadV4 {
        parent_hash: v3.parent_hash,
        fee_recipient: v3.fee_recipient,
        state_root: v3.state_root,
        receipts_root: v3.receipts_root,
        logs_bloom: v3.logs_bloom,
        prev_randao: v3.prev_randao,
        block_number: v3.block_number,
        gas_limit: v3.gas_limit,
        gas_used: v3.gas_used,
        timestamp: v3.timestamp,
        extra_data: v3.extra_data.clone(),
        base_fee_per_gas: v3.base_fee_per_gas,
        block_hash: v3.block_hash,
        transactions: v3.transactions.clone(),
        withdrawals: v3.withdrawals.clone(),
        blob_gas_used: v3.blob_gas_used,
        excess_blob_gas: v3.excess_blob_gas,
        block_access_list: SszList::try_from(Vec::new()).unwrap(),
        slot_number: 0,
    };
    let npr_gloas = NewPayloadRequestGloas {
        execution_payload: v4,
        versioned_hashes: npr.versioned_hashes.clone(),
        parent_beacon_block_root: npr.parent_beacon_block_root,
        execution_requests: npr.execution_requests.clone(),
    };
    println!("payload_v4 root      : {}", hex::encode(npr_gloas.execution_payload.hash_tree_root(&h)));
    println!("npr(Gloas) root      : {}", hex::encode(npr_gloas.hash_tree_root(&h)));
    Ok(())
}

/// Walks EEST fixture JSONs and writes one `<name>.input.bin` /
/// `<name>.expected.bin` pair per block carrying stateless fields. Input
/// bytes are written verbatim (the rubric forbids host manipulation).
fn extract_eest(fixtures_dir: &PathBuf, out_dir: &PathBuf) -> anyhow::Result<()> {
    fn walk(dir: &std::path::Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, files)?;
            } else if path.extension().is_some_and(|e| e == "json") {
                files.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    walk(fixtures_dir, &mut files)?;
    fs::create_dir_all(out_dir)?;

    let decode_hex = |s: &str| hex::decode(s.trim_start_matches("0x"));

    let (mut cases, mut skipped_files) = (0usize, 0usize);
    for file in &files {
        let Ok(raw) = fs::read_to_string(file) else {
            skipped_files += 1;
            continue;
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&raw) else {
            skipped_files += 1;
            continue;
        };
        let Some(tests) = doc.as_object() else { continue };
        let stem = file.file_stem().unwrap().to_string_lossy();

        for (test_idx, (test_name, test)) in tests.iter().enumerate() {
            let Some(blocks) = test.get("blocks").and_then(|b| b.as_array()) else {
                continue;
            };
            for (block_idx, block) in blocks.iter().enumerate() {
                let (Some(input_hex), Some(output_hex)) = (
                    block.get("statelessInputBytes").and_then(|v| v.as_str()),
                    block.get("statelessOutputBytes").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let input = decode_hex(input_hex)?;
                let expected = decode_hex(output_hex)?;

                // Compact unique name: file stem + test ordinal + block
                // ordinal (full test id kept in a sidecar for triage).
                let base = format!("{stem}__t{test_idx}_b{block_idx}");
                fs::write(out_dir.join(format!("{base}.input.bin")), &input)?;
                fs::write(out_dir.join(format!("{base}.expected.bin")), &expected)?;
                fs::write(out_dir.join(format!("{base}.name.txt")), test_name)?;
                cases += 1;
            }
        }
    }
    println!(
        "extracted {cases} case(s) from {} fixture file(s) ({skipped_files} unreadable) into {}",
        files.len(),
        out_dir.display()
    );
    Ok(())
}

fn real_input(
    npr_path: &PathBuf,
    chain_config_path: &PathBuf,
    witness_json_path: &PathBuf,
) -> anyhow::Result<(StatelessInput, ChainConfig)> {
    let npr_bytes = fs::read(npr_path).with_context(|| format!("read {npr_path:?}"))?;
    let new_payload_request = NewPayloadRequest::from_ssz_bytes(&npr_bytes)
        .map_err(|e| anyhow::anyhow!("decode NewPayloadRequest: {e:?}"))?;

    let cc_bytes =
        fs::read(chain_config_path).with_context(|| format!("read {chain_config_path:?}"))?;
    let chain_config = ChainConfig::from_ssz_bytes(&cc_bytes)
        .map_err(|e| anyhow::anyhow!("decode ChainConfig: {e:?}"))?;

    let witness_raw =
        fs::read_to_string(witness_json_path).with_context(|| format!("read {witness_json_path:?}"))?;
    let witness = witness_from_json(&witness_raw)?;

    let public_keys = recover_public_keys(&new_payload_request)?;

    let input = StatelessInput {
        new_payload_request,
        witness,
        chain_config: chain_config.clone(),
        public_keys: SszList::try_from(public_keys)
            .map_err(|e| anyhow::anyhow!("public_keys out of bounds: {e:?}"))?,
    };
    Ok((input, chain_config))
}

/// Parses a `debug_executionWitness`-style JSON object (same wire shape zkboost's
/// witness service receives) into the canonical `ExecutionWitness`.
fn witness_from_json(raw: &str) -> anyhow::Result<ExecutionWitness> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    // Accept either the raw result object or a JSON-RPC envelope.
    let obj = value.get("result").unwrap_or(&value);

    let bytes_list = |key: &str| -> anyhow::Result<Vec<Vec<u8>>> {
        obj.get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        let s = item.as_str().context("witness item not a string")?;
                        hex::decode(s.trim_start_matches("0x")).context("witness item not hex")
                    })
                    .collect()
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    };

    fn to_ssz<const M: usize, const N: usize>(
        items: Vec<Vec<u8>>,
    ) -> anyhow::Result<SszList<SszList<u8, M>, N>> {
        SszList::try_from(
            items
                .into_iter()
                .map(SszList::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("witness item too large: {e:?}"))?,
        )
        .map_err(|e| anyhow::anyhow!("witness list too long: {e:?}"))
    }

    Ok(ExecutionWitness {
        state: to_ssz(bytes_list("state")?)?,
        codes: to_ssz(bytes_list("codes")?)?,
        headers: to_ssz(bytes_list("headers")?)?,
    })
}

/// Recovers 65-byte uncompressed public keys from payload transactions, in
/// payload order — mirrors zkboost's `proof/input.rs`.
fn recover_public_keys(
    new_payload_request: &NewPayloadRequest,
) -> anyhow::Result<Vec<[u8; PUBLIC_KEY_BYTES]>> {
    use alloy_consensus::{EthereumTxEnvelope, TxEip4844};
    use alloy_eips::Decodable2718;

    new_payload_request
        .transactions()
        .into_iter()
        .enumerate()
        .map(|(i, tx)| {
            let tx = EthereumTxEnvelope::<TxEip4844>::decode_2718(&mut tx.as_ref())
                .with_context(|| format!("failed to decode tx #{i}"))?;
            tx.signature()
                .recover_from_prehash(&tx.signature_hash())
                .map(|key| key.to_encoded_point(false).as_bytes().try_into().unwrap())
                .with_context(|| format!("failed to recover signature for tx #{i}"))
        })
        .collect()
}

fn emit(
    out_dir: &PathBuf,
    name: &str,
    input: &StatelessInput,
    chain_config: &ChainConfig,
) -> anyhow::Result<()> {
    fs::create_dir_all(out_dir)?;

    let input_bytes = input.to_schema_prefixed_ssz();
    let root = input.new_payload_request.hash_tree_root(&Sha2Hasher);
    let expected_success =
        StatelessValidationResult::new(root, true, chain_config.clone()).to_ssz();
    let expected_failure =
        StatelessValidationResult::new(root, false, chain_config.clone()).to_ssz();

    let write = |suffix: &str, bytes: &[u8]| -> anyhow::Result<PathBuf> {
        let path = out_dir.join(format!("{name}_{suffix}"));
        fs::write(&path, bytes).with_context(|| format!("write {path:?}"))?;
        Ok(path)
    };

    let input_path = write("input.bin", &input_bytes)?;
    let success_path = write("expected_success.bin", &expected_success)?;
    let failure_path = write("expected_failure.bin", &expected_failure)?;
    let root_path = write("root.hex", format!("{}\n", hex::encode(root)).as_bytes())?;

    println!("input             : {} ({} bytes)", input_path.display(), input_bytes.len());
    println!("expected(success) : {} ({} bytes)", success_path.display(), expected_success.len());
    println!("expected(failure) : {} ({} bytes)", failure_path.display(), expected_failure.len());
    println!("npr root          : {}", hex::encode(root));
    println!("chain_config ssz  : {}", hex::encode(chain_config.to_ssz()));
    println!("root file         : {}", root_path.display());
    Ok(())
}
