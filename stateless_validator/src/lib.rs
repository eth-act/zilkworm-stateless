// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Host-side adapter that converts a [`stateless::StatelessInput`] into the SSZ
//! `SszStatelessInput` wire format consumed by the `zilkworm-stateless` zkVM guests
//! (SP1, RISC0, ZisK).
//!
//! The guests commit a 33-byte public output:
//!   `new_payload_request_root[0..32] || successful_validation[32]`
//! where `new_payload_request_root` is `hash_tree_root(SszNewPayloadRequest)`.

use std::collections::{BTreeMap, HashMap};

use alloy_consensus::{transaction::Transaction, Header};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::{nodes::TrieNode, Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use stateless::StatelessInput;

// ── Public API ────────────────────────────────────────────────────────────────

/// Host-side adapter that holds the SSZ bytes and expected public values for
/// a `zilkworm-stateless` zkVM guest execution.
#[derive(Clone, Debug)]
pub struct ZilkwormStatelessInput {
    /// Raw SSZ-encoded `SszStatelessInput` bytes — fed directly to the guest via stdin.
    pub ssz_bytes: Vec<u8>,
    /// `hash_tree_root(SszNewPayloadRequest)` computed on the host.
    pub new_payload_request_root: [u8; 32],
    /// Whether the block is expected to be valid.
    pub valid: bool,
}

impl ZilkwormStatelessInput {
    /// Convert a [`stateless::StatelessInput`] into the SSZ guest input.
    pub fn new(si: &StatelessInput, valid_block: bool) -> Result<Self> {
        let (ssz_bytes, npr_root) = stateless_input_to_ssz(si)?;
        Ok(Self { ssz_bytes, new_payload_request_root: npr_root, valid: valid_block })
    }

    /// Returns the 33-byte expected public output: `root[32] || valid[1]`.
    pub fn expected_public_values(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.extend_from_slice(&self.new_payload_request_root);
        out.push(if self.valid { 1 } else { 0 });
        out
    }
}

// ── SSZ layout constants ──────────────────────────────────────────────────────

const MAX_EXTRA_DATA_BYTES: u64 = 32;
const MAX_BYTES_PER_TRANSACTION: u64 = 1 << 30;
const MAX_TRANSACTIONS_PER_PAYLOAD: u64 = 1 << 20;
const MAX_WITHDRAWALS_PER_PAYLOAD: u64 = 1 << 16;
const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64 = 4096;
const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64 = 1 << 13;
const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64 = 1 << 4;
const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64 = 1 << 1;
const MAX_BLOCK_ACCESS_LIST_BYTES: u64 = 1 << 24;

// ── Top-level conversion ──────────────────────────────────────────────────────

fn stateless_input_to_ssz(si: &StatelessInput) -> Result<(Vec<u8>, [u8; 32])> {
    let witness = &si.witness;

    if witness.headers.is_empty() {
        bail!("witness.headers must contain at least the parent header");
    }

    let parent_header = {
        let mut slice = witness.headers[0].as_ref();
        Header::decode(&mut slice).context("decoding parent header")?
    };
    let pre_state_root: B256 = parent_header.state_root;

    // Build FlatNodeStore (state[1]) — wrap MPT nodes verbatim.
    let state1 = build_flat_store_rlp(witness.state.iter().map(|b| b.as_ref()));

    // Walk MPT to extract accounts, storage, codes → pre-state RLP (state[0]).
    let nodes: HashMap<B256, Vec<u8>> = witness
        .state
        .iter()
        .map(|b| (keccak256(b.as_ref()), b.to_vec()))
        .collect();

    let codes_by_hash: HashMap<B256, Vec<u8>> = witness
        .codes
        .iter()
        .map(|c| (keccak256(c.as_ref()), c.to_vec()))
        .collect();

    let mut preimages: HashMap<B256, &[u8]> = HashMap::new();
    for key in &witness.keys {
        preimages.insert(keccak256(key.as_ref()), key.as_ref());
    }

    let mut accounts: Vec<FlatAcct> = Vec::new();
    let state_leaves = walk_all_leaves(pre_state_root, &nodes)?;
    for (path_bytes, value_rlp) in state_leaves {
        if path_bytes.len() != 32 {
            continue;
        }
        let hashed_addr = B256::from_slice(&path_bytes);
        let Some(addr_preimage) = preimages.get(&hashed_addr) else { continue };
        if addr_preimage.len() != 20 {
            continue;
        }
        let addr = Address::from_slice(addr_preimage);
        let trie_account = {
            let mut slice = value_rlp.as_slice();
            TrieAccount::decode(&mut slice).context("decoding TrieAccount")?
        };
        let code: Bytes = if trie_account.code_hash == KECCAK_EMPTY {
            Bytes::new()
        } else {
            codes_by_hash
                .get(&trie_account.code_hash)
                .map(|v| Bytes::from(v.clone()))
                .unwrap_or_default()
        };
        let mut storage: BTreeMap<U256, U256> = BTreeMap::new();
        if trie_account.storage_root != EMPTY_ROOT_HASH {
            let storage_leaves = walk_all_leaves(trie_account.storage_root, &nodes)
                .with_context(|| format!("walking storage MPT for {addr}"))?;
            for (slot_path, slot_rlp) in storage_leaves {
                if slot_path.len() != 32 {
                    continue;
                }
                let hashed_slot = B256::from_slice(&slot_path);
                let Some(slot_preimage) = preimages.get(&hashed_slot) else { continue };
                if slot_preimage.len() != 32 {
                    continue;
                }
                let slot = U256::from_be_slice(slot_preimage);
                let value: U256 = {
                    let mut s = slot_rlp.as_slice();
                    Decodable::decode(&mut s).context("decoding storage value")?
                };
                storage.insert(slot, value);
            }
        }
        accounts.push(FlatAcct {
            address: addr,
            nonce: trie_account.nonce,
            balance: trie_account.balance,
            code_hash: trie_account.code_hash,
            storage_root: trie_account.storage_root,
            code,
            storage,
        });
    }
    accounts.sort_by(|a, b| a.address.cmp(&b.address));

    let state0 = build_prestate_rlp(&accounts);

    // Encode codes for SSZ witness (raw bytecode bytes).
    let codes: Vec<Vec<u8>> = witness.codes.iter().map(|c| c.to_vec()).collect();

    // Encode headers (skip parent header at index 0; it's included in witness for chain check).
    let header_rlps: Vec<Vec<u8>> = witness.headers.iter().map(|h| h.to_vec()).collect();

    // Build SszExecutionWitness.
    let witness_ssz = encode_witness(&state0, &state1, &codes, &header_rlps);

    // Build SszNewPayloadRequest from the block.
    let block = &si.block;
    let header = &block.header;
    let parent_beacon_root = header.parent_beacon_block_root.unwrap_or_default();

    // RLP-encode each transaction.
    let tx_rlps: Vec<Vec<u8>> = block
        .body
        .transactions
        .iter()
        .map(|tx| {
            let mut buf = Vec::new();
            tx.encode(&mut buf);
            buf
        })
        .collect();

    // Build SSZ withdrawals.
    let withdrawals: Vec<SszWithdrawal> = block
        .body
        .withdrawals
        .iter()
        .flat_map(|wds| wds.iter())
        .map(|w| SszWithdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: w.address.into_array(),
            amount: w.amount,
        })
        .collect();

    // Execution requests: not available from block body in current reth type — use empty.
    let exec_requests = SszExecutionRequests {
        deposits: Vec::new(),
        withdrawals: Vec::new(),
        consolidations: Vec::new(),
    };

    let block_hash: [u8; 32] = header.hash_slow().into();
    let extra_data: Vec<u8> = header.extra_data.to_vec();
    let base_fee_u256: U256 = header.base_fee_per_gas.map(U256::from).unwrap_or_default();
    let logs_bloom: [u8; 256] = header.logs_bloom.as_slice().try_into().expect("bloom is 256 bytes");

    let ep = SszExecutionPayload {
        parent_hash: header.parent_hash.into(),
        fee_recipient: header.beneficiary.into_array(),
        state_root: header.state_root.into(),
        receipts_root: header.receipts_root.into(),
        logs_bloom,
        prev_randao: header.mix_hash.into(),
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data,
        base_fee_per_gas: base_fee_u256,
        block_hash,
        transactions: tx_rlps,
        withdrawals,
        blob_gas_used: header.blob_gas_used.unwrap_or(0),
        excess_blob_gas: header.excess_blob_gas.unwrap_or(0),
        block_access_list: Vec::new(),
    };

    // Collect versioned hashes from EIP-4844 transactions.
    let versioned_hashes: Vec<[u8; 32]> = block
        .body
        .transactions
        .iter()
        .filter_map(|tx| tx.blob_versioned_hashes())
        .flat_map(|hashes| hashes.iter().map(|h| h.0))
        .collect();

    let npr = SszNewPayloadRequest {
        execution_payload: ep,
        versioned_hashes,
        parent_beacon_block_root: parent_beacon_root.into(),
        execution_requests: exec_requests,
    };

    let npr_root = htr_new_payload_request(&npr);
    let npr_ssz = encode_new_payload_request(&npr);

    let chain_id = si.chain_config.chain_id;
    let ssz_bytes = encode_stateless_input(&npr_ssz, &witness_ssz, chain_id);

    Ok((ssz_bytes, npr_root))
}

// ── FlatAcct helper ───────────────────────────────────────────────────────────

struct FlatAcct {
    address: Address,
    nonce: u64,
    balance: U256,
    code_hash: B256,
    storage_root: B256,
    code: Bytes,
    storage: BTreeMap<U256, U256>,
}

// ── Pre-state RLP encoder ─────────────────────────────────────────────────────
//
// Mirrors gen_ef_witness.py::build_prestate_rlp.
// Layout: RLP_LIST([accounts_rlp, storage_rlp, codes_rlp])
//   accounts_rlp = RLP_LIST([RLP_LIST([addr, nonce, balance, code_hash, storage_root]) ...])
//   storage_rlp  = RLP_LIST([RLP_LIST([addr, RLP_LIST([k, v, k, v, ...])]) ...])
//   codes_rlp    = RLP_LIST([code_hash, code_bytes, ...])

fn build_prestate_rlp(accounts: &[FlatAcct]) -> Vec<u8> {
    let mut acc_items: Vec<Vec<u8>> = Vec::new();
    let mut stor_items: Vec<Vec<u8>> = Vec::new();
    let mut code_items: Vec<Vec<u8>> = Vec::new();
    let mut seen_codes: std::collections::HashSet<B256> = Default::default();

    for acct in accounts {
        // Account entry: [addr, nonce, balance, code_hash, storage_root]
        let addr_rlp = rlp_bytes(acct.address.as_slice());
        let nonce_rlp = rlp_uint(acct.nonce);
        let balance_rlp = rlp_uint256(acct.balance);
        let code_hash_rlp = rlp_bytes(acct.code_hash.as_slice());
        let storage_root_rlp = rlp_bytes(acct.storage_root.as_slice());
        let acct_entry = rlp_list_of_raw(&[
            &addr_rlp, &nonce_rlp, &balance_rlp, &code_hash_rlp, &storage_root_rlp,
        ]);
        acc_items.push(acct_entry);

        // Storage entry if non-empty
        if !acct.storage.is_empty() {
            let mut kv_items: Vec<Vec<u8>> = Vec::new();
            for (k, v) in &acct.storage {
                kv_items.push(rlp_uint256(*k));
                kv_items.push(rlp_uint256(*v));
            }
            let kv_list = rlp_list_of_raw_flat(&kv_items);
            let addr_rlp2 = rlp_bytes(acct.address.as_slice());
            let entry = rlp_list_of_raw(&[&addr_rlp2, &kv_list]);
            stor_items.push(entry);
        }

        // Code entry (hash, bytes) — deduplicated, skip empty code
        if acct.code_hash != KECCAK_EMPTY && !acct.code.is_empty()
            && seen_codes.insert(acct.code_hash)
        {
            code_items.push(rlp_bytes(acct.code_hash.as_slice()));
            code_items.push(rlp_bytes(&acct.code));
        }
    }

    let accounts_rlp = rlp_list_of_raw_flat(&acc_items);
    let storage_rlp = rlp_list_of_raw_flat(&stor_items);
    let codes_rlp = rlp_list_of_raw_flat(&code_items);
    rlp_list_of_raw(&[&accounts_rlp, &storage_rlp, &codes_rlp])
}

// ── RLP primitives (shared) ───────────────────────────────────────────────────

fn uint_to_be_bytes_minimal(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

fn rlp_wrap_raw(payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = Vec::with_capacity(n + 9);
    if n < 56 {
        out.push(0xc0 + n as u8);
    } else {
        let nb = uint_to_be_bytes_minimal(n as u64);
        out.push(0xf7 + nb.len() as u8);
        out.extend_from_slice(&nb);
    }
    out.extend_from_slice(payload);
    out
}

// ── FlatNodeStore RLP encoder ─────────────────────────────────────────────────
//
// Mirrors gen_ef_witness.py::build_flat_store_rlp.
// Layout: RLP_LIST_RAW(concat(0xa0||keccak(node) || node_rlp for each node))

fn build_flat_store_rlp<'a>(nodes: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    for node in nodes {
        let hash = keccak256(node);
        payload.push(0xa0); // RLP byte32 prefix
        payload.extend_from_slice(hash.as_slice());
        payload.extend_from_slice(node);
    }
    rlp_wrap_raw(&payload)
}

// ── SSZ encoding helpers ──────────────────────────────────────────────────────

/// SSZ list of variable-length byte strings.
fn ssz_bytelist_list(items: &[Vec<u8>]) -> Vec<u8> {
    if items.is_empty() {
        return Vec::new();
    }
    let n = items.len();
    let base = 4 * n;
    let mut offsets = Vec::with_capacity(n);
    let mut off = base;
    for item in items {
        offsets.push(off as u32);
        off += item.len();
    }
    let mut out = Vec::with_capacity(off);
    for o in offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Encode SszExecutionWitness.
fn encode_witness(state0: &[u8], state1: &[u8], codes: &[Vec<u8>], header_rlps: &[Vec<u8>]) -> Vec<u8> {
    let state_ssz = ssz_bytelist_list(&[state0.to_vec(), state1.to_vec()]);
    let codes_ssz = ssz_bytelist_list(codes);
    let headers_ssz = ssz_bytelist_list(header_rlps);

    let fixed_size: u32 = 12;
    let off_state: u32 = fixed_size;
    let off_codes: u32 = off_state + state_ssz.len() as u32;
    let off_headers: u32 = off_codes + codes_ssz.len() as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&off_state.to_le_bytes());
    out.extend_from_slice(&off_codes.to_le_bytes());
    out.extend_from_slice(&off_headers.to_le_bytes());
    out.extend_from_slice(&state_ssz);
    out.extend_from_slice(&codes_ssz);
    out.extend_from_slice(&headers_ssz);
    out
}

// ── SszExecutionPayload / SszNewPayloadRequest encoding ───────────────────────

struct SszWithdrawal {
    index: u64,
    validator_index: u64,
    address: [u8; 20],
    amount: u64,
}

struct SszDepositRequest {
    pubkey: [u8; 48],
    withdrawal_credentials: [u8; 32],
    amount: u64,
    signature: [u8; 96],
    index: u64,
}

struct SszWithdrawalRequest {
    source_address: [u8; 20],
    validator_pubkey: [u8; 48],
    amount: u64,
}

struct SszConsolidationRequest {
    source_address: [u8; 20],
    source_pubkey: [u8; 48],
    target_pubkey: [u8; 48],
}

struct SszExecutionRequests {
    deposits: Vec<SszDepositRequest>,
    withdrawals: Vec<SszWithdrawalRequest>,
    consolidations: Vec<SszConsolidationRequest>,
}

struct SszExecutionPayload {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: [u8; 256],
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: Vec<u8>,
    base_fee_per_gas: U256,
    block_hash: [u8; 32],
    transactions: Vec<Vec<u8>>,
    withdrawals: Vec<SszWithdrawal>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    block_access_list: Vec<u8>,
}

struct SszNewPayloadRequest {
    execution_payload: SszExecutionPayload,
    versioned_hashes: Vec<[u8; 32]>,
    parent_beacon_block_root: [u8; 32],
    execution_requests: SszExecutionRequests,
}

fn encode_execution_payload(ep: &SszExecutionPayload) -> Vec<u8> {
    // 18 fields: 14 fixed + 4 variable (extra_data, transactions, withdrawals, block_access_list).
    // Fixed part size:
    //   32+20+32+32+256+32 + 8+8+8+8 + 4(off_extra) + 32 + 32 + 4(off_tx) + 4(off_wdl) + 8+8 + 4(off_bal)
    // = 32+20+32+32+256+32+8+8+8+8+4+32+32+4+4+8+8+4 = 532
    let fixed_size: u32 = 532;

    // Encode transactions list as SSZ ByteList-of-ByteLists: each tx is a ByteList.
    // The transactions field is itself a List[ByteList, MAX_TX].
    // SSZ encoding: ssz_bytelist_list(tx_rlps)
    let tx_ssz = ssz_bytelist_list(&ep.transactions);

    // Withdrawals: fixed-size structs (48 bytes each): index(8)+validator_index(8)+address(20)+amount(8)
    let wdl_ssz = encode_withdrawals_ssz(&ep.withdrawals);

    let base_fee_le: [u8; 32] = {
        let mut b = [0u8; 32];
        let bytes = ep.base_fee_per_gas.to_le_bytes::<32>();
        b.copy_from_slice(&bytes);
        b
    };

    let off_extra = fixed_size;
    let off_tx = off_extra + ep.extra_data.len() as u32;
    let off_wdl = off_tx + tx_ssz.len() as u32;
    let off_bal = off_wdl + wdl_ssz.len() as u32;

    let mut out = Vec::with_capacity(fixed_size as usize
        + ep.extra_data.len() + tx_ssz.len() + wdl_ssz.len() + ep.block_access_list.len());

    out.extend_from_slice(&ep.parent_hash);
    out.extend_from_slice(&ep.fee_recipient);
    out.extend_from_slice(&ep.state_root);
    out.extend_from_slice(&ep.receipts_root);
    out.extend_from_slice(&ep.logs_bloom);
    out.extend_from_slice(&ep.prev_randao);
    out.extend_from_slice(&ep.block_number.to_le_bytes());
    out.extend_from_slice(&ep.gas_limit.to_le_bytes());
    out.extend_from_slice(&ep.gas_used.to_le_bytes());
    out.extend_from_slice(&ep.timestamp.to_le_bytes());
    out.extend_from_slice(&off_extra.to_le_bytes()); // extra_data offset
    out.extend_from_slice(&base_fee_le);
    out.extend_from_slice(&ep.block_hash);
    out.extend_from_slice(&off_tx.to_le_bytes()); // transactions offset
    out.extend_from_slice(&off_wdl.to_le_bytes()); // withdrawals offset
    out.extend_from_slice(&ep.blob_gas_used.to_le_bytes());
    out.extend_from_slice(&ep.excess_blob_gas.to_le_bytes());
    out.extend_from_slice(&off_bal.to_le_bytes()); // block_access_list offset

    debug_assert_eq!(out.len(), fixed_size as usize);

    out.extend_from_slice(&ep.extra_data);
    out.extend_from_slice(&tx_ssz);
    out.extend_from_slice(&wdl_ssz);
    out.extend_from_slice(&ep.block_access_list);
    out
}

fn encode_withdrawals_ssz(withdrawals: &[SszWithdrawal]) -> Vec<u8> {
    // Each withdrawal is 8+8+20+8 = 44 bytes (fixed-size SSZ container).
    let mut out = Vec::with_capacity(withdrawals.len() * 44);
    for w in withdrawals {
        out.extend_from_slice(&w.index.to_le_bytes());
        out.extend_from_slice(&w.validator_index.to_le_bytes());
        out.extend_from_slice(&w.address);
        out.extend_from_slice(&w.amount.to_le_bytes());
    }
    out
}

fn encode_execution_requests_ssz(er: &SszExecutionRequests) -> Vec<u8> {
    // SszExecutionRequests: 3 variable-length lists (deposits, withdrawals, consolidations).
    // Each is a List of fixed-size structs.
    let deposits_ssz = encode_deposits_ssz(&er.deposits);
    let wdl_req_ssz = encode_withdrawal_requests_ssz(&er.withdrawals);
    let con_ssz = encode_consolidations_ssz(&er.consolidations);

    let fixed_size: u32 = 12; // 3 × 4-byte offsets
    let off0 = fixed_size;
    let off1 = off0 + deposits_ssz.len() as u32;
    let off2 = off1 + wdl_req_ssz.len() as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&off0.to_le_bytes());
    out.extend_from_slice(&off1.to_le_bytes());
    out.extend_from_slice(&off2.to_le_bytes());
    out.extend_from_slice(&deposits_ssz);
    out.extend_from_slice(&wdl_req_ssz);
    out.extend_from_slice(&con_ssz);
    out
}

fn encode_deposits_ssz(deposits: &[SszDepositRequest]) -> Vec<u8> {
    // Each deposit: pubkey(48) + withdrawal_creds(32) + amount(8) + sig(96) + index(8) = 192
    let mut out = Vec::with_capacity(deposits.len() * 192);
    for d in deposits {
        out.extend_from_slice(&d.pubkey);
        out.extend_from_slice(&d.withdrawal_credentials);
        out.extend_from_slice(&d.amount.to_le_bytes());
        out.extend_from_slice(&d.signature);
        out.extend_from_slice(&d.index.to_le_bytes());
    }
    out
}

fn encode_withdrawal_requests_ssz(reqs: &[SszWithdrawalRequest]) -> Vec<u8> {
    // Each: source_addr(20) + validator_pubkey(48) + amount(8) = 76
    let mut out = Vec::with_capacity(reqs.len() * 76);
    for r in reqs {
        out.extend_from_slice(&r.source_address);
        out.extend_from_slice(&r.validator_pubkey);
        out.extend_from_slice(&r.amount.to_le_bytes());
    }
    out
}

fn encode_consolidations_ssz(reqs: &[SszConsolidationRequest]) -> Vec<u8> {
    // Each: source_addr(20) + source_pubkey(48) + target_pubkey(48) = 116
    let mut out = Vec::with_capacity(reqs.len() * 116);
    for r in reqs {
        out.extend_from_slice(&r.source_address);
        out.extend_from_slice(&r.source_pubkey);
        out.extend_from_slice(&r.target_pubkey);
    }
    out
}

fn encode_new_payload_request(npr: &SszNewPayloadRequest) -> Vec<u8> {
    // SszNewPayloadRequest: 4 fields — execution_payload (var), versioned_hashes (var),
    //   parent_beacon_block_root (32 fixed), execution_requests (var).
    // Fixed part: 4(off_payload) + 4(off_hashes) + 32(pbr) + 4(off_er) = 44 bytes
    let payload_ssz = encode_execution_payload(&npr.execution_payload);
    // versioned_hashes: List[Hash32, 4096] — each 32 bytes, concatenated.
    let hashes_ssz: Vec<u8> = npr.versioned_hashes.iter().flat_map(|h| h.iter().copied()).collect();
    let er_ssz = encode_execution_requests_ssz(&npr.execution_requests);

    let fixed_size: u32 = 44;
    let off_payload: u32 = fixed_size;
    let off_hashes: u32 = off_payload + payload_ssz.len() as u32;
    let off_er: u32 = off_hashes + hashes_ssz.len() as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&off_payload.to_le_bytes());
    out.extend_from_slice(&off_hashes.to_le_bytes());
    out.extend_from_slice(&npr.parent_beacon_block_root);
    out.extend_from_slice(&off_er.to_le_bytes());
    out.extend_from_slice(&payload_ssz);
    out.extend_from_slice(&hashes_ssz);
    out.extend_from_slice(&er_ssz);
    out
}

/// Encode SszStatelessInput.
///
/// Layout (gen_ef_witness.py::encode_stateless_input):
///   fixed: off_npr(4) + off_wit(4) + off_cc(4) + off_pk(4) = 16 bytes
///   variable: npr_bytes + witness_bytes + chain_config_bytes(8) + public_keys_bytes(0)
fn encode_stateless_input(npr_ssz: &[u8], witness_ssz: &[u8], chain_id: u64) -> Vec<u8> {
    let cc_bytes = chain_id.to_le_bytes();
    let pk_bytes: &[u8] = &[];

    let fixed_size: u32 = 16;
    let off_npr: u32 = fixed_size;
    let off_wit: u32 = off_npr + npr_ssz.len() as u32;
    let off_cc: u32 = off_wit + witness_ssz.len() as u32;
    let off_pk: u32 = off_cc + cc_bytes.len() as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&off_npr.to_le_bytes());
    out.extend_from_slice(&off_wit.to_le_bytes());
    out.extend_from_slice(&off_cc.to_le_bytes());
    out.extend_from_slice(&off_pk.to_le_bytes());
    out.extend_from_slice(npr_ssz);
    out.extend_from_slice(witness_ssz);
    out.extend_from_slice(&cc_bytes);
    out.extend_from_slice(pk_bytes);
    out
}

// ── SSZ hash_tree_root ────────────────────────────────────────────────────────
//
// Implements the same algorithm as core/src/stateless.cpp / core/include/z6m/ssz.hpp.

fn sha256(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// merkleize(chunks, limit): pad chunks to next power-of-2 or limit (whichever is larger),
/// then build a binary SHA256 tree bottom-up.
fn merkleize(chunks: &[[u8; 32]], limit: u64) -> [u8; 32] {
    let n = chunks.len() as u64;
    let size = if limit == 0 {
        if n == 0 { 1 } else { n.next_power_of_two() }
    } else {
        // limit must be >= n; pad to next power-of-two that is >= limit
        limit.next_power_of_two()
    };

    // Build padded layer.
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(size as usize);
    for chunk in chunks.iter().take(size as usize) {
        layer.push(*chunk);
    }
    while (layer.len() as u64) < size {
        layer.push([0u8; 32]);
    }

    // Reduce.
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(sha256(&pair[0], &pair[1]));
        }
        layer = next;
    }
    layer[0]
}

fn mix_in_length(root: [u8; 32], length: u64) -> [u8; 32] {
    let mut len_chunk = [0u8; 32];
    len_chunk[..8].copy_from_slice(&length.to_le_bytes());
    sha256(&root, &len_chunk)
}

fn htr_uint64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

fn htr_uint256(v: U256) -> [u8; 32] {
    v.to_le_bytes()
}

/// hash_tree_root of a fixed ByteVector[N]: zero-pad to 32-byte chunk boundary, merkleize.
fn htr_byte_vector(data: &[u8]) -> [u8; 32] {
    let nchunks = data.len().div_ceil(32);
    let mut chunks: Vec<[u8; 32]> = vec![[0u8; 32]; nchunks.max(1)];
    for (i, byte) in data.iter().enumerate() {
        chunks[i / 32][i % 32] = *byte;
    }
    merkleize(&chunks, 0)
}

/// hash_tree_root of a ByteList[N]: pack, merkleize(limit=ceil(N/32)), mix_in_length.
fn htr_byte_list(data: &[u8], max_bytes: u64) -> [u8; 32] {
    let limit = max_bytes.div_ceil(32);
    let nchunks = data.len().div_ceil(32);
    let mut chunks: Vec<[u8; 32]> = vec![[0u8; 32]; nchunks.max(0)];
    for (i, byte) in data.iter().enumerate() {
        chunks[i / 32][i % 32] = *byte;
    }
    let root = merkleize(&chunks, limit);
    mix_in_length(root, data.len() as u64)
}

/// hash_tree_root(container): merkleize(field_roots, limit=nfields).
fn htr_container(fields: &[[u8; 32]]) -> [u8; 32] {
    merkleize(fields, fields.len() as u64)
}

fn htr_withdrawal(w: &SszWithdrawal) -> [u8; 32] {
    htr_container(&[
        htr_uint64(w.index),
        htr_uint64(w.validator_index),
        htr_byte_vector(&w.address),
        htr_uint64(w.amount),
    ])
}

fn htr_deposit_request(d: &SszDepositRequest) -> [u8; 32] {
    htr_container(&[
        htr_byte_vector(&d.pubkey),
        htr_byte_vector(&d.withdrawal_credentials),
        htr_uint64(d.amount),
        htr_byte_vector(&d.signature),
        htr_uint64(d.index),
    ])
}

fn htr_withdrawal_request(w: &SszWithdrawalRequest) -> [u8; 32] {
    htr_container(&[
        htr_byte_vector(&w.source_address),
        htr_byte_vector(&w.validator_pubkey),
        htr_uint64(w.amount),
    ])
}

fn htr_consolidation_request(c: &SszConsolidationRequest) -> [u8; 32] {
    htr_container(&[
        htr_byte_vector(&c.source_address),
        htr_byte_vector(&c.source_pubkey),
        htr_byte_vector(&c.target_pubkey),
    ])
}

fn htr_list_of_containers<T, F: Fn(&T) -> [u8; 32]>(items: &[T], limit: u64, f: F) -> [u8; 32] {
    let chunks: Vec<[u8; 32]> = items.iter().map(|x| f(x)).collect();
    let root = merkleize(&chunks, limit);
    mix_in_length(root, items.len() as u64)
}

fn htr_execution_requests(er: &SszExecutionRequests) -> [u8; 32] {
    htr_container(&[
        htr_list_of_containers(&er.deposits, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, htr_deposit_request),
        htr_list_of_containers(&er.withdrawals, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD, htr_withdrawal_request),
        htr_list_of_containers(&er.consolidations, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD, htr_consolidation_request),
    ])
}

fn htr_execution_payload(ep: &SszExecutionPayload) -> [u8; 32] {
    // transactions: List[ByteList[MAX_BYTES_PER_TX], MAX_TX_PER_PAYLOAD]
    let tx_roots: Vec<[u8; 32]> = ep.transactions.iter()
        .map(|tx| htr_byte_list(tx, MAX_BYTES_PER_TRANSACTION))
        .collect();
    let tx_root = merkleize(&tx_roots, MAX_TRANSACTIONS_PER_PAYLOAD);
    let tx_htr = mix_in_length(tx_root, ep.transactions.len() as u64);

    // withdrawals: List[SszWithdrawal, MAX_WITHDRAWALS]
    let wdl_htr = htr_list_of_containers(&ep.withdrawals, MAX_WITHDRAWALS_PER_PAYLOAD, htr_withdrawal);

    htr_container(&[
        htr_byte_vector(&ep.parent_hash),
        htr_byte_vector(&ep.fee_recipient),
        htr_byte_vector(&ep.state_root),
        htr_byte_vector(&ep.receipts_root),
        htr_byte_vector(&ep.logs_bloom),
        htr_byte_vector(&ep.prev_randao),
        htr_uint64(ep.block_number),
        htr_uint64(ep.gas_limit),
        htr_uint64(ep.gas_used),
        htr_uint64(ep.timestamp),
        htr_byte_list(&ep.extra_data, MAX_EXTRA_DATA_BYTES),
        htr_uint256(ep.base_fee_per_gas),
        htr_byte_vector(&ep.block_hash),
        tx_htr,
        wdl_htr,
        htr_uint64(ep.blob_gas_used),
        htr_uint64(ep.excess_blob_gas),
        htr_byte_list(&ep.block_access_list, MAX_BLOCK_ACCESS_LIST_BYTES),
    ])
}

fn htr_new_payload_request(npr: &SszNewPayloadRequest) -> [u8; 32] {
    // versioned_hashes: List[Hash32, MAX_BLOB_COMMITMENTS]
    let vh_chunks: Vec<[u8; 32]> = npr.versioned_hashes.clone();
    let vh_root = merkleize(&vh_chunks, MAX_BLOB_COMMITMENTS_PER_BLOCK);
    let vh_htr = mix_in_length(vh_root, npr.versioned_hashes.len() as u64);

    htr_container(&[
        htr_execution_payload(&npr.execution_payload),
        vh_htr,
        htr_byte_vector(&npr.parent_beacon_block_root),
        htr_execution_requests(&npr.execution_requests),
    ])
}

// ── MPT walking (adapted from z6m_stateless_validator) ───────────────────────

fn walk_all_leaves(root: B256, nodes: &HashMap<B256, Vec<u8>>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    if root == EMPTY_ROOT_HASH {
        return Ok(out);
    }
    let Some(root_rlp) = nodes.get(&root).cloned() else {
        return Ok(out);
    };
    walk_subtree(&root_rlp, Nibbles::new(), nodes, &mut out)?;
    Ok(out)
}

fn walk_subtree(
    node_rlp: &[u8],
    walked: Nibbles,
    nodes: &HashMap<B256, Vec<u8>>,
    out: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    let node = {
        let mut slice = node_rlp;
        TrieNode::decode(&mut slice).context("decoding trie node")?
    };
    match node {
        TrieNode::EmptyRoot => Ok(()),
        TrieNode::Leaf(leaf) => {
            let full = concat_nibbles(&walked, &leaf.key);
            out.push((nibbles_to_bytes(&full), leaf.value.clone()));
            Ok(())
        }
        TrieNode::Extension(ext) => {
            let new_walked = concat_nibbles(&walked, &ext.key);
            if let Some(child_rlp) = resolve_child(&ext.child, nodes)? {
                walk_subtree(&child_rlp, new_walked, nodes, out)?;
            }
            Ok(())
        }
        TrieNode::Branch(branch) => {
            let mut stack_idx = 0usize;
            for nib in 0u8..16 {
                if branch.state_mask.is_bit_set(nib) {
                    let child = branch
                        .stack
                        .get(stack_idx)
                        .ok_or_else(|| anyhow!("branch stack shorter than mask"))?;
                    let mut new_walked = walked.clone();
                    new_walked.push(nib);
                    if let Some(child_rlp) = resolve_child(child, nodes)? {
                        walk_subtree(&child_rlp, new_walked, nodes, out)?;
                    }
                    stack_idx += 1;
                }
            }
            Ok(())
        }
    }
}

fn nibbles_to_bytes(nib: &Nibbles) -> Vec<u8> {
    let mut out = Vec::with_capacity(nib.len() / 2);
    let mut i = 0;
    while i + 1 < nib.len() {
        let hi = nib.get(i).expect("in-bounds");
        let lo = nib.get(i + 1).expect("in-bounds");
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn resolve_child(
    child: &alloy_trie::nodes::RlpNode,
    nodes: &HashMap<B256, Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let bytes: &[u8] = child.as_ref();
    if bytes.len() == 33 && bytes[0] == 0xa0 {
        let hash = B256::from_slice(&bytes[1..33]);
        Ok(nodes.get(&hash).cloned())
    } else {
        Ok(Some(bytes.to_vec()))
    }
}

fn concat_nibbles(a: &Nibbles, b: &Nibbles) -> Nibbles {
    let mut out = a.clone();
    for i in 0..b.len() {
        out.push(b.get(i).unwrap());
    }
    out
}

// ── Raw RLP helpers ───────────────────────────────────────────────────────────
//
// Minimal RLP encoding without alloy_rlp traits, matching gen_ef_witness.py exactly.

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let n = b.len();
    let mut out = Vec::with_capacity(n + 9);
    if n < 56 {
        out.push(0x80 + n as u8);
    } else {
        let nb = uint_to_be_bytes_minimal(n as u64);
        out.push(0xb7 + nb.len() as u8);
        out.extend_from_slice(&nb);
    }
    out.extend_from_slice(b);
    out
}

fn rlp_uint(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(7);
    rlp_bytes(&be[start..])
}

fn rlp_uint256(n: U256) -> Vec<u8> {
    if n == U256::ZERO {
        return vec![0x80];
    }
    let be = n.to_be_bytes::<32>();
    let start = be.iter().position(|&b| b != 0).unwrap_or(31);
    rlp_bytes(&be[start..])
}

/// Wrap pre-encoded items in an RLP list (items are already RLP-encoded).
fn rlp_list_of_raw(items: &[&Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    rlp_wrap_raw(&payload)
}

/// Wrap a flat vec of pre-encoded items in an RLP list.
fn rlp_list_of_raw_flat(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    rlp_wrap_raw(&payload)
}
