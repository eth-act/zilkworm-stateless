//! ZisK prover host for the C++ stateless-validator guest.
//!
//! The C++ guest ELF is compiled by `make guest_zisk` (CMake / rv64ima
//! bare-metal).  This host program loads it into the ZisK SDK and:
//!
//!   execute  — simulate without proof; prints cycle count + public output
//!              Uses ziskemu::ZiskEmulator directly (no proving key needed).
//!   prove    — generate a ZisK STARK / PLONK proof, verify, save to disk
//!              Requires the proving key installed at ~/.zisk/provingKey.
//!   verify   — load a previously saved proof and verify it
//!
//! Public output format (matches the SP1 guest for cross-backend consistency):
//!   8 × u32 LE slots = SHA-256(root[32] ∥ success[1]) = 32 raw bytes
//!   stored at ZisK OUTPUT_ADDR = 0xa001_0000.
//!
//! ZisK SDK: https://github.com/0xPolygonHermez/zisk  (tag v0.18.0)

use clap::{Parser, Subcommand};
use eyre::{eyre, Result};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

// Low-level emulator (execute only, no proving key required).
use zisk_common::EmuTrace;
use zisk_core::Riscv2zisk;
use ziskemu::{EmuOptions, ZiskEmulator};

// SDK types for prove / verify.
use zisk_sdk::{
    ExecutorKind, GuestProgram, ProofKind, ProverClient, ZiskStdin,
};
use zisk_sdk::Proof;

// ─── Embed the pre-built C++ guest ELF ──────────────────────────────────────
// build.rs sets ZISK_ELF_z6m_guest to the absolute ELF path.
// include_bytes! embeds the raw bytes so the binary is self-contained.
const Z6M_ELF_BYTES: &[u8] = include_bytes!(env!("ZISK_ELF_z6m_guest"));

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "z6m_zisk_prover",
    about = "ZisK prover host for the C++ stateless-validator guest"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Simulate the guest in the ZisK emulator (no proof, no proving key needed).
    Execute {
        /// Path to the SSZ-encoded SszStatelessInput binary.
        #[arg(long)]
        input: PathBuf,
    },

    /// Generate a ZisK proof, verify it locally, and save to disk.
    /// Requires the ZisK proving key at ~/.zisk/provingKey.
    Prove {
        /// Path to the SSZ-encoded SszStatelessInput binary.
        #[arg(long)]
        input: PathBuf,
        /// Where to write the serialised proof.
        #[arg(long, default_value = "proof.bin")]
        output: PathBuf,
        /// Proof kind:
        ///   stark   — VadcopFinal full STARK (default)
        ///   minimal — VadcopFinalMinimal (smaller, faster verify)
        ///   plonk   — EVM-verifiable PLONK proof
        #[arg(long, default_value = "stark")]
        mode: String,
    },

    /// Load a proof from disk and verify it.
    Verify {
        /// Path to a proof file written by `prove`.
        #[arg(long, default_value = "proof.bin")]
        proof: PathBuf,
    },
}

// ─── Input helpers ───────────────────────────────────────────────────────────

/// Read the raw SSZ input file.
fn read_raw_input(path: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| eyre!("cannot read {}: {}", path.display(), e))
}

/// Wrap raw bytes into a ZiskStdin (single length-prefixed record).
///
/// ZisK's ZiskStdin::write_slice produces:
///   [u64 LE: byte length][raw bytes][0–7 padding bytes to 8-byte alignment]
///
/// The prover maps this into INPUT_ADDR (0x4000_0000) with an 8-byte reserved
/// header prepended, giving:
///   [8 bytes: header][u64 LE: len][raw SSZ bytes]
///
/// The C++ guest's read_input_raw() skips the header, reads the u64 length,
/// and returns a direct pointer into the input region — no allocation, no ecall.
fn make_stdin(raw: &[u8]) -> ZiskStdin {
    let stdin = ZiskStdin::new();
    stdin.write_slice(raw);
    stdin
}

/// Encode raw bytes into the ZisK stdin wire format used by the low-level emulator.
///
/// The ZiskStdin wire format per record (used both on-disk and in INPUT_ADDR):
///   [8 bytes: u64 LE payload length]
///   [payload bytes]
///   [0–7 padding bytes to align next record to 8 bytes]
///
/// When running through the SDK's ProverClient the SDK adds an extra 8-byte
/// header before the first record (INPUT_INITIAL_OFFSET = 8).  The bare
/// ZiskEmulator::process_rom does NOT add that header — it passes the raw
/// bytes directly to the emulator.  We therefore produce the format the
/// emulator expects: header-less, just the [len][data][pad] record.
fn encode_stdin_for_emulator(raw: &[u8]) -> Vec<u8> {
    let len = raw.len() as u64;
    let padding = (8 - (raw.len() % 8)) % 8;
    let mut out = Vec::with_capacity(8 + raw.len() + padding);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(raw);
    out.resize(out.len() + padding, 0);
    out
}

// ─── Output helpers ──────────────────────────────────────────────────────────

/// Decode and display the 32-byte SHA-256 digest from raw output bytes.
///
/// The C++ guest writes SHA-256(root[32] ∥ success[1]) as 8 × u32 LE output
/// slots = 32 bytes at OUTPUT_ADDR (0xa001_0000).
/// ZiskEmulator::process_rom returns those bytes directly via get_output_8().
fn print_digest_from_bytes(output_bytes: &[u8]) {
    if output_bytes.len() >= 32 {
        println!(
            "public output (sha256 digest) : 0x{}",
            hex::encode(&output_bytes[..32])
        );
    } else {
        println!(
            "public output (raw, {} bytes)  : 0x{}",
            output_bytes.len(),
            hex::encode(output_bytes)
        );
    }
}

fn print_digest_from_publics(pv: &zisk_sdk::PublicValues) {
    let mut buf = [0u8; 32];
    pv.read_slice(&mut buf);
    println!("public output (sha256 digest) : 0x{}", hex::encode(buf));
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let args = Args::parse();

    match args.command {
        // ── Execute (emulator only, no proving key) ──────────────────────────
        //
        // Uses zisk_core::Riscv2zisk + ziskemu::ZiskEmulator directly, which
        // avoids the ProverClient::build() path that checks for the proving key.
        // ZiskEmulator::process_rom returns the raw output bytes (get_output_8),
        // which correspond to the 64 × u32 slots at OUTPUT_ADDR.
        Command::Execute { input } => {
            let raw = read_raw_input(&input)?;

            println!("Executing guest (ZisK emulator, no proof) …");

            // Convert rv64ima ELF → ZisK ROM (RISC-V → ZisK instruction set).
            let riscv2zisk = Riscv2zisk::new(Z6M_ELF_BYTES);
            let zisk_rom = riscv2zisk
                .run()
                .map_err(|e| eyre!("ELF → ZisK ROM conversion failed: {e:?}"))?;

            // Prepare input in the format the emulator expects.
            let stdin_bytes = encode_stdin_for_emulator(&raw);

            // Run the emulator — returns the raw output region bytes.
            let output_bytes = ZiskEmulator::process_rom(
                &zisk_rom,
                &stdin_bytes,
                &EmuOptions::default(),
                None::<Box<dyn Fn(EmuTrace)>>,
            )
            .map_err(|e| eyre!("emulation failed: {e:?}"))?;

            print_digest_from_bytes(&output_bytes);
            println!(
                "output size              : {} bytes ({} u32 slots)",
                output_bytes.len(),
                output_bytes.len() / 4
            );
        }

        // ── Prove ────────────────────────────────────────────────────────────
        Command::Prove { input, output, mode } => {
            let raw = read_raw_input(&input)?;
            let stdin = make_stdin(&raw);

            let proof_kind = match mode.as_str() {
                "stark"   => ProofKind::VadcopFinal,
                "minimal" => ProofKind::VadcopFinalMinimal,
                "plonk"   => ProofKind::Plonk,
                other     => return Err(eyre!(
                    "Unknown proof mode '{other}'. Valid options: stark | minimal | plonk"
                )),
            };

            // GuestProgram::from_bytes is infallible.
            let program = GuestProgram::from_bytes("z6m_guest", Z6M_ELF_BYTES.to_vec());

            // ProverClient::embedded() requires the proving key at ~/.zisk/provingKey.
            let client = ProverClient::embedded()
                .executor(ExecutorKind::Emulator)
                .build()
                .map_err(|e| eyre!(
                    "Failed to build prover client: {e}\n\
                     The ZisK proving key must be installed at ~/.zisk/provingKey.\n\
                     Install it with: cargo zisk install-prove-key"
                ))?;

            // ROM setup — computes and caches the program verification key.
            println!("Setting up program (ROM verkey) …");
            client
                .setup(&program)
                .run()
                .map_err(|e| eyre!("setup submit: {e}"))?
                .await
                .map_err(|e| eyre!("setup: {e}"))?;

            println!("Generating {mode} proof …");
            let result = client
                .prove(&program, stdin)
                .wrap(proof_kind)
                .run()
                .map_err(|e| eyre!("prove submit: {e}"))?
                .await
                .map_err(|e| eyre!("prove: {e}"))?;

            // ProveResult derefs to ProveOutput; get_proof() returns &Proof.
            result
                .get_proof()
                .verify()
                .map_err(|e| eyre!("local verify: {e}"))?;
            println!("Proof verified locally ✓");

            print_digest_from_publics(result.get_publics());
            println!("proving time             : {} ms", result.get_proving_time());
            println!("execution steps          : {}", result.get_execution_steps());

            result
                .save_proof(&output)
                .map_err(|e| eyre!("save proof: {e}"))?;
            println!("Proof saved → {}", output.display());
        }

        // ── Verify ───────────────────────────────────────────────────────────
        Command::Verify { proof } => {
            let proof_obj = Proof::load(&proof)
                .map_err(|e| eyre!("load proof {}: {e}", proof.display()))?;

            proof_obj
                .verify()
                .map_err(|e| eyre!("verify: {e}"))?;
            println!("Proof verified ✓");

            print_digest_from_publics(proof_obj.get_publics());
        }
    }

    Ok(())
}
