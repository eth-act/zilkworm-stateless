//! Program verifying-key generation for the zilkworm-stateless guest ELFs.
//!
//! Produces the `.vk` release artifact published next to each ELF
//! (`stateless-validator-zilkworm-<zkvm>-<version>.vk`), derived directly
//! from each zkVM's own SDK — no intermediary tooling — so the file a
//! verifier consumes is exactly the SDK's serialized verifying key:
//!
//!   sp1    — bincode-serialized `SP1VerifyingKey` from `Prover::setup`
//!   zisk   — bincode-serialized `ProgramVK` from `GuestProgram::vk()`
//!            (the ROM-merkle verkey). PREREQUISITE: the ROM merkle setup
//!            must exist for this ELF — run `cargo-zisk setup` (needs
//!            the ZisK proving key via ziskup) before invoking keygen
//!   openvm — `AppVerifyingKey` from `Sdk::app_keygen`, written with
//!            `openvm_sdk::fs` (the SDK's own serialization). The app
//!            config MUST match the proving side: standard VM config with
//!            256 public-values bytes.
//!
//! Build with exactly one feature: `cargo build --release --features <zkvm>`.

use std::path::PathBuf;

use clap::Parser;

const _: () = {
    assert!(
        (cfg!(feature = "sp1") as u8 + cfg!(feature = "zisk") as u8 + cfg!(feature = "openvm") as u8)
            == 1,
        "enable exactly one zkVM feature: sp1 | zisk | openvm"
    );
};

#[derive(Parser)]
#[command(name = "keygen", about = "Generate the program verifying key for a guest ELF")]
struct Args {
    /// Path to the guest ELF.
    #[arg(long)]
    elf: PathBuf,
    /// Output path for the verifying key.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let elf = std::fs::read(&args.elf)?;

    #[cfg(feature = "sp1")]
    {
        use sp1_sdk::{Prover, ProverClient, ProvingKey};
        let rt = tokio::runtime::Runtime::new()?;
        let (vk_bytes, id) = rt.block_on(async {
            let prover = ProverClient::builder().cpu().build().await;
            let pk = prover
                .setup(elf.as_slice().into())
                .await
                .map_err(|e| anyhow::anyhow!("sp1 setup: {e}"))?;
            let vk = pk.verifying_key();
            use sp1_sdk::HashableKey;
            Ok::<_, anyhow::Error>((bincode::serialize(vk)?, vk.bytes32()))
        })?;
        std::fs::write(&args.out, vk_bytes)?;
        println!("sp1 vk written: {} (bytes32 {})", args.out.display(), id);
    }

    #[cfg(feature = "zisk")]
    {
        use zisk_sdk::GuestProgram;
        let program = GuestProgram::from_bytes("z6m_guest", elf);
        let vk = program.vk().map_err(|e| {
            anyhow::anyhow!(
                "zisk rom-merkle verkey: {e} \
                 (run `cargo-zisk setup -e <elf>` first — requires the \
                 ZisK proving key installed via ziskup)"
            )
        })?;
        std::fs::write(&args.out, bincode::serialize(&vk)?)?;
        println!(
            "zisk vk written: {} (vk {})",
            args.out.display(),
            vk.vk.iter().map(|v| format!("{v:016x}")).collect::<String>()
        );
    }

    #[cfg(feature = "openvm")]
    {
        use openvm_sdk::{
            config::{AggregationSystemParams, AppConfig},
            fs::write_object_to_file,
            Sdk,
        };
        use openvm_sdk_config::SdkVmConfig;
        use openvm_stark_sdk::config::{
            app_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT,
        };

        // Must mirror the proving-side configuration exactly (standard VM,
        // 256 public-values bytes) or the vk will not match produced proofs.
        let mut config = SdkVmConfig::standard();
        config.system.config = config.system.config.with_public_values(256);
        let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
        let sdk = Sdk::new(
            AppConfig::new(config.optimize(), app_params),
            AggregationSystemParams::default(),
        )
        .map_err(|e| anyhow::anyhow!("openvm sdk init: {e}"))?;
        let (_app_pk, app_vk) = sdk.app_keygen();
        write_object_to_file(&args.out, &app_vk)
            .map_err(|e| anyhow::anyhow!("write vk: {e}"))?;
        // Note: the OpenVM app vk is ELF-independent (it commits to the VM
        // config; the program commitment is checked against the proof), but
        // it is published per-ELF for a uniform artifact layout.
        let _ = elf;
        println!("openvm app vk written: {}", args.out.display());
    }

    Ok(())
}
