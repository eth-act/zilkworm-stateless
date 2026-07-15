# Build Provenance

This document records how the released guest ELFs are produced, for the EF
zkEVM guest-program rubric's compiler-provenance requirements.

## Compiler: unmodified upstream GCC

The guests are compiled with the **xPack GNU RISC-V Embedded GCC**
distribution — stock upstream GCC binaries, no patches, no custom passes:

| | |
|---|---|
| Distribution | `@xpack-dev-tools/riscv-none-elf-gcc` |
| Pinned version | `15.2.0-1.1` (xpm package) / release asset `15.2.0-1` |
| Upstream | GNU GCC 15.2.0, binutils as released by the xPack project |
| Source | https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases |
| Modifications | **none** — installed verbatim via `xpm install` at the pinned version |

The pin lives in `.github/workflows/release.yml` (`RISCV_XPACK_VERSION`);
released ELFs are only ever produced by that public workflow. Per-target
codegen flags are in `zkvm/<zkvm>/cmake/*.cmake` (plain `-march`/`-mabi`/
`-O3`; no nonstandard passes).

## Source-level components (not compiler modifications)

All customization is ordinary source code, reviewable in public repos:

| Component | Basis | Nature of changes |
|---|---|---|
| `zilkworm` (`zilk_core`) | fork of [erigontech/silkworm] | stateless-execution engine work (witness-backed state, MPT, canonical witness ingestion) |
| `zvm1` (evmone) | fork of [ethereum/evmone] via erigontech | zkVM precompile acceleration hooks (`#ifdef SP1/ZISK/OPENVM` dispatch) |
| `core/`, `zkvm/` (this repo) | original | SSZ wire contract, per-zkVM bare-metal runtimes |

## Verifying keys

`.vk` release artifacts are derived directly from each zkVM's own SDK by
`keygen/` (this repo) at the versions recorded in `ZKVM_VERSIONS` — no
intermediary tooling between the SDK and the published artifact.

## Signatures

Every release asset is minisign-signed in CI (trusted comment = filename);
the signing public key is published as `minisign.pub` in each release. Pin
it on first use and verify with:

```bash
minisign -Vm <artifact> -p minisign.pub
```

## Reproducibility (in progress)

Bit-reproducible builds (two independent CI builds asserting identical
SHA-256) are planned; see `ZILKWORM_READINESS_PLAN.md` Phase 3.4. Until
then, SHA256SUMS.txt in each release is itself signed.
