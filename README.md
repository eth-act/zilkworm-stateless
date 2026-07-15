# zilkworm-stateless

A modular bare-metal C++ guest program for zero-knowledge EVM execution.

## Prerequisites

### RISC-V Toolchain (one-time, global install)

The SP1 build requires **xPack riscv-none-elf-gcc**, which bundles a newlib
sysroot.  No `package.json` or `.xpacks` folder is added to the project.

```bash
npm install --location=global xpm@latest
xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global
```

CMake auto-detects the toolchain from `~/Library/xPacks/` (macOS) or
`~/.local/xPacks/` (Linux).  No `PATH` export required.

> **CMake ≥ 3.28**


## Building

```bash
make guest_sp1
```

### Outputs

```
cpp/build/sp1/
├── z6m_guest.elf    ← RISC-V ELF loaded by the SP1 prover
├── z6m_guest.bin    ← flat binary (code + data)
└── z6m_guest.text   ← code section only
```

Each zkVM's `CMakeLists.txt` fetches zilkworm from
`https://github.com/erigontech/zilkworm` at configure time via CMake's
`FetchContent`.  Only two subdirectories are imported:

- `third_party/` — evmone, evmc, blst, intx, nlohmann_json
- `zilk_core/` — silkworm_core (EVM types, RLP, trie) + silkworm_dev (StateTransition)
## Releases

Tag-driven releases (`.github/workflows/release.yml`) publish, per zkVM:

- `stateless-validator-zilkworm-<zkvm>-<zkvmVersion>.elf` — the guest program
- `stateless-validator-zilkworm-<zkvm>-<zkvmVersion>.vk` — its program
  verifying key, derived directly from the zkVM's SDK (see `keygen/`)
- `<file>.minisig` for every artifact, plus `SHA256SUMS.txt` (also signed)
- `minisign.pub` — the signing public key (pin it after first use)

Verify any artifact with:

```bash
minisign -Vm stateless-validator-zilkworm-sp1-6.3.1.elf -p minisign.pub
```

zkVM SDK versions are pinned in `ZKVM_VERSIONS`; toolchain provenance is
documented in `PROVENANCE.md`.

## License

The code in this repository is dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Note that the stateless-execution engine this guest builds
on (`zilkworm`/`zilk_core`, derived from erigontech/silkworm, and the
`zvm1` evmone fork) remains licensed under Apache-2.0 by its upstream
authors; those terms continue to apply to that code.
