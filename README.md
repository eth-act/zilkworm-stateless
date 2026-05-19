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