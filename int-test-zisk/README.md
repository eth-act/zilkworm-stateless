# Z6M C++ Guest for ZisK

Integration-test pipeline for running the C++ stateless-validator guest on
[ZisK zkVM](https://github.com/0xPolygonHermez/zisk).

The guest (`zkvm/zisk/`) is compiled as a bare-metal `rv64ima` ELF by CMake.
This Rust host loads it into the ZisK SDK, feeds SSZ-encoded input, and either
executes it in the emulator (no proof) or generates a full ZisK proof.

---

## Prerequisites

### RISC-V toolchain (guest)

The same xPack toolchain used for the SP1 guest also builds the ZisK guest
(`rv64ima` is a superset of `rv64im`):

```bash
npm install -g xpm
xpm install -g @xpack-dev-tools/riscv-none-elf-gcc@latest
```

### Rust stable (host)

```bash
rustup toolchain install stable
```

The ZisK host prover uses plain stable Rust — no special toolchain needed.

### ZisK SDK dependencies

The ZisK SDK is fetched from GitHub by Cargo automatically when you run
`make prover`.  On first build this downloads and compiles several crates;
allow 10–20 minutes on a clean cache.

> **macOS note**: The ZisK ASM executor requires Linux.  On macOS the SDK
> automatically falls back to the pure-Rust emulator, which is always used
> here.  Proving on macOS uses the emulator backend.

---

## Quick Start

```bash
# 1. Build the ZisK guest ELF + the Rust prover binary
make all

# 2. Generate a minimal synthetic input (no Ethereum node required)
make mock-input

# 3. Execute (emulator only — instant, no proof)
make execute INPUT=mock_input.bin
```

Expected output:

```
Executing guest (emulator, no proof) …
public output (sha256 digest) : 0x<32-byte hex>
execution steps               : <N>
execution time                : <ms>
```

---

## Generating a Proof

```bash
# Full STARK (default)
make prove INPUT=mock_input.bin

# Smaller STARK variant
make prove INPUT=mock_input.bin MODE=minimal

# EVM-verifiable PLONK proof
make prove INPUT=mock_input.bin MODE=plonk OUTPUT=plonk_proof.bin
```

The proof is saved to `proof.bin` (or the path given by `OUTPUT`).
It is verified locally immediately after generation.

---

## Verifying a Proof

```bash
make verify PROOF=proof.bin
```

---

## CLI Reference

All three commands are also available directly from the compiled binary:

```bash
./target/release/z6m_zisk_prover execute --input <file.bin>

./target/release/z6m_zisk_prover prove \
    --input  <file.bin>   \
    --output proof.bin    \
    --mode   stark        # stark | minimal | plonk

./target/release/z6m_zisk_prover verify --proof proof.bin
```

---

## Public Output Format

The C++ guest outputs SHA-256(`new_payload_request_root[32] ∥ successful_validation[1]`)
packed into 8 × u32 LE slots at the ZisK output region (`OUTPUT_ADDR = 0xa001_0000`).

The host reads the first 32 bytes of the 256-byte output region and displays
the hex digest.  This is identical to the SP1 guest's public-values digest,
allowing proofs from both backends to be compared.

---

## How Input is Passed

The raw SSZ bytes from `mock_input.bin` are wrapped in one `ZiskStdin` record:

```
[u64 LE: byte length][raw SSZ bytes]
```

The ZisK prover maps this into the guest's input region at `INPUT_ADDR = 0x4000_0000`:

```
INPUT_ADDR + 0  : [8 bytes: reserved header]
INPUT_ADDR + 8  : [u64 LE: length]
INPUT_ADDR + 16 : [raw SSZ bytes]
```

The guest's `read_input_raw()` skips the 8-byte header, reads the u64 length,
and returns a pointer directly into the input region — no allocation, no ecall.

---

## Differences from the SP1 Integration Test (`int-test/`)

| Aspect | SP1 (`int-test/`) | ZisK (`int-test-zisk/`) |
|---|---|---|
| SDK crate | `sp1-sdk` | `zisk-sdk` |
| Input delivery | `SP1Stdin` → hint-stream ecalls | `ZiskStdin` → memory-mapped at `0x4000_0000` |
| Output reading | `pv.read::<[u8;32]>()` from PV buffer | `get_public_values_slice()` from output region |
| Halt in guest | Custom SP1 ecall `t0=0x00` | Standard `ecall` with `a7=93` |
| Proof kind options | core / compressed / groth16 / plonk | stark / minimal / plonk |
| CPU proving (macOS) | Supported | Emulator only (ASM executor requires Linux) |
| Rust toolchain (host) | Pinned 1.93.0 | Stable |
