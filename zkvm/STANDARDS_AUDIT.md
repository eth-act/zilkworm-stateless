# zkvm-standards compliance audit — zilkworm-stateless guests

Audited against [eth-act/zkvm-standards](https://github.com/eth-act/zkvm-standards)
(8 published standards, cloned 2026-07-15). Three guest runtimes:
SP1 (`zkvm/sp1`), ZisK (`zkvm/zisk`), OpenVM (`zkvm/openvm`).

Legend: ✅ conforms · 🟡 partial / conditional · ❌ gap (migration needed) ·
🏛 vendor obligation (zkVM must provide; guest cannot self-remediate)

| Standard | SP1 | ZisK | OpenVM | Notes |
|---|---|---|---|---|
| riscv-target (`riscv64im_zicclsm`) | 🟡 | 🟡 | ❌ | see §1 |
| io-interface (`read_input`/`write_output`) | ❌ | ❌ | ❌ | see §2 |
| static-library-and-linker-script | 🟡 | 🟡 | 🟡 | see §3 |
| standard-termination-semantics | ✅* | ✅* | ✅* | fixed this audit, see §4 |
| memory-layout-restrictions | ✅ | ✅ | ✅ | see §5 |
| memory-safety-guard-regions | 🏛/🟡 | 🏛/🟡 | 🏛/🟡 | see §6 |
| instruction-address-misaligned | 🏛 | 🏛 | 🏛 | see §7 |
| c-interface-accelerators | ❌ | ❌ | ❌ | see §8 |

## 1. riscv-target — 🟡/❌

Standard mandates `riscv64im_zicclsm-unknown-none-elf` (RV64I + M, no C, no
F/D, LP64 soft-float, static ELF, little-endian, flat memory).

- **SP1**: `-march=rv64im -mabi=lp64` — ISA/ABI conform. `Zicclsm`
  (transparent misaligned loads/stores) is a **VM property**; SP1 HyperCube
  handles misaligned access. Effective: conforms.
- **ZisK**: `-march=rv64ima -mabi=lp64` — the **A extension is outside the
  mandated target**. Our `atomic_stubs.c` exists, so dropping `a` is likely a
  flag change + relink; ZisK's own toolchain docs suggest rv64ima, so confirm
  the VM accepts pure rv64im ELFs (it should — subset).
- **OpenVM**: `rv32im/ilp32` — **32-bit, off-target**. OpenVM does not
  execute rv64 today; this stays non-conformant until OpenVM ships an rv64
  target. Out of guest control (🏛-ish), but it means the OpenVM ELF cannot
  claim the standard target triple.

## 2. io-interface — ❌ all three (biggest migration, as predicted)

Standard: `void read_input(const uint8_t** buf, size_t* len)` (idempotent,
zero-copy, cannot fail) + `void write_output(const uint8_t*, size_t)`
(append semantics).

Current per-VM I/O:
- SP1: `read_vec_raw()` over the hint stream (destructive, NOT idempotent —
  each call consumes the next hint) + `syscall_write(FD_PUBLIC_VALUES)`.
- ZisK: memory-mapped `INPUT_ADDR 0x4000_0000` read + `OUTPUT_ADDR`
  64×u32 slots.
- OpenVM: hint stream reads + `reveal_u32()` word-wise public values.

Migration sketch (fits the current code shape well):
- Implement `read_input` per VM: SP1 = one `read_vec_raw` cached in statics
  (gives idempotence); ZisK = return the mapped input region directly
  (already zero-copy); OpenVM = cached hint read.
- Implement `write_output` per VM over the existing commit paths (SP1 PV
  buffer already has append semantics; OpenVM buffers then reveals words at
  halt; ZisK writes slots).
- Then all three `main.cpp`s collapse into ONE zkVM-agnostic file using
  `zkvm_io.h`. Blocked on nothing; coordinate with ere-guests' promised
  reference libs to avoid churn (they will ship vendor implementations).

## 3. static-library-and-linker-script — 🟡

The standard binds **vendors** to ship `_start` + IO + accelerators as a
static library with a linker script defining `_heap_start`/`_heap_end`. No
vendor libraries exist yet, so this repo hand-rolls all three runtimes
(vendor-role stand-ins).

Guest-side conformance done in this audit:
- ✅ `_heap_start` / `_heap_end` now defined in all three linker scripts, and
  the `_sbrk` bump allocators now base on `_heap_start` (was `_end`).
  **ZisK side effect**: the heap previously started at `_end`, i.e. *inside*
  the 256 KiB stack region (heap and stack could silently clobber each
  other — plausible contributor to the ZisK wild-pointer crash, task
  NEXT.10). The heap now starts above `_init_stack_top`.
- ✅ ENTRY(_start), gp/sp init, init_array constructors — already conform.
- ✅ BSS zeroing: all three zkVMs guarantee zero-initialized memory
  ("hardware zeroing" path expressly permitted by the standard).
- ❌ Not yet a vendor *static library* — when eth-act/ere-guests publish
  reference vendor libs, replace `{sp1,zisk,openvm}_{entrypoint.S,runtime.cpp,
  syscalls.hpp}` with them and keep only `main.cpp`.

## 4. standard-termination-semantics — ✅ (fixed in this audit)

Was ❌: all three `__start` functions discarded `main()`'s return value and
halted with success unconditionally, violating the mandated ABI (`0` =
success, non-zero = abnormal with error code). Now:
- SP1: `syscall_halt(rc)` (SP1 exit code preserved, 8-bit).
- ZisK: `sys_halt(rc)` (ecall a7=93 with a0=rc).
- OpenVM: `terminate_success()` / `terminate_failure()` — OpenVM's TERMINATE
  immediate is compile-time, so non-zero collapses to exit code 1
  (error-code range is expressly vendor-defined).
- `abort()`/`assert` already route to `sys_panic`-style halt(1) paths. ✅
- Verifier-side note: SP1/ZisK/OpenVM are all Type 1 verifiers for our use
  (proof of a failed execution does not verify as success).

## 5. memory-layout-restrictions — ✅

The standard blesses vendor-specific layouts via vendor linker scripts. Our
three scripts implement each VM's documented map (SP1 text @0x7900_0000 /
stack top 0x7800_0000; ZisK ROM 0x8000_0000 + RAM 0xa003_0000; OpenVM text
0x0020_0800 / stack top 0x0020_0400). Conforms by construction.

## 6. memory-safety-guard-regions — 🏛 vendor, 🟡 guest

Mandates: first 4 KiB non-accessible (null trap) + ≥4 KiB stack guard
adjacent below the stack, both trapping to abnormal termination.

- Trapping is enforceable only by the **zkVM** (🏛). None of the three VMs
  documents conformant guard regions today; raise with vendors/zkEVM team.
- Guest-side observations:
  - OpenVM reserves addresses below 0x400 (1 KiB) — smaller than the 4 KiB
    the standard requires, and no stack guard below 0x200400 (stack bottom
    is... stack grows down from 0x200400 toward 0x0 — the reserved 1 KiB IS
    the de-facto stack floor).
  - SP1: stack grows down from 0x7800_0000 with nothing mapped beneath —
    guard behavior depends on SP1's unmapped-page semantics.
  - ZisK: stack region sits directly above BSS with no guard gap; a stack
    overflow walks straight into `_end`-adjacent data. Now that the heap
    moved above the stack, consider inserting a 4 KiB guard gap between
    BSS and the stack base in `zisk.ld` (cheap, catches overflow only if
    the VM faults on unmapped access).
  - Mitigation available to us: `-fstack-clash-protection` (GCC 15 supports
    RISC-V) — consider adding to all three toolchain files.

## 7. instruction-address-misaligned — 🏛 vendor / ✅ guest

Pure VM semantics (misaligned jump ⇒ abnormal termination, no rounding).
Guest obligation is nil; our code is C/C++ compiled `-march` without the C
extension, so IALIGN=32 as assumed. Nothing to do in this repo.

## 8. c-interface-accelerators — ❌ all three

Standard ships `zkvm_accelerators.h` (keccak256, sha256, secp256k1/r1,
bn254, BLS12-381, modexp, ripemd160, blake2f — 8-byte-aligned structs,
`zkvm_status` returns). Current acceleration is `#ifdef SP1/ZISK/OPENVM`
blocks inside the zvm1 evmone fork calling raw per-VM ecalls/insns.

Migration: implement `zkvm_accelerators.h` in each runtime (thin shims over
the existing ecall wrappers — the hard part, the ecall encodings, is done),
then switch zvm1's hooks to call the standard ABI unconditionally. Result:
zvm1 works unmodified on ANY conformant zkVM. Depends on nothing; ~2-3 days
including re-benchmarks (watch for inlining loss at the C ABI boundary —
the SP1 hint-read fast path was cycle-tuned).

## Remediation queue (priority order)

1. ~~Termination semantics~~ — done (this audit).
2. ~~`_heap_start`/`_heap_end` + ZisK heap/stack overlap~~ — done (this audit).
3. io-interface shims + single shared `main.cpp` (~2 d) — do before
   ere-guests' tooling lands so the ELF interface is already standard.
4. c-interface-accelerators shims in the three runtimes + zvm1 switch (~3 d).
5. ZisK `-march=rv64im` (drop `a`) spike (~½ d).
6. Stack-guard gap in zisk.ld + `-fstack-clash-protection` across
   toolchains (~½ d, GCC only).
7. Track vendor gaps upstream: guard regions (all), rv64 target (OpenVM),
   Zicclsm statements (all), misaligned-fetch semantics statements (all).
