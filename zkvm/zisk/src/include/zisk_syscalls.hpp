// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

/*
 * ZisK zkVM ABI constants and inline helpers.
 *
 * ZisK memory map (core/src/mem.rs):
 *
 *   INPUT_ADDR   0x4000_0000  Memory-mapped guest input (length-prefixed records)
 *   ROM_ADDR     0x8000_0000  ELF .text / .rodata
 *   RAM_ADDR     0xa000_0000  All writable RAM
 *   UART_ADDR    0xa000_0200  Write one byte here to emit to stdout
 *   OUTPUT_ADDR  0xa001_0000  Public output slots (up to 64 × u32 = 256 bytes)
 *   AVAIL_MEM    0xa003_0000  Guest heap start
 *
 * Precompile syscalls use CSR writes via the `csrs` instruction.
 * Halt uses a standard RISC-V ecall with a7 = 93 (Linux exit).
 * UART output uses a memory-mapped byte store to UART_ADDR.
 *
 * Source references (0xpolygonhermez/zisk):
 *   definitions/src/syscall.rs   — CSR port numbers
 *   ziskos/entrypoint/src/       — entry, I/O, syscall macros
 *   core/src/mem.rs              — memory map constants
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

/* ─────────────────────────────────────────────────────────────────────────
 * Memory-map constants
 * ───────────────────────────────────────────────────────────────────────── */

static constexpr uintptr_t ZISK_INPUT_ADDR  = 0x40000000ULL;
static constexpr uintptr_t ZISK_OUTPUT_ADDR = 0xa0010000ULL;
static constexpr uintptr_t ZISK_UART_ADDR   = 0xa0000200ULL;

/* The first 8 bytes of the input region are a reserved header (initially 0).
 * The first real record begins at offset 8:  [u64 len LE][len bytes of data]. */
static constexpr size_t ZISK_INPUT_HEADER   = 8;
/* Maximum number of u32 public-output slots. */
static constexpr uint32_t ZISK_MAX_OUTPUT_SLOTS = 64;

/* ─────────────────────────────────────────────────────────────────────────
 * Precompile syscall CSR port numbers  (definitions/src/syscall.rs)
 * ───────────────────────────────────────────────────────────────────────── */

static constexpr uint32_t ZISK_SC_KECCAKF         = 0x800;
static constexpr uint32_t ZISK_SC_ARITH256         = 0x801;
static constexpr uint32_t ZISK_SC_ARITH256_MOD     = 0x802;
static constexpr uint32_t ZISK_SC_SECP256K1_ADD    = 0x803;
static constexpr uint32_t ZISK_SC_SECP256K1_DBL    = 0x804;
static constexpr uint32_t ZISK_SC_SHA256F          = 0x805;
static constexpr uint32_t ZISK_SC_BN254_ADD        = 0x806;
static constexpr uint32_t ZISK_SC_BN254_DBL        = 0x807;
static constexpr uint32_t ZISK_SC_BN254_FP2_ADD    = 0x808;
static constexpr uint32_t ZISK_SC_BN254_FP2_SUB    = 0x809;
static constexpr uint32_t ZISK_SC_BN254_FP2_MUL    = 0x80A;
static constexpr uint32_t ZISK_SC_ARITH384_MOD     = 0x80B;
static constexpr uint32_t ZISK_SC_BLS12_381_ADD    = 0x80C;
static constexpr uint32_t ZISK_SC_BLS12_381_DBL    = 0x80D;
static constexpr uint32_t ZISK_SC_BLS12_381_FP2_ADD= 0x80E;
static constexpr uint32_t ZISK_SC_BLS12_381_FP2_SUB= 0x80F;
static constexpr uint32_t ZISK_SC_BLS12_381_FP2_MUL= 0x810;
static constexpr uint32_t ZISK_SC_ADD256           = 0x811;
static constexpr uint32_t ZISK_SC_POSEIDON2        = 0x812;
static constexpr uint32_t ZISK_SC_DMA_MEMCPY       = 0x813;
static constexpr uint32_t ZISK_SC_DMA_MEMCMP       = 0x814;
static constexpr uint32_t ZISK_SC_DMA_INPUTCPY     = 0x815;
static constexpr uint32_t ZISK_SC_DMA_MEMSET       = 0x816;
static constexpr uint32_t ZISK_SC_SECP256R1_ADD    = 0x817;
static constexpr uint32_t ZISK_SC_SECP256R1_DBL    = 0x818;
static constexpr uint32_t ZISK_SC_BLAKE2B_ROUND    = 0x819;
static constexpr uint32_t ZISK_SC_PROFILE          = 0x81A;

/* ─────────────────────────────────────────────────────────────────────────
 * CSR precompile syscall macro
 *
 * ZisK precompiles are invoked by writing the address of the operand
 * buffer into a custom CSR via the `csrs` instruction:
 *
 *   csrs  <port>, <register holding ptr>
 *
 * The CSR number must be a compile-time constant (encoded in the immediate
 * field of the CSRRS instruction), hence the macro approach.
 * ───────────────────────────────────────────────────────────────────────── */

#define ZISK_SYSCALL(csr_port, data_ptr)                                   \
    do {                                                                    \
        register uintptr_t _r asm("a0") =                                  \
            reinterpret_cast<uintptr_t>(data_ptr);                          \
        asm volatile("csrs " #csr_port ", %0" : : "r"(_r) : "memory");     \
    } while (0)

/* ─────────────────────────────────────────────────────────────────────────
 * Input: read from the memory-mapped input region
 *
 * Format at ZISK_INPUT_ADDR:
 *   [8 bytes: reserved header]
 *   [8 bytes: u64 LE record length]
 *   [len bytes: record data]
 *   ... (additional records follow, each 8-byte aligned)
 *
 * read_input_raw() returns the first record.  The ZisK prover populates
 * INPUT_ADDR before execution starts; no fcall is needed for the initial
 * record.
 * ───────────────────────────────────────────────────────────────────────── */

struct ZiskInputBuf {
    const uint8_t *ptr;   /* pointer to record data                      */
    size_t         len;   /* byte length of record                       */
};

[[nodiscard]]
inline ZiskInputBuf read_input_raw() noexcept {
    /* Skip the 8-byte reserved header, then read the u64 length prefix. */
    const uint8_t *base = reinterpret_cast<const uint8_t *>(
        ZISK_INPUT_ADDR + ZISK_INPUT_HEADER);

    uint64_t len;
    __builtin_memcpy(&len, base, sizeof(len));   /* LE u64, no alignment req */

    return { base + sizeof(len), static_cast<size_t>(len) };
}

/* ─────────────────────────────────────────────────────────────────────────
 * Output: write public values as u32 LE slots
 *
 * ZisK exposes up to 64 u32 slots at OUTPUT_ADDR (0xa001_0000).  The
 * prover reads these after the guest halts and includes them in the proof's
 * public inputs.  No hashing or framing is done by ZisK itself — the guest
 * writes exactly what the verifier will see.
 *
 * write_output_bytes() packs an arbitrary byte array into consecutive u32
 * LE slots, zero-padding the last slot if the length is not a multiple of 4.
 * ───────────────────────────────────────────────────────────────────────── */

extern uint32_t g_zisk_output_slot;   /* defined in zisk_runtime.cpp       */

[[gnu::always_inline]]
inline void zisk_set_output(uint32_t slot, uint32_t value) noexcept {
    volatile uint32_t *out =
        reinterpret_cast<volatile uint32_t *>(ZISK_OUTPUT_ADDR + 4ULL * slot);
    *out = value;
}

inline void write_output_bytes(const uint8_t *data, size_t len) noexcept {
    size_t i = 0;
    /* Full 4-byte words. */
    for (; i + 4 <= len; i += 4) {
        uint32_t word;
        __builtin_memcpy(&word, data + i, 4);
        zisk_set_output(g_zisk_output_slot++, word);
    }
    /* Remaining 1–3 bytes: zero-pad to u32. */
    if (i < len) {
        uint32_t word = 0;
        __builtin_memcpy(&word, data + i, len - i);
        zisk_set_output(g_zisk_output_slot++, word);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * UART debug output (single-byte memory-mapped write)
 * ───────────────────────────────────────────────────────────────────────── */

[[gnu::always_inline]]
inline void zisk_uart_write(char c) noexcept {
    *reinterpret_cast<volatile char *>(ZISK_UART_ADDR) = c;
}

inline void zisk_print(const char *s) noexcept {
    for (; *s; ++s) zisk_uart_write(*s);
}

inline void zisk_print(std::string_view s) noexcept {
    for (char c : s) zisk_uart_write(c);
}

inline void zisk_println(const char *s) noexcept {
    zisk_print(s);
    zisk_uart_write('\n');
}

inline void zisk_println(std::string_view s) noexcept {
    zisk_print(s);
    zisk_uart_write('\n');
}

/* ─────────────────────────────────────────────────────────────────────────
 * Halt / exit
 *
 * ZisK halts via a standard RISC-V ecall with a7 = 93 (Linux exit).
 * The BIOS intercepts this ecall and finalises the proof, reading the
 * output slots from OUTPUT_ADDR.
 * ───────────────────────────────────────────────────────────────────────── */

extern "C" [[noreturn]] void sys_halt(uint8_t exit_code) noexcept;

/* ─────────────────────────────────────────────────────────────────────────
 * Panic hook (called by unrecoverable runtime errors)
 * ───────────────────────────────────────────────────────────────────────── */

extern "C" [[noreturn]] void sys_panic(const uint8_t *msg_ptr, size_t len) noexcept;
