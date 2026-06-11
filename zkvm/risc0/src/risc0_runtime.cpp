// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* RISC0 zkVM runtime for pure C++ guest (rv32im bare-metal).
 *
 * Provides: _start support (__start), SOFTWARE ecall wrappers for
 *           sys_read / sys_write, HALT with tagged output-state digest,
 *           and a bump-allocator _sbrk for newlib malloc.
 *
 * RISC0 memory layout (risc0/zkvm/platform/src/memory.rs):
 *   GUEST_MIN_MEM = 0x0000_4000   (lowest usable guest address)
 *   TEXT_START    = 0x0020_0800   (code loads here; heap starts after BSS)
 *   STACK_TOP     = 0x0020_0400   (initial SP; stack grows downward)
 *   GUEST_MAX_MEM = 0xC000_0000   (highest usable guest address)
 *
 * Output-state digest computed at halt time:
 *   The HALT ecall requires an 8-word (32-byte) output_state that encodes
 *   the journal digest using RISC0's tagged-struct SHA256 scheme.
 *   All SHA256 is in RISC0's LE-u32 format (each 4-byte word byte-swapped
 *   relative to standard big-endian SHA256 output).
 *
 *   j   = risc0_sha256(all_journal_bytes)
 *   jd  = risc0_sha256( risc0_sha256("risc0.ReceiptJournal") || j )
 *   od  = risc0_sha256( risc0_sha256("risc0.Output") || jd || zeros32 )
 *   out_state = od   (as 8 LE-u32 words)
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "include/risc0_syscalls.hpp"
#include <evmone_precompiles/sha256.hpp>

/* ─────────────────────────────────────────────────────────────────────────── *
 *  Syscall name strings (must exactly match RISC0 host's expected strings).   *
 *  Format produced by declare_syscall!() macro:                               *
 *    module_path!() "::" stringify!(NAME) "\0"                                *
 *  Module path of nr submodule = "risc0_zkvm_platform::syscall::nr"           *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" {
const char RISC0_NR_SYS_LOG[]   = "risc0_zkvm_platform::syscall::nr::SYS_LOG";
const char RISC0_NR_SYS_PANIC[] = "risc0_zkvm_platform::syscall::nr::SYS_PANIC";
const char RISC0_NR_SYS_READ[]  = "risc0_zkvm_platform::syscall::nr::SYS_READ";
const char RISC0_NR_SYS_WRITE[] = "risc0_zkvm_platform::syscall::nr::SYS_WRITE";
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  Bare-metal _sbrk (bump allocator for newlib malloc)                        *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" {
extern char _end;  // linker-provided end of BSS
}
static char *_heap_ptr = nullptr;

extern "C" void *_sbrk(ptrdiff_t incr) noexcept {
    char *prev = _heap_ptr;
    _heap_ptr += incr;
    return prev;
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  Bare-metal runtime stubs                                                    *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" { void *__dso_handle = nullptr; }

extern "C" __attribute__((weak)) void _Unwind_Resume(void *) { __builtin_trap(); }
extern "C" __attribute__((weak)) int  __gxx_personality_v0(
    int, int, uint64_t, void *, void *) { __builtin_trap(); }
extern "C" __attribute__((weak)) int  __cxa_atexit(void (*)(void *), void *, void *) { return 0; }
extern "C" __attribute__((weak)) void __cxa_pure_virtual() { __builtin_trap(); }

/* ─────────────────────────────────────────────────────────────────────────── *
 *  Journal buffer (accumulated and hashed at halt time)                        *
 * ─────────────────────────────────────────────────────────────────────────── */
static constexpr size_t JOURNAL_BUF_INITIAL_CAP = 4096;
static uint8_t *g_journal_buf = nullptr;
static size_t   g_journal_len = 0;
static size_t   g_journal_cap = 0;

static void journal_buf_init() {
    g_journal_buf = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>(JOURNAL_BUF_INITIAL_CAP)));
    g_journal_len = 0;
    g_journal_cap = JOURNAL_BUF_INITIAL_CAP;
}

static void journal_buf_append(const uint8_t *data, size_t len) {
    if (g_journal_len + len > g_journal_cap) [[unlikely]] {
        size_t new_cap = g_journal_cap;
        while (new_cap < g_journal_len + len)
            new_cap *= 2;
        uint8_t *new_buf = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>(new_cap)));
        std::memcpy(new_buf, g_journal_buf, g_journal_len);
        g_journal_buf = new_buf;
        g_journal_cap = new_cap;
    }
    std::memcpy(g_journal_buf + g_journal_len, data, len);
    g_journal_len += len;
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  RISC0 SHA256 helper                                                         *
 *                                                                               *
 *  RISC0 stores SHA256 digests as [u32; 8] in little-endian byte order.        *
 *  Standard SHA256 produces big-endian output (per the SHA256 spec).           *
 *  To match RISC0's Digest::as_bytes(), byte-swap each 4-byte word.            *
 *  This is used consistently throughout the tagged-struct output computation.  *
 * ─────────────────────────────────────────────────────────────────────────── */
static void risc0_sha256(uint8_t out[32], const uint8_t *data, size_t len) {
    // Standard big-endian SHA256 via evmone (software path – no SP1 defined)
    evmone::crypto::sha256(reinterpret_cast<std::byte *>(out),
                           reinterpret_cast<const std::byte *>(data), len);
    // Byte-swap each 32-bit word: BE → LE (RISC0 Digest byte layout)
    for (int i = 0; i < 8; i++) {
        const uint8_t a = out[i*4+0], b = out[i*4+1],
                      c = out[i*4+2], d = out[i*4+3];
        out[i*4+0] = d; out[i*4+1] = c;
        out[i*4+2] = b; out[i*4+3] = a;
    }
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  SOFTWARE ecall: sys_write(fd, buf, nbytes)                                  *
 *                                                                               *
 *  Register mapping (from risc0/zkvm/platform/src/syscall.rs):                 *
 *    t0 = ECALL_SOFTWARE (2)                                                    *
 *    t6 = Syscall::Write (16)                                                   *
 *    a0 = NULL    (no from-host buffer)                                         *
 *    a1 = 0       (0 from-host words)                                           *
 *    a2 = ptr to syscall name string                                            *
 *    a3 = fd                                                                    *
 *    a4 = write buffer pointer                                                  *
 *    a5 = byte count                                                            *
 * ─────────────────────────────────────────────────────────────────────────── */
static void risc0_sys_write(uint32_t fd, const uint8_t *buf, size_t nbytes) {
    register uint32_t t0 asm("t0") = RISC0_ECALL_SOFTWARE;
    register uint32_t t6 asm("t6") = RISC0_SYSCALL_WRITE;
    register uint32_t a0 asm("a0") = 0;   // no recv buffer
    register uint32_t a1 asm("a1") = 0;   // 0 recv words
    register uint32_t a2 asm("a2") = reinterpret_cast<uint32_t>(RISC0_NR_SYS_WRITE);
    register uint32_t a3 asm("a3") = fd;
    register uint32_t a4 asm("a4") = reinterpret_cast<uint32_t>(buf);
    register uint32_t a5 asm("a5") = static_cast<uint32_t>(nbytes);
    asm volatile("ecall"
                 : "+r"(a0), "+r"(a1)
                 : "r"(t0), "r"(t6), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
                 : "memory");
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  SOFTWARE ecall: sys_read(fd, buf, nbytes) → bytes_read                      *
 *                                                                               *
 *  Register mapping:                                                            *
 *    t0 = ECALL_SOFTWARE (2)                                                    *
 *    t6 = Syscall::Read (12)                                                    *
 *    a0 = receive buffer pointer (in/out: host fills this)                     *
 *    a1 = byte count (buffer capacity; in/out)                                 *
 *    a2 = ptr to syscall name string                                            *
 *    a3 = fd                                                                    *
 *    a4 = byte count (requested)                                                *
 *  Returns: a0 = bytes actually read                                            *
 * ─────────────────────────────────────────────────────────────────────────── */
static size_t risc0_sys_read(uint32_t fd, uint8_t *buf, size_t nbytes) {
    register uint32_t t0 asm("t0") = RISC0_ECALL_SOFTWARE;
    register uint32_t t6 asm("t6") = RISC0_SYSCALL_READ;
    register uint32_t a0 asm("a0") = reinterpret_cast<uint32_t>(buf);
    register uint32_t a1 asm("a1") = static_cast<uint32_t>(nbytes);
    register uint32_t a2 asm("a2") = reinterpret_cast<uint32_t>(RISC0_NR_SYS_READ);
    register uint32_t a3 asm("a3") = fd;
    register uint32_t a4 asm("a4") = static_cast<uint32_t>(nbytes);
    asm volatile("ecall"
                 : "+r"(a0), "+r"(a1)
                 : "r"(t0), "r"(t6), "r"(a2), "r"(a3), "r"(a4)
                 : "memory");
    return static_cast<size_t>(a0);
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  syscall_write (public API)                                                   *
 *                                                                               *
 *  Thin wrapper around risc0_sys_write.  If the fd is the journal, the bytes   *
 *  are also buffered locally for hashing at halt time.                          *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" void syscall_write(uint32_t fd, const uint8_t *buf, size_t nbytes) {
    risc0_sys_write(fd, buf, nbytes);
    if (fd == RISC0_FD_JOURNAL) [[unlikely]] {
        journal_buf_append(buf, nbytes);
    }
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  syscall_halt – compute RISC0 output state and issue HALT ecall              *
 *                                                                               *
 *  Output state computation (RISC0 tagged-struct SHA256 scheme):               *
 *    j   = risc0_sha256(journal_bytes)                                         *
 *    jd  = risc0_sha256(risc0_sha256("risc0.ReceiptJournal") || j)             *
 *    od  = risc0_sha256(risc0_sha256("risc0.Output") || jd || zeros[32])       *
 *                                                                               *
 *  HALT ecall registers:                                                        *
 *    t0 = ECALL_HALT (0)                                                        *
 *    a0 = (exit_code << 8) | TERMINATE(0)                                      *
 *    a1 = pointer to out_state [u32; 8]                                         *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" [[noreturn]] void syscall_halt(uint8_t exit_code) {
    /* 1. Journal content hash */
    uint8_t j[32];
    risc0_sha256(j, g_journal_buf, g_journal_len);

    /* 2. Journal tag: risc0_sha256("risc0.ReceiptJournal") */
    static const uint8_t receipt_journal_tag[] = "risc0.ReceiptJournal";
    uint8_t tag_rj[32];
    risc0_sha256(tag_rj, receipt_journal_tag,
                 sizeof(receipt_journal_tag) - 1 /* no NUL */);

    /* 3. Journal digest = risc0_sha256(tag_rj || j) */
    uint8_t jd_input[64];
    std::memcpy(jd_input,      tag_rj, 32);
    std::memcpy(jd_input + 32, j,      32);
    uint8_t jd[32];
    risc0_sha256(jd, jd_input, 64);

    /* 4. Output tag: risc0_sha256("risc0.Output") */
    static const uint8_t output_tag[] = "risc0.Output";
    uint8_t tag_out[32];
    risc0_sha256(tag_out, output_tag, sizeof(output_tag) - 1);

    /* 5. Output digest = risc0_sha256(tag_out || jd || zeros[32])
          Assumptions digest = Digest::ZERO = all-zero bytes */
    uint8_t od_input[96];
    std::memcpy(od_input,      tag_out, 32);
    std::memcpy(od_input + 32, jd,      32);
    std::memset(od_input + 64, 0,       32);

    uint8_t out_state[32];
    risc0_sha256(out_state, od_input, 96);

    /* 6. HALT ecall */
    {
        register uint32_t t0 asm("t0") = RISC0_ECALL_HALT;
        register uint32_t a0 asm("a0") =
            (static_cast<uint32_t>(exit_code) << 8) | RISC0_HALT_TERMINATE;
        register uint32_t a1 asm("a1") =
            reinterpret_cast<uint32_t>(out_state);
        asm volatile("ecall" : : "r"(t0), "r"(a0), "r"(a1) : "memory");
    }
    __builtin_unreachable();
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  read_vec_raw – read one length-prefixed input frame from stdin (fd 0)       *
 *                                                                               *
 *  Frame format (RISC0 serde / risc0_zkvm::guest::env::read_frame):            *
 *    [4 bytes: len as u32 little-endian] [len bytes: payload]                  *
 *                                                                               *
 *  Allocation is from the heap (via _sbrk).  Capacity is rounded up to the    *
 *  nearest 4 bytes for word-aligned access.                                    *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" ReadVecResult read_vec_raw() noexcept {
    /* 1. Read 4-byte length prefix */
    uint32_t len = 0;
    risc0_sys_read(RISC0_FD_STDIN,
                   reinterpret_cast<uint8_t *>(&len), 4);

    if (len == 0) [[unlikely]] {
        return {nullptr, 0, 0};
    }

    /* 2. Allocate (round up to 4-byte boundary for word alignment) */
    size_t capacity = (static_cast<size_t>(len) + 3) & ~size_t(3);
    uint8_t *ptr = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>(capacity)));

    /* 3. Read payload */
    risc0_sys_read(RISC0_FD_STDIN, ptr, static_cast<size_t>(len));

    return {ptr, static_cast<size_t>(len), capacity};
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  sys_panic – write message to stderr and halt with exit code 1               *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" __attribute__((cold)) [[noreturn]] void sys_panic(const uint8_t *msg, size_t len) {
    risc0_sys_write(RISC0_FD_STDERR, msg, len);
    syscall_halt(1);
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  Global constructors (linker-provided arrays)                                *
 * ─────────────────────────────────────────────────────────────────────────── */
extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

extern "C" int main();

extern "C" void __start() {
    /* 0. Initialise heap pointer from linker-provided _end symbol.
          Align to 4 bytes (rv32im word width). */
    _heap_ptr = reinterpret_cast<char *>(
        (reinterpret_cast<uintptr_t>(&_end) + 3) & ~uintptr_t(3));

    /* 1. Run C++ global constructors. */
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
        (*p)();
    for (auto p = __init_array_start; p != __init_array_end; ++p)
        (*p)();

    /* 2. Initialise journal buffer. */
    journal_buf_init();

    /* 3. Call guest program. */
    main();

    /* 4. Halt with success (never returns). */
    syscall_halt(0);
}
