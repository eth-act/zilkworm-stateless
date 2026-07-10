// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* OpenVM zkVM runtime for pure C++ guest (rv32im bare-metal).
 *
 * Provides: _start support (__start), a bump-allocator _sbrk for newlib
 * malloc, and read_vec_raw() built from OpenVM's hint-stream instructions.
 *
 * OpenVM memory layout (openvm-platform crate: crates/toolchain/platform/src/memory.rs):
 *   GUEST_MIN_MEM = 0x0000_0400   (lowest usable guest address)
 *   TEXT_START    = 0x0020_0800   (code loads here; heap starts after BSS)
 *   STACK_TOP     = 0x0020_0400   (initial SP; stack grows downward)
 *   MEM_SIZE      = 0x2000_0000   (512 MiB ceiling)
 *
 * Output is committed directly by main.cpp via openvm::reveal_u32() — unlike
 * RISC0's tagged-hash journal scheme, OpenVM's public-output mechanism is
 * "reveal individual u32 words," so there is no journal buffer to maintain
 * here.
 */

#include <cstddef>
#include <cstdint>
#include "include/openvm_syscalls.hpp"

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
 *  read_vec_raw – read one hint-stream input vector                            *
 *                                                                               *
 *  Mirrors openvm::io::read_vec() exactly (extensions/rv32im/guest/src/io.rs): *
 *    1. hint_input()               – advance to the next hint stream           *
 *    2. hint_read_u32(scratch)     – read the 4-byte length prefix             *
 *    3. hint_buffer_chunked(...)   – read ceil(len/4) words, chunked at 1023   *
 *                                    words/instruction                         *
 *                                                                               *
 *  Allocation is from the heap (via _sbrk), rounded up to a 4-byte boundary    *
 *  for word-aligned access, matching sp1_syscalls.hpp / risc0's read_vec_raw.  *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" openvm::ReadVecResult read_vec_raw() noexcept {
    using namespace openvm;

    hint_input();

    /* 1. Read the 4-byte length prefix into a scratch word. */
    uint32_t scratch = 0;
    uint32_t len = hint_read_u32(&scratch);

    if (len == 0) [[unlikely]] {
        return {nullptr, 0, 0};
    }

    /* 2. Allocate (round up to 4-byte boundary for word alignment). */
    size_t capacity = (static_cast<size_t>(len) + 3) & ~size_t(3);
    uint8_t *ptr = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>(capacity)));

    /* 3. Read the payload, chunked at MAX_HINT_BUFFER_WORDS per instruction. */
    hint_buffer_chunked(ptr, capacity / 4);

    return {ptr, static_cast<size_t>(len), capacity};
}

/* ─────────────────────────────────────────────────────────────────────────── *
 *  sys_panic – print message (best-effort) and halt with exit code 1          *
 * ─────────────────────────────────────────────────────────────────────────── */
extern "C" __attribute__((cold)) [[noreturn]] void sys_panic(const uint8_t *msg, size_t len) {
    openvm::print_str(reinterpret_cast<const char *>(msg), len);
    openvm::terminate_failure();
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

    /* 2. Call guest program. */
    main();

    /* 3. Halt with success (never returns). */
    openvm::terminate_success();
}
