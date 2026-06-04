// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* ZisK zkVM runtime for bare-metal C++ guest.
 *
 * Provides:
 *   - __start()       C++ runtime initialiser (runs global ctors, calls main)
 *   - sys_halt()      ZisK halt via ecall a7=93
 *   - sys_panic()     Emit message to UART then halt with exit code 1
 *   - _sbrk()         Bump-allocator heap for newlib malloc
 *   - g_zisk_output_slot  Public output slot counter used by write_output_bytes()
 *   - Bare-metal stubs for __cxa_atexit, __cxa_pure_virtual, _Unwind_Resume, etc.
 *
 * ZisK I/O ABI summary (0xpolygonhermez/zisk):
 *   Input  : memory-mapped at INPUT_ADDR (0x4000_0000), length-prefixed records.
 *   Output : up to 64 u32 slots at OUTPUT_ADDR (0xa001_0000).
 *   UART   : single-byte store to UART_ADDR (0xa000_0200).
 *   Halt   : ecall with a7 = 93 (Linux exit syscall number).
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "include/zisk_syscalls.hpp"

/* ─────────────────────────────────────────────────────────────────────────
 * Public output slot counter
 * Shared with zisk_syscalls.hpp (write_output_bytes uses it).
 * ───────────────────────────────────────────────────────────────────────── */
uint32_t g_zisk_output_slot = 0;

/* ─────────────────────────────────────────────────────────────────────────
 * Heap bump-allocator (_sbrk for newlib malloc)
 *
 * _end is the linker-provided symbol at the top of BSS (bottom of heap).
 * _init_stack_top is 256 KiB above _end; the heap grows upward toward the
 * stack.  For the short lifetime of a zkVM guest this is fine.
 * ───────────────────────────────────────────────────────────────────────── */
extern "C" { extern char _end; }

static char *_heap_ptr = nullptr;

/* Initialised once in __start() so the null check is free on the hot path. */
extern "C" void *_sbrk(ptrdiff_t incr) noexcept {
    char *prev   = _heap_ptr;
    _heap_ptr   += incr;
    return prev;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Bare-metal runtime stubs
 * ───────────────────────────────────────────────────────────────────────── */

extern "C" { void *__dso_handle = nullptr; }

extern "C" __attribute__((weak)) void _Unwind_Resume(void *) { __builtin_trap(); }

extern "C" __attribute__((weak))
int __gxx_personality_v0(int, int, uint64_t, void *, void *) { __builtin_trap(); }

extern "C" __attribute__((weak))
int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }

extern "C" __attribute__((weak))
void __cxa_pure_virtual() { __builtin_trap(); }

/* ─────────────────────────────────────────────────────────────────────────
 * ZisK halt
 *
 * Issues a standard RISC-V ecall with a7 = 93 (Linux exit syscall number).
 * ZisK's BIOS intercepts this and finalises the proof.
 * ───────────────────────────────────────────────────────────────────────── */
extern "C" [[noreturn]] void sys_halt(uint8_t exit_code) noexcept {
    register uint64_t a0 asm("a0") = static_cast<uint64_t>(exit_code);
    register uint64_t a7 asm("a7") = 93;   /* Linux SYS_exit */
    asm volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
    __builtin_unreachable();
}

/* ─────────────────────────────────────────────────────────────────────────
 * Panic hook
 * ───────────────────────────────────────────────────────────────────────── */
extern "C" [[noreturn]] void sys_panic(const uint8_t *msg_ptr, size_t len) noexcept {
    /* Emit message character-by-character to UART. */
    for (size_t i = 0; i < len; ++i)
        zisk_uart_write(static_cast<char>(msg_ptr[i]));
    zisk_uart_write('\n');
    sys_halt(1);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Linker-provided constructor / destructor arrays
 * ───────────────────────────────────────────────────────────────────────── */
extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

/* Forward declaration of the guest entry point (main.cpp). */
extern "C" int main();

/* ─────────────────────────────────────────────────────────────────────────
 * __start — called from zisk_entrypoint.S after .data/.bss are ready
 *
 *  0. Initialise the heap pointer (_sbrk base = _end, 8-byte aligned).
 *  1. Run C++ global pre-init and init arrays (global constructors).
 *  2. Call main().
 *  3. Halt the VM with exit code 0 (never returns).
 * ───────────────────────────────────────────────────────────────────────── */
extern "C" [[noreturn]] void __start() {
    /* 0. Heap base: align _end up to 8 bytes for rv64ima ld/sd safety. */
    _heap_ptr = reinterpret_cast<char *>(
        (reinterpret_cast<uintptr_t>(&_end) + 7) & ~uintptr_t(7));

    /* 1. C++ global constructors. */
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
        (*p)();
    for (auto p = __init_array_start; p != __init_array_end; ++p)
        (*p)();

    /* 2. Guest program. */
    main();

    /* 3. Halt with success. */
    sys_halt(0);
}
