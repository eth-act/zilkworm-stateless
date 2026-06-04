// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* ZisK zkVM entry point for rv64ima C++ guest.
 *
 * ZisK's prover loads the guest ELF and begins execution at the symbol
 * named by the ELF e_entry field, which is _start below.  _start must
 * land at ROM_ADDR (0x8000_0000) — enforced by the .text.init section
 * placement in zisk.ld.
 *
 * Responsibilities (in order):
 *   1. Initialise the global pointer (gp) for RISC-V linker relaxation.
 *   2. Set the stack pointer to _init_stack_top (top of a 256 KiB stack
 *      just above BSS in the RAM region).
 *   3. Copy the .data section from its ROM load address (__data_load) to
 *      its RAM run address [__data_start, __data_end).  Done in pure
 *      assembly so no C runtime is required.
 *   4. Zero the .bss section in the same way.
 *   5. Call __start() (in zisk_runtime.cpp) which runs C++ global
 *      constructors and then calls main().  __start never returns — it
 *      issues the ZisK halt ecall.
 *
 * All of steps 3–4 are done with inline word loops so we need no memcpy
 * or memset before the runtime is ready.
 */

    .section .text.init, "ax", @progbits
    .globl _start
    .type  _start, @function
_start:
    /* ── 1. Global pointer ────────────────────────────────────────────── */
    /* Required before any GP-relative access (sdata, sbss, etc.).
     * .option norelax prevents the assembler from rewriting this la into a
     * GP-relative load, which would be circular.                           */
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    /* ── 2. Stack pointer ──────────────────────────────────────────────── */
    /* _init_stack_top is set by the linker script to 256 KiB above BSS.   */
    la      sp, _init_stack_top

    /* ── 3. Copy .data from ROM (LMA) to RAM (VMA) ─────────────────────
     * Source : __data_load  (ROM address where the ELF stored the image)
     * Dest   : [__data_start, __data_end)  (RAM run addresses)
     * If LMA == VMA (no split) skip the copy.                              */
    la      t0, __data_load     /* source: ROM LMA                         */
    la      t1, __data_start    /* dest:   RAM VMA start                   */
    la      t2, __data_end      /* dest:   RAM VMA end                     */
    beq     t0, t1, .Lbss_zero  /* LMA == VMA → no copy needed            */
    bgeu    t1, t2, .Lbss_zero  /* zero-length .data → skip                */
.Ldata_copy:
    ld      t3, 0(t0)
    sd      t3, 0(t1)
    addi    t0, t0, 8
    addi    t1, t1, 8
    bltu    t1, t2, .Ldata_copy

    /* ── 4. Zero .bss ─────────────────────────────────────────────────── */
    /* [__bss_start, __BSS_END__) is 8-byte aligned by the linker script.  */
.Lbss_zero:
    la      t0, __bss_start
    la      t1, __BSS_END__
    bgeu    t0, t1, .Lruntime   /* empty .bss → skip                       */
.Lbss_loop:
    sd      zero, 0(t0)
    addi    t0, t0, 8
    bltu    t0, t1, .Lbss_loop

    /* ── 5. C++ runtime + main ─────────────────────────────────────────── */
    /* __start() lives in zisk_runtime.cpp.  It runs global constructors,
     * calls main(), then halts the VM.  It never returns.                   */
.Lruntime:
    call    __start

    /* Unreachable: spin forever as a safety net. */
1:  j       1b

    .size _start, . - _start
