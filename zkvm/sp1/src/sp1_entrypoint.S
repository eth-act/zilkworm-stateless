// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* SP1 zkVM entry point for rv64im C++ guest.
 *
 * Sets up the global pointer (gp) and stack pointer (sp) before
 * transferring control to __start(), which initialises the C++ runtime
 * and calls main().
 *
 * Stack convention: SP1 HyperCube places the top of the guest stack at
 * 0x78000000.  The linker script places the .text segment starting at
 * 0x79000000 so the two regions do not overlap.
 */

    .section .text._start
    .globl _start
    .type  _start, @function
_start:
    /* Initialise the global pointer for RISC-V relaxation optimisations. */
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    /* Set the stack pointer to the SP1-mandated top-of-stack address. */
    li      sp, 0x78000000

    /* Call the C++ runtime initialiser, which runs global constructors
       and then calls main().  It never returns — it calls syscall_halt(). */
    call    __start

    /* Unreachable: spin forever as a safety net. */
1:  j       1b

    .size _start, . - _start
