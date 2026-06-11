// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* RISC0 zkVM entry point for rv32im C++ guest.
 *
 * Memory layout (risc0/zkvm/platform/src/memory.rs):
 *   STACK_TOP  = 0x0020_0400   (initial SP; stack grows downward)
 *   TEXT_START = 0x0020_0800   (code loads here)
 *   GUEST_MAX_MEM = 0xC000_0000
 */

    .section .text._start
    .globl _start
    .type  _start, @function
_start:
    /* Initialise the global pointer for RISC-V GP-relative relaxation. */
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    /* Set stack pointer to RISC0's STACK_TOP.
       The stack grows downward from 0x200400 toward GUEST_MIN_MEM (0x4000),
       giving approximately 2 MB of stack space. */
    li      sp, 0x00200400

    /* Call the C++ runtime initialiser.  Runs global constructors,
       initialises the journal buffer, calls main(), then halts.
       Never returns. */
    call    __start

    /* Unreachable: spin as a safety net. */
1:  j       1b

    .size _start, . - _start
