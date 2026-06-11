// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Optimized memcpy for rv32im (RISC0 zkVM).
//
// rv32im requires all lw/sw instructions to be 4-byte aligned.
// This implementation copies 4 bytes at a time when both src and dst are
// word-aligned, falling back to byte-by-byte for misaligned cases.
//
// Compiled with -fno-builtin so the compiler does not replace this with a
// call to itself.

__asm__(
    ".text\n"
    ".globl memcpy\n"
    ".p2align 2\n"
    ".type memcpy,@function\n"
"memcpy:\n"
    // a0 = dst, a1 = src, a2 = n; return a0 (original dst)
    "mv      a3, a0\n"              // save original dst
    "beqz    a2, .Lcpy_done\n"     // n == 0 → nothing to do

    // Check alignment: if (dst | src) & 3 != 0, byte copy
    "or      a4, a0, a1\n"
    "andi    a4, a4, 3\n"
    "bnez    a4, .Lcpy_byte\n"

    // --- Word-aligned fast path: copy 4 bytes per iteration ---
".Lcpy_word:\n"
    "li      a4, 4\n"
    "bltu    a2, a4, .Lcpy_byte\n" // fewer than 4 bytes left
    "lw      a5, 0(a1)\n"
    "sw      a5, 0(a0)\n"
    "addi    a0, a0,  4\n"
    "addi    a1, a1,  4\n"
    "addi    a2, a2, -4\n"
    "j       .Lcpy_word\n"

    // --- Byte fallback ---
".Lcpy_byte:\n"
    "beqz    a2, .Lcpy_done\n"
    "lbu     a4, 0(a1)\n"
    "sb      a4, 0(a0)\n"
    "addi    a0, a0,  1\n"
    "addi    a1, a1,  1\n"
    "addi    a2, a2, -1\n"
    "j       .Lcpy_byte\n"

".Lcpy_done:\n"
    "mv      a0, a3\n"             // return original dst
    "ret\n"
    ".size memcpy, . - memcpy\n"
);
