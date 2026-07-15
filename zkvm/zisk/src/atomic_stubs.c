// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* Bare-metal atomic and FPU environment stubs for ZisK rv64ima guest.
 *
 * The ZisK ISA is rv64ima (Integer + Multiply/Divide + Atomics, no float).
 * libstdc++ and silkworm_core reference __atomic_* builtins; in a single-
 * threaded bare-metal environment these reduce to simple load/store.
 * The lp64 ABI has no hardware FPU, so fegetround/fesetround are no-ops.
 */

#include <stdint.h>

#define WEAK   __attribute__((weak))
#define OPAQUE __attribute__((used, visibility("default")))

/* ─── Floating-point environment (no FPU in lp64) ─────────────────────── */
WEAK OPAQUE int fegetround(void)  { return 0; }
WEAK OPAQUE int fesetround(int)   { return 0; }

/* ─── 32-bit atomics ───────────────────────────────────────────────────── */
WEAK OPAQUE
int __atomic_fetch_add_4(volatile int *ptr, int val, int memorder)
{
    (void)memorder;
    int old = *ptr;
    *ptr   += val;
    return old;
}

WEAK OPAQUE
int __atomic_fetch_sub_4(volatile int *ptr, int val, int memorder)
{
    (void)memorder;
    int old = *ptr;
    *ptr   -= val;
    return old;
}

WEAK OPAQUE
int __atomic_compare_exchange_4(volatile int *ptr, int *expected,
                                 int desired, int weak,
                                 int success_mem, int failure_mem)
{
    (void)weak; (void)success_mem; (void)failure_mem;
    if (*ptr == *expected) { *ptr = desired; return 1; }
    *expected = *ptr;
    return 0;
}

/* ─── 64-bit atomics ───────────────────────────────────────────────────── */
WEAK OPAQUE
long long __atomic_fetch_add_8(volatile long long *ptr, long long val, int memorder)
{
    (void)memorder;
    long long old = *ptr;
    *ptr += val;
    return old;
}

WEAK OPAQUE
long long __atomic_fetch_sub_8(volatile long long *ptr, long long val, int memorder)
{
    (void)memorder;
    long long old = *ptr;
    *ptr -= val;
    return old;
}

WEAK OPAQUE
int __atomic_compare_exchange_8(volatile long long *ptr, long long *expected,
                                 long long desired, int weak,
                                 int success_mem, int failure_mem)
{
    (void)weak; (void)success_mem; (void)failure_mem;
    if (*ptr == *expected) { *ptr = desired; return 1; }
    *expected = *ptr;
    return 0;
}
