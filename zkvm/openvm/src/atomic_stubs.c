// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>

#define WEAK   __attribute__((weak))
#define OPAQUE __attribute__((used,visibility("default")))

// --- Floating-point rounding (unused in zkVM, stub out) ---------------------
WEAK OPAQUE
int fegetround(void) { return 0; }

WEAK OPAQUE
int fesetround(int r) { (void)r; return 0; }

// --- 32-bit atomics (zkVM is single-threaded; plain loads/stores suffice) ---
WEAK OPAQUE
int __atomic_fetch_add_4(volatile int *ptr, int val, int memorder)
{
    (void)memorder;
    int old = *ptr;
    *ptr += val;
    return old;
}

WEAK OPAQUE
int __atomic_fetch_sub_4(volatile int *ptr, int val, int memorder)
{
    (void)memorder;
    int old = *ptr;
    *ptr -= val;
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
