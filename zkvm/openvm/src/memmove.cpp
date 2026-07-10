// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// memmove for rv32im (OpenVM zkVM).
//
// In practice memmove is called mostly by std::string for non-overlapping
// regions.  Forward to memcpy on the fast path; backward byte copy for the
// rare overlapping dst > src case.

#include <cstring>

extern "C" void *memmove(void *dest, const void *src, size_t n) noexcept {
    auto *d = static_cast<unsigned char *>(dest);
    const auto *s = static_cast<const unsigned char *>(src);
    if (d <= s || d >= s + n) [[likely]]
        return memcpy(dest, src, n);

    // Overlapping, dst > src: copy backward to avoid clobbering source.
    d += n;
    s += n;
    while (n--)
        *--d = *--s;
    return dest;
}
