/* z6m/ssz.hpp — Minimal SSZ decode + hash_tree_root helpers.
 *
 * Spec reference: stateless_ssz.py (Amsterdam fork)
 *
 * This is a hand-rolled, dependency-free SSZ implementation that:
 *   - Deserialises the SszStatelessInput container from the hint stream.
 *   - Computes hash_tree_root for all NewPayloadRequest variants so the
 *     guest can commit the correct new_payload_request_root.
 *   - Serialises SszStatelessValidationResult for the output.
 *
 * Only the subset of SSZ needed by this guest is implemented.
 * No dynamic memory allocation is used; all buffers are views into the
 * original input slice or into a small stack-allocated workspace.
 *
 * SHA-256 calls go through evmone::crypto::sha256(), which is accelerated
 * by the SP1 SHA-256 precompile ecalls via syscall_sha256_extend/compress.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <evmone_precompiles/sha256.hpp>

// SSZ primitive sizes

static constexpr size_t SSZ_OFFSET_SIZE = 4; // uint32 LE

// Byte-span view (no ownership)

struct ByteSpan {
    const uint8_t* ptr;
    size_t         len;

    constexpr bool empty() const noexcept { return len == 0; }

    ByteSpan slice(size_t off, size_t n) const noexcept {
        return {ptr + off, n};
    }
    ByteSpan from(size_t off) const noexcept {
        return {ptr + off, len - off};
    }
};

// LE integer readers

[[nodiscard]] static inline uint32_t read_u32le(const uint8_t* p) noexcept {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v; // host is LE on RISC-V; harmless on any arch since SP1 target is LE
}

[[nodiscard]] static inline uint64_t read_u64le(const uint8_t* p) noexcept {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

// SHA-256 wrapper (evmone, SP1-accelerated)

static inline void sha256_bytes(uint8_t out[32], const uint8_t* data, size_t len) noexcept {
    evmone::crypto::sha256(
        reinterpret_cast<std::byte*>(out),
        reinterpret_cast<const std::byte*>(data), len);
}

static inline void sha256_pair(uint8_t out[32], const uint8_t left[32], const uint8_t right[32]) noexcept {
    uint8_t buf[64];
    std::memcpy(buf,      left,  32);
    std::memcpy(buf + 32, right, 32);
    sha256_bytes(out, buf, 64);
}

// SSZ hash_tree_root primitives

// Zero hash used as padding when merkleizing with fewer chunks than the next power-of-two.
static constexpr uint8_t ZERO_HASH[32] = {};

// Merkleize a flat array of 32-byte chunks (count must be a power-of-two or padded).
// Writes the root into `out[32]`.  Uses stack space proportional to the height.
// For our use case, the maximum chunk count is bounded by MAX_TRANSACTIONS_PER_PAYLOAD
// so this function is called with at most a few thousand chunks.
static void merkleize_chunks(uint8_t out[32], const uint8_t* chunks, size_t chunk_count) noexcept;

// Pad `chunk_count` to the next power-of-two, then merkleize.
static void merkleize(uint8_t out[32], const uint8_t* chunks, size_t chunk_count, size_t limit) noexcept;

// mix_in_length: sha256(root || uint256(length))
static inline void mix_in_length(uint8_t out[32], const uint8_t root[32], uint64_t length) noexcept {
    uint8_t buf[64] = {};
    std::memcpy(buf, root, 32);
    // length as little-endian uint256 (only lower 8 bytes are nonzero)
    std::memcpy(buf + 32, &length, 8);
    sha256_bytes(out, buf, 64);
}

// hash_tree_root of a boolean (padded to 32 bytes)
static inline void htr_bool(uint8_t out[32], bool v) noexcept {
    std::memset(out, 0, 32);
    out[0] = v ? 1 : 0;
}

// hash_tree_root of a uint64 (padded to 32 bytes, LE)
static inline void htr_uint64(uint8_t out[32], uint64_t v) noexcept {
    std::memset(out, 0, 32);
    std::memcpy(out, &v, 8);
}

// hash_tree_root of a uint256 (already 32 bytes, LE)
static inline void htr_uint256(uint8_t out[32], const uint8_t v[32]) noexcept {
    std::memcpy(out, v, 32);
}

// hash_tree_root of a fixed ByteVector[N] (N ≤ 32: zero-pad; N > 32: chunk)
// For our types, ByteVector lengths are 20, 32, 48, 96, 256.
static void htr_byte_vector(uint8_t out[32], const uint8_t* data, size_t n) noexcept {
    if (n <= 32) {
        std::memset(out, 0, 32);
        std::memcpy(out, data, n);
        return;
    }
    // Chunk into 32-byte pieces; the last chunk is zero-padded.
    size_t nchunks = (n + 31) / 32;
    // We build a temporary array on the stack for small sizes.
    // For n=256 (bloom) nchunks=8, for n=96 nchunks=3, for n=48 nchunks=2.
    // Maximum used: 256 bytes → 8 chunks.
    static constexpr size_t MAX_CHUNKS = 8;
    uint8_t chunks[MAX_CHUNKS][32] = {};
    for (size_t i = 0; i < nchunks && i < MAX_CHUNKS; ++i) {
        size_t off = i * 32;
        size_t copy = (off + 32 <= n) ? 32 : (n - off);
        std::memcpy(chunks[i], data + off, copy);
    }
    merkleize_chunks(out, chunks[0], nchunks);
}

// hash_tree_root of a ByteList[N]: merkleize(pack(data), limit=chunk_limit) + mix_in_length
static void htr_byte_list(uint8_t out[32], const uint8_t* data, size_t data_len, size_t limit_bytes) noexcept {
    // pack: group bytes into 32-byte chunks
    size_t nchunks = (data_len + 31) / 32;
    size_t limit_chunks = (limit_bytes + 31) / 32;

    // For very small data, a stack buffer is fine.
    // Allocate on the heap via the bump allocator is not available here.
    // Use a fixed stack buffer sufficient for our maximum sizes.
    // Largest ByteList we encounter: MAX_BLOCK_ACCESS_LIST_BYTES = 2^24 = 16MB — too large for stack.
    // But we only need to merkleize the chunks, which can be done iteratively.
    // We implement a streaming merkleize that doesn't store all chunks at once.
    //
    // For simplicity, and because the guest only needs correctness (not performance),
    // we use a recursive halving approach with a stack depth proportional to log2(limit_chunks).

    // merkleize handles the trailing partial chunk (zero-padded) and virtual
    // zero leaves up to the limit via the zero-hash ladder.
    (void)nchunks;
    uint8_t root[32];
    merkleize(root, data, data_len, limit_chunks);
    mix_in_length(out, root, data_len);
}

// Merkleize implementations

// Next power of two >= n (minimum 1).
static size_t next_pow2(size_t n) noexcept {
    if (n <= 1) return 1;
    --n;
    n |= n >> 1; n |= n >> 2; n |= n >> 4;
    n |= n >> 8; n |= n >> 16; n |= n >> 32;
    return n + 1;
}

// Root of an all-zero subtree with 2^depth leaves:
//   zero_subtree(0) = 32 zero bytes, zero_subtree(d) = H(z(d-1) || z(d-1)).
// Lazily filled once; SSZ list limits bound the depth well below 64. Without
// this shortcut, merkleizing a list with a large limit (e.g. a transaction
// ByteList capped at 2^30 bytes = 2^25 chunks) walks tens of millions of
// virtual zero leaves per item.
static const uint8_t* zero_subtree_root(size_t depth) noexcept {
    static uint8_t table[64][32];
    static size_t  filled = 0;   // levels [0, filled) are valid
    if (depth >= 64) depth = 63;
    while (filled <= depth) {
        if (filled == 0)
            std::memset(table[0], 0, 32);
        else
            sha256_pair(table[filled], table[filled - 1], table[filled - 1]);
        ++filled;
    }
    return table[depth];
}

// Recursive merkleize over `data_len` bytes of chunk data, padded to `total`
// (power-of-two) 32-byte leaves. A final partial chunk is zero-padded; leaves
// beyond the data are zero. Cost is O(data_len/32 · log(total)): empty
// subtrees resolve via the zero-hash ladder instead of being walked
// leaf-by-leaf.
static void merkleize_power_of_two(
    uint8_t out[32],
    const uint8_t* data,  // raw chunk bytes (not necessarily a multiple of 32)
    size_t data_len,      // number of valid bytes at `data`
    size_t total          // leaf count, padded to power-of-two
) noexcept {
    if (data_len == 0) {
        size_t depth = 0;
        while ((size_t{1} << depth) < total) ++depth;
        std::memcpy(out, zero_subtree_root(depth), 32);
        return;
    }
    if (total == 1) {
        if (data_len >= 32) {
            std::memcpy(out, data, 32);
        } else {
            std::memset(out, 0, 32);
            std::memcpy(out, data, data_len);
        }
        return;
    }
    size_t half = total / 2;
    size_t half_bytes = half * 32;
    uint8_t left[32], right[32];
    size_t left_len  = (data_len > half_bytes) ? half_bytes : data_len;
    size_t right_len = (data_len > half_bytes) ? data_len - half_bytes : 0;
    merkleize_power_of_two(left, data, left_len, half);
    merkleize_power_of_two(right, data + half_bytes, right_len, half);
    sha256_pair(out, left, right);
}

static void merkleize_chunks(uint8_t out[32], const uint8_t* chunks, size_t chunk_count) noexcept {
    if (chunk_count == 0) {
        // hash_tree_root of empty = SHA-256 of 64 zero bytes
        sha256_pair(out, ZERO_HASH, ZERO_HASH);
        return;
    }
    size_t padded = next_pow2(chunk_count);
    merkleize_power_of_two(out, chunks, chunk_count * 32, padded);
}

// Merkleize with a limit (for lists): pad to next_pow2(limit) virtual leaves.
// Real data is the `data_len` bytes at `data` (a trailing partial chunk is
// zero-padded); leaves past the data are zero.
static void merkleize(uint8_t out[32], const uint8_t* data, size_t data_len, size_t limit) noexcept {
    if (limit == 0) {
        std::memset(out, 0, 32);
        return;
    }
    size_t padded = next_pow2(limit);
    merkleize_power_of_two(out, data, data_len, padded);
}

// SSZ container merkleize (for containers with a known set of field roots)

// Given an array of field hash_tree_roots (each 32 bytes), compute the
// container's hash_tree_root = merkleize(field_roots, limit=nfields).
static void htr_container(uint8_t out[32], const uint8_t (*field_roots)[32], size_t nfields) noexcept {
    // Container uses exact field count — padded to next power of two.
    // field_roots is a flat array of 32-byte entries.
    merkleize_chunks(out, field_roots[0], nfields);
}

// SSZ deserialization helpers

// Read a uint32 offset from an SSZ offset table entry.
static inline uint32_t ssz_read_offset(ByteSpan s, size_t i) noexcept {
    return read_u32le(s.ptr + i * SSZ_OFFSET_SIZE);
}

// For an SSZ container, extract the variable-length field at index `var_idx`
// (0-based among variable-length fields).  `fixed_size` is the total size of
// all fixed-size fields + offset placeholders.
//
// The first offset in the offset table gives the start of variable data.
// Consecutive offsets give the end of each variable field.
//
// Caller must know the layout and pass the offset position of this field's
// offset entry and the offset position of the *next* field (or end of data).
static inline ByteSpan ssz_varfield(ByteSpan container,
                                     uint32_t this_offset,
                                     uint32_t next_offset) noexcept {
    return {container.ptr + this_offset, next_offset - this_offset};
}









