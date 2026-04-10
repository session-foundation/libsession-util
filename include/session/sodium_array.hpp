#pragma once

#include "util.hpp"

namespace session {

// Calls sodium_malloc for secure allocation; throws a std::bad_alloc on allocation failure
void* sodium_buffer_allocate(size_t size);
// Frees a pointer constructed with sodium_buffer_allocate.  Does nothing if `p` is nullptr.
void sodium_buffer_deallocate(void* p);
// Calls sodium_memzero to zero a buffer
void sodium_zero_buffer(void* ptr, size_t size);


// Wrapper around a type that uses `sodium_memzero` to zero the container on destruction; may only
// be used with trivially destructible types.
template <typename T, typename = std::enable_if_t<std::is_trivially_destructible_v<T>>>
struct sodium_cleared : T {
    using T::T;

    ~sodium_cleared() { sodium_zero_buffer(this, sizeof(*this)); }
};

template <oxenc::basic_char Char, size_t N>
struct cleared_array : sodium_cleared<std::array<Char, N>> {
    using sodium_cleared<std::array<Char, N>>::sodium_cleared;

    // Provide implicit conversion to fixed extent span because otherwise span's built-in is dynamic
    // extent (because span uses CTAD which detects std::array but not our subclass).
    operator std::span<Char, N>() { return std::span{static_cast<std::array<Char, N>&>(*this)}; }
    operator std::span<const Char, N>() const {
        return std::span{static_cast<const std::array<Char, N>&>(*this)};
    }
};

template <size_t N>
using cleared_bytes = cleared_array<std::byte, N>;
using cleared_b32 = cleared_bytes<32>;
using cleared_b64 = cleared_bytes<64>;


// sodium Allocator wrapper; this allocates/frees via libsodium, which is designed for dealing with
// sensitive data.  It is as a result slower and has more overhead than a standard allocator and
// intended for use with a container (such as std::vector) when storing keys.
template <typename T>
struct sodium_allocator {
    using value_type = T;

    [[nodiscard]] static T* allocate(std::size_t n) {
        return static_cast<T*>(sodium_buffer_allocate(n * sizeof(T)));
    }

    static void deallocate(T* p, std::size_t) { sodium_buffer_deallocate(p); }

    template <typename T2>
    bool operator==(const sodium_allocator<T2>&) const noexcept {
        return true;
    }
    template <typename T2>
    bool operator!=(const sodium_allocator<T2>&) const noexcept {
        return false;
    }
};

/// Vector that uses sodium's secure (but heavy) memory allocations
template <typename T>
using sodium_vector = std::vector<T, sodium_allocator<T>>;

// Like std::allocator but zeros memory before freeing.  Lighter weight than sodium_allocator
// (uses regular heap allocation) but still ensures sensitive data is wiped on deallocation.
template <typename T>
struct clearing_allocator {
    using value_type = T;

    [[nodiscard]] static T* allocate(std::size_t n) {
        return std::allocator<T>{}.allocate(n);
    }

    static void deallocate(T* p, std::size_t n) {
        sodium_zero_buffer(p, n * sizeof(T));
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename T2>
    bool operator==(const clearing_allocator<T2>&) const noexcept { return true; }
};

/// Vector that zeros its buffer on deallocation (including when resizing).  Lighter weight
/// than sodium_vector but still suitable for short-lived sensitive data.
template <typename T>
using cleared_vector = std::vector<T, clearing_allocator<T>>;

}  // namespace session
