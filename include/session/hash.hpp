#pragma once

#include <oxenc/common.h>

#include <array>
#include <optional>

#include "types.hpp"

namespace session::hash {

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function that returns a ustring of the requested
/// size containing the hash.
///
/// Inputs:
/// - `size` -- length of the hash to be generated.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.
///
/// Outputs:
/// - a `size` byte hash.
ustring hash(size_t size, ustring_view msg, std::optional<ustring_view> key = std::nullopt);

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function for generating a hash that takes a span
/// to write the hash into.  The size of the hash is determined from the size of the span.
///
/// Inputs:
/// - `hash` -- writable span in which to write the hash.  The size of the span must be between 16
///   and 64.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.  Must be less than 64 bytes long.
void hash(std::span<unsigned char> hash, ucspan msg, std::optional<ucspan> key = std::nullopt);

// Helper callable usable with unordered_map and similar to hash an array of chars by simply copying
// the first sizeof(size_t) bytes, suitable for use with pre-hashed values.
struct identity_hasher {
    template <oxenc::basic_char Char, size_t N>
    requires(N >= sizeof(size_t)) constexpr size_t operator()(
            const std::array<Char, N>& v) const noexcept {
        size_t out;
        std::copy(v.begin(), v.begin() + sizeof(out), reinterpret_cast<Char*>(&out));
        return out;
    }
};

}  // namespace session::hash
