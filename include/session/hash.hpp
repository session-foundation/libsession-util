#pragma once

#include <optional>

#include "types.hpp"

namespace session::hash {

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function.
///
/// Inputs:
/// - `size` -- length of the hash to be generated.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.
///
/// Outputs:
/// - a `size` byte hash.
std::vector<unsigned char> hash(
        const size_t size,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key = std::nullopt);

}  // namespace session::hash
