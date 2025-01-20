#pragma once

#include "types.hpp"

namespace session::random {

/// API: random/random
///
/// Wrapper around the randombytes_buf function.
///
/// Inputs:
/// - `size` -- the number of random bytes to be generated.
///
/// Outputs:
/// - random bytes of the specified length.
ustring random(size_t size);

/// API: random/random_base32
///
/// Return a random base32 string with the given length.
///
/// Inputs:
/// - `size` -- the number of characters to be generated.
///
/// Outputs:
/// - random base32 string of the specified length.
std::string random_base32(size_t size);

}  // namespace session::random
