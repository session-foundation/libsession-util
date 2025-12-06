#pragma once

#include <sodium/randombytes.h>

#include <algorithm>

#include "util.hpp"

namespace session {
/// rng type that uses llarp::randint(), which is cryptographically secure
struct CSRNG {
    using result_type = uint64_t;

    static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); };

    static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); };

    uint64_t operator()() {
        uint64_t i;
        randombytes((uint8_t*)&i, sizeof(i));
        return i;
    };
};

extern CSRNG csrng;

}  // namespace session

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
std::vector<unsigned char> random(size_t size);

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
