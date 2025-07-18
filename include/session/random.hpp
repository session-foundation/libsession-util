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

/// API: random/get_uniform_distribution
///
/// Generates a cryptographically secure random integer within a given range (inclusive).
///
/// Inputs:
/// - `min` -- the minimum value for the range.
/// - `max` -- the maximum value for the range.
///
/// Outputs:
/// - A random integer in the specified range
template <typename T>
T get_uniform_distribution(T min, T max) {
    if (min > max)
        return min; 

    const uint64_t range = static_cast<uint64_t>(max) - static_cast<uint64_t>(min) + 1;
    return static_cast<T>(static_cast<uint64_t>(min) + (csrng() % range));
}

}  // namespace session::random
