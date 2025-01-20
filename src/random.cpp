#include "session/random.hpp"

#include <sodium/randombytes.h>

#include <algorithm>

#include "session/export.h"
#include "session/util.hpp"

namespace session::random {

constexpr char base32_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567";

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

ustring random(size_t size) {
    ustring result;
    result.resize(size);
    randombytes_buf(result.data(), size);

    return result;
}

std::string random_base32(size_t size) {
    CSRNG rng;
    std::string charset = base32_charset;
    std::string result;

    for (size_t i = 0; i < size; ++i) {
        std::shuffle(charset.begin(), charset.end(), rng);
        result.push_back(charset[0]);
    }

    return result;
}

}  // namespace session::random

extern "C" {

LIBSESSION_C_API unsigned char* session_random(size_t size) {
    auto result = session::random::random(size);
    auto* ret = static_cast<unsigned char*>(malloc(size));
    std::memcpy(ret, result.data(), result.size());
    return ret;
}

}  // extern "C"
