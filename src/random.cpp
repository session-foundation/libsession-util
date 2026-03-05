#include "session/random.hpp"

#include <fmt/ranges.h>
#include <sodium/randombytes.h>

#include <algorithm>
#include <atomic>

#include "session/export.h"
#include "session/util.hpp"

namespace session::random {

std::vector<unsigned char> random(size_t size) {
    std::vector<unsigned char> result;
    result.resize(size);
    randombytes_buf(result.data(), size);

    return result;
}

static constexpr auto base32_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"sv;
std::string random_base32(size_t size) {
    std::string result;
    result.reserve(size);
    constexpr auto bits_per_char = 5;
    constexpr auto chars_per_draw = 64 / bits_per_char;
    static_assert(1 << bits_per_char == base32_charset.size());
    constexpr uint64_t mask = (1 << bits_per_char) - 1;

    do {
        auto bits = csrng();
        for (int i = 0; result.size() < size && i < chars_per_draw; i++) {
            result.push_back(base32_charset[bits & mask]);
            bits >>= bits_per_char;
        }
    } while (result.size() < size);

    return result;
}

std::string unique_id(std::string_view prefix) {
    static std::atomic<uint32_t> counter{0};
    return fmt::format(
            "{}-{}-{}", prefix, counter.fetch_add(1, std::memory_order_relaxed), random_base32(4));
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
