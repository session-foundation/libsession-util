#include "session/hash.hpp"
#include "session/hash.h"

#include <sodium/crypto_generichash_blake2b.h>

#include "session/export.h"
#include "session/util.hpp"

namespace {

void hash_impl(
        std::span<unsigned char> hash,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key) {
    const auto size = hash.size();
    if (size < crypto_generichash_blake2b_BYTES_MIN || size > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid size: expected between 16 and 64 bytes (inclusive)"};

    if (key && key->size() > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid key: expected less than 65 bytes"};

    crypto_generichash_blake2b(
            hash.data(),
            size,
            msg.data(),
            msg.size(),
            key ? key->data() : nullptr,
            key ? key->size() : 0);
}

}  // namespace

namespace session::hash {

void hash(
        std::span<unsigned char> hash,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key) {
    hash_impl(hash, msg, key);
}

std::vector<unsigned char> hash(
        const size_t size,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key) {
    std::vector<unsigned char> result(size);
    hash_impl(result, msg, key);
    return result;
}

}  // namespace session::hash

extern "C" {

LIBSESSION_C_API bool session_hash(
        size_t size,
        const unsigned char* msg_in,
        size_t msg_len,
        const unsigned char* key_in,
        size_t key_len,
        unsigned char* hash_out) {
    try {
        std::optional<std::span<const unsigned char>> key;

        if (key_in && key_len)
            key = {key_in, key_len};

        hash_impl({hash_out, size}, {msg_in, msg_len}, key);
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
