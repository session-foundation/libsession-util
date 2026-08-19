#include "session/hash.hpp"

#include <sodium/crypto_generichash_blake2b.h>

#include "session/export.h"
#include "session/hash.h"
#include "session/util.hpp"

namespace {

using namespace session;

void hash_impl(
        std::span<std::byte> hash,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key) {
    const auto size = hash.size();
    if (size < crypto_generichash_blake2b_BYTES_MIN || size > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid size: expected between 16 and 64 bytes (inclusive)"};

    if (key && key->size() > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid key: expected less than 65 bytes"};

    crypto_generichash_blake2b(
            to_unsigned(hash.data()),
            size,
            to_unsigned(msg.data()),
            msg.size(),
            key ? to_unsigned(key->data()) : nullptr,
            key ? key->size() : 0);
}

}  // namespace

namespace session::hash {

void hash(
        std::span<std::byte> hash,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key) {
    hash_impl(hash, msg, key);
}

std::vector<std::byte> hash(
        const size_t size,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key) {
    std::vector<std::byte> result(size);
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
        std::optional<std::span<const std::byte>> key;

        if (key_in && key_len)
            key = std::span{reinterpret_cast<const std::byte*>(key_in), key_len};

        hash_impl(
                std::span{reinterpret_cast<std::byte*>(hash_out), size},
                std::span{reinterpret_cast<const std::byte*>(msg_in), msg_len},
                key);
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
