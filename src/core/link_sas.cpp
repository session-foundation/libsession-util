#include <oxenc/endian.h>
#include <sodium/crypto_pwhash.h>

#include <session/core/link_sas.hpp>
#include <session/hash.hpp>
#include <stdexcept>

using namespace session::literals;

namespace session::core {

std::array<std::string_view, 21> link_request_sas(std::span<const std::byte> plaintext) {
    std::array<unsigned char, 16> salt;
    hash::blake2b_pers(salt, "SessionLinkEmoji"_b2b_pers, plaintext);

    std::array<unsigned char, 16> seed;
    if (0 != crypto_pwhash(
                     seed.data(),
                     seed.size(),
                     reinterpret_cast<const char*>(plaintext.data()),
                     plaintext.size(),
                     salt.data(),
                     /*opslimit=*/2,
                     /*memlimit=*/16ULL * 1024 * 1024,
                     crypto_pwhash_ALG_ARGON2ID13))
        throw std::runtime_error{"link_request_sas: Argon2id key derivation failed"};

    // Interpret the 16-byte seed as a 128-bit little-endian integer split into two 64-bit words.
    uint64_t lo = oxenc::load_little_to_host<uint64_t>(seed.data());
    uint64_t hi = oxenc::load_little_to_host<uint64_t>(seed.data() + 8);

    std::array<std::string_view, 21> result;
    for (int k = 0; k < 21; k++) {
        int bit = k * 6;
        uint8_t index;
        if (bit + 6 <= 64)
            index = (lo >> bit) & 0x3F;
        else if (bit >= 64)
            index = (hi >> (bit - 64)) & 0x3F;
        else
            // Single crossing point: k=10, bit=60.
            // Low 4 bits come from lo (bits 60-63), high 2 bits come from hi (bits 64-65).
            index = ((lo >> 60) | (hi << 4)) & 0x3F;
        result[k] = SAS_EMOJI[index];
    }
    return result;
}

}  // namespace session::core
