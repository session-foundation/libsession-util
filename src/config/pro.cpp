#include <session/config/pro.h>
#include <session/pro_backend.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>
#include <session/sodium_array.hpp>

#include "internal.hpp"

namespace session::config {

bool ProConfig::load(const dict& root) {
    // Get proof fields from session pro data sitting in the 'p' (proof) dictionary
    auto p_it = root.find("p");
    if (p_it == root.end())
        return false;

    // Lookup and get 'p'
    const config::dict* p = std::get_if<config::dict>(&p_it->second);
    if (!p)
        return false;

    std::optional<std::vector<unsigned char>> maybe_rotating_seed = maybe_vector(root, "r");
    if (!maybe_rotating_seed || maybe_rotating_seed->size() != crypto_sign_ed25519_SEEDBYTES)
        return false;

    // NOTE: Load into the proof object
    {
        std::optional<uint8_t> version = maybe_int(*p, "@");
        std::optional<std::vector<unsigned char>> maybe_gen_index_hash = maybe_vector(*p, "g");
        std::optional<std::chrono::sys_time<std::chrono::milliseconds>> maybe_expiry_unix_ts_ms =
                maybe_ts_ms(*p, "e");
        std::optional<std::vector<unsigned char>> maybe_sig = maybe_vector(*p, "s");

        if (!version)
            return false;
        if (!maybe_gen_index_hash || maybe_gen_index_hash->size() != proof.gen_index_hash.size())
            return false;
        if (!maybe_sig || maybe_sig->size() != proof.sig.max_size())
            return false;
        if (!maybe_expiry_unix_ts_ms)
            return false;

        proof.version = *version;
        std::memcpy(
                proof.gen_index_hash.data(),
                maybe_gen_index_hash->data(),
                proof.gen_index_hash.size());
        proof.expiry_unix_ts = *maybe_expiry_unix_ts_ms;
        std::memcpy(proof.sig.data(), maybe_sig->data(), proof.sig.size());
    }

    // Derive the rotating public key from the seed and populate the proof's pubkey and the outer
    // private key
    crypto_sign_ed25519_seed_keypair(
            proof.rotating_pubkey.data(), rotating_privkey.data(), maybe_rotating_seed->data());
    return true;
}

};  // namespace session::config
