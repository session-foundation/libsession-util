#include <session/config/pro.h>
#include <session/pro_backend.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>
#include <session/sodium_array.hpp>

#include "internal.hpp"

namespace session::config {
static_assert(sizeof(((ProConfig*)0)->rotating_privkey) == crypto_sign_ed25519_SECRETKEYBYTES);
bool ProConfig::verify_signature(const array_uc32& verify_pubkey) const {
    uint64_t expiry_unix_ts = proof.expiry_unix_ts.time_since_epoch().count();
    if (!proof.verify_signature(verify_pubkey))
        return false;

    session::array_uc32 rederived_pk;
    [[maybe_unused]] session::cleared_uc64 rederived_sk;
    crypto_sign_ed25519_seed_keypair(
            rederived_pk.data(), rederived_sk.data(), rotating_privkey.data());

    bool result = false;
    if (rederived_pk.size() == proof.rotating_pubkey.size())
        result = std::memcmp(
                         rederived_pk.data(), proof.rotating_pubkey.data(), rederived_pk.size()) ==
                 0;
    return result;
}

bool ProConfig::load(const dict& root) {
    // Get proof fields sitting in 'p' dictionary
    auto p_it = root.find("p");
    if (p_it == root.end())
        return false;

    // Lookup and get 'p'
    const config::dict* p = std::get_if<config::dict>(&p_it->second);
    if (!p)
        return false;

    std::optional<std::vector<unsigned char>> maybe_rotating_privkey = maybe_vector(root, "r");
    if (!maybe_rotating_privkey || maybe_rotating_privkey->size() != rotating_privkey.max_size())
        return false;

    // NOTE: Load into the proof object
    {
        std::optional<uint8_t> version = maybe_int(*p, "@");
        std::optional<std::vector<unsigned char>> maybe_gen_index_hash = maybe_vector(*p, "g");
        std::optional<std::vector<unsigned char>> maybe_rotating_pubkey = maybe_vector(*p, "r");
        std::optional<std::chrono::sys_seconds> maybe_expiry_unix_ts = maybe_ts(*p, "e");
        std::optional<std::vector<unsigned char>> maybe_sig = maybe_vector(*p, "s");

        if (!version)
            return false;
        if (!maybe_gen_index_hash || maybe_gen_index_hash->size() != proof.gen_index_hash.size())
            return false;
        if (!maybe_rotating_pubkey ||
            maybe_rotating_pubkey->size() != proof.rotating_pubkey.max_size())
            return false;
        if (!maybe_sig || maybe_sig->size() != proof.sig.max_size())
            return false;

        version = *version;
        std::memcpy(
                proof.gen_index_hash.data(),
                maybe_gen_index_hash->data(),
                proof.gen_index_hash.size());
        std::memcpy(
                proof.rotating_pubkey.data(),
                maybe_rotating_pubkey->data(),
                proof.rotating_pubkey.size());
        proof.expiry_unix_ts = *maybe_expiry_unix_ts;
        std::memcpy(proof.sig.data(), maybe_sig->data(), proof.sig.size());
    }

    std::memcpy(rotating_privkey.data(), maybe_rotating_privkey->data(), rotating_privkey.size());
    return true;
}

};  // namespace session::config

// Ensure these are byte buffers and we can just use sizeof to build std::spans to interop with C++
static_assert((sizeof((pro_pro_config*)0)->rotating_privkey) == crypto_sign_ed25519_SECRETKEYBYTES);

LIBSESSION_C_API bool pro_config_verify_signature(
        pro_pro_config const* pro, uint8_t const* verify_pubkey, size_t verify_pubkey_len) {
    if (verify_pubkey_len != crypto_sign_ed25519_PUBLICKEYBYTES)
        return false;

    session::config::ProConfig config = {};
    std::memcpy(
            config.rotating_privkey.data(), pro->rotating_privkey.data, sizeof pro->rotating_privkey.data);
    config.proof.version = pro->proof.version;
    std::memcpy(
            config.proof.gen_index_hash.data(),
            pro->proof.gen_index_hash.data,
            sizeof pro->proof.gen_index_hash.data);
    std::memcpy(
            config.proof.rotating_pubkey.data(),
            pro->proof.rotating_pubkey.data,
            sizeof pro->proof.rotating_pubkey.data);
    config.proof.expiry_unix_ts =
            std::chrono::sys_seconds(std::chrono::seconds(pro->proof.expiry_unix_ts_s));
    std::memcpy(config.proof.sig.data(), pro->proof.sig.data, sizeof pro->proof.sig.data);

    session::array_uc32 verify_pubkey_cpp;
    std::memcpy(verify_pubkey_cpp.data(), verify_pubkey, verify_pubkey_len);
    bool result = config.verify_signature(verify_pubkey_cpp);
    return result;
}
