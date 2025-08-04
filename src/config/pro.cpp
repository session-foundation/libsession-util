#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>
#include <session/sodium_array.hpp>

#include "internal.hpp"

namespace session::config {

static_assert(sizeof(((Proof *)0)->rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(sizeof(((Proof *)0)->sig) == crypto_sign_ed25519_BYTES);

bool Proof::verify(const std::array<uint8_t, 32>& verify_pubkey) const
{
    std::array<uint8_t, 32> hash_to_sign = hash();
    int verify_result = crypto_sign_ed25519_verify_detached(
            sig.data(), hash_to_sign.data(), hash_to_sign.size(), verify_pubkey.data());
    bool result = verify_result == 0;
    return result;
}

std::array<uint8_t, 32> Proof::hash() const
{
    // TODO: Check why does sys_time have a time since epoch? Is it counting some other duration?
    uint64_t expiry_unix_ts_u64 = expiry_unix_ts.time_since_epoch().count();
    std::array<uint8_t, 32> result = {};
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, /*key*/ nullptr, 0, result.max_size());
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(
            &state, gen_index_hash.data(), gen_index_hash.size());
    crypto_generichash_blake2b_update(
            &state, rotating_pubkey.data(), rotating_pubkey.size());
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<uint8_t*>(&expiry_unix_ts_u64), sizeof(expiry_unix_ts_u64));
    crypto_generichash_blake2b_final(&state, result.data(), result.size());
    return result;
}

bool Proof::load(const dict& root)
{
    std::optional<uint8_t> version = maybe_int(root, "v");
    std::optional<std::vector<unsigned char>> maybe_gen_index_hash = maybe_vector(root, "g");
    std::optional<std::vector<unsigned char>> maybe_rotating_pubkey = maybe_vector(root, "r");
    std::optional<std::chrono::sys_seconds> maybe_expiry_unix_ts = maybe_ts(root, "e");
    std::optional<std::vector<unsigned char>> maybe_sig = maybe_vector(root, "s");

    if (!version)
        return false;
    if (!maybe_gen_index_hash || maybe_gen_index_hash->size() != gen_index_hash.size())
        return false;
    if (!maybe_rotating_pubkey || maybe_rotating_pubkey->size() != rotating_pubkey.max_size())
        return false;
    if (!maybe_sig || maybe_sig->size() != sig.max_size())
        return false;

    version = *version;
    std::memcpy(gen_index_hash.data(), maybe_gen_index_hash->data(), gen_index_hash.size());
    std::memcpy(rotating_pubkey.data(), maybe_rotating_pubkey->data(), rotating_pubkey.size());
    expiry_unix_ts = *maybe_expiry_unix_ts;
    std::memcpy(sig.data(), maybe_sig->data(), sig.size());

    return true;
}

bool Pro::verify(const std::array<uint8_t, 32>& verify_pubkey) const
{
    if (!proof.verify(verify_pubkey))
        return false;

    std::array<uint8_t, 32> rederived_pk;
    [[maybe_unused]] session::cleared_uc32 rederived_sk;
    crypto_sign_ed25519_seed_keypair(
            rederived_pk.data(), rederived_sk.data(), rotating_privkey.data());
    bool result = rederived_pk == proof.rotating_pubkey;
    return result;
}

bool Pro::load(const dict& root)
{
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

    if (!proof.load(*p))
        return false;

    std::memcpy(rotating_privkey.data(), maybe_rotating_privkey->data(), rotating_privkey.size());
    return true;
}

};  // namespace session::config
