#include <session/config/pro.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>

#include "internal.hpp"

namespace {
session::array_uc32 proof_hash_internal(
        std::uint8_t version,
        std::span<const std::uint8_t> gen_index_hash,
        std::span<const std::uint8_t> rotating_pubkey,
        std::uint64_t expiry_unix_ts) {
    session::array_uc32 result = {};
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, /*key*/ nullptr, 0, result.max_size());
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(&state, gen_index_hash.data(), gen_index_hash.size());
    crypto_generichash_blake2b_update(&state, rotating_pubkey.data(), rotating_pubkey.size());
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<uint8_t*>(&expiry_unix_ts), sizeof(expiry_unix_ts));
    crypto_generichash_blake2b_final(&state, result.data(), result.size());
    return result;
}

bool proof_verify_internal(
        std::span<const std::uint8_t> hash,
        std::span<const std::uint8_t> sig,
        std::span<const std::uint8_t> verify_pubkey) {
    // The C/C++ interface verifies that the payloads are the correct size using the type system so
    // only need asserts here.
    assert(hash.size() == 32);
    assert(sig.size() == crypto_sign_ed25519_BYTES);
    assert(verify_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
    int verify_result = crypto_sign_ed25519_verify_detached(
            sig.data(), hash.data(), hash.size(), verify_pubkey.data());
    bool result = verify_result == 0;
    return result;
}

bool pro_verify_internal(
        std::span<const std::uint8_t> rotating_privkey,
        std::span<const std::uint8_t> verify_pubkey,
        std::uint8_t version,
        std::span<const std::uint8_t> gen_index_hash,
        std::span<const std::uint8_t> rotating_pubkey,
        std::uint64_t expiry_unix_ts,
        std::span<const std::uint8_t> sig) {

    session::array_uc32 hash =
            proof_hash_internal(version, gen_index_hash, rotating_pubkey, expiry_unix_ts);
    if (!proof_verify_internal(hash, sig, verify_pubkey))
        return false;

    session::array_uc32 rederived_pk;
    [[maybe_unused]] session::cleared_uc32 rederived_sk;
    crypto_sign_ed25519_seed_keypair(
            rederived_pk.data(), rederived_sk.data(), rotating_privkey.data());

    bool result = false;
    if (rederived_pk.size() == rotating_pubkey.size())
        result = std::memcmp(rederived_pk.data(), rotating_pubkey.data(), rederived_pk.size()) == 0;

    return result;
}

}  // namespace

namespace session::config {

static_assert(sizeof(((ProConfig*)0)->rotating_privkey) == crypto_sign_ed25519_SECRETKEYBYTES);
static_assert(sizeof(((ProProof*)0)->gen_index_hash) == 32);
static_assert(sizeof(((ProProof*)0)->rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(sizeof(((ProProof*)0)->sig) == crypto_sign_ed25519_BYTES);

bool ProProof::verify(const array_uc32& verify_pubkey) const {
    array_uc32 hash_to_sign = hash();
    bool result = proof_verify_internal(hash_to_sign, sig, verify_pubkey);
    return result;
}

array_uc32 ProProof::hash() const {
    array_uc32 result = proof_hash_internal(
            version, gen_index_hash, rotating_pubkey, expiry_unix_ts.time_since_epoch().count());
    return result;
}

bool ProProof::load(const dict& root) {
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

bool ProConfig::verify(const array_uc32& verify_pubkey) const {
    uint64_t expiry_unix_ts = proof.expiry_unix_ts.time_since_epoch().count();
    bool result = pro_verify_internal(
            rotating_privkey,
            verify_pubkey,
            proof.version,
            proof.gen_index_hash,
            proof.rotating_pubkey,
            expiry_unix_ts,
            proof.sig);
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

    if (!proof.load(*p))
        return false;

    std::memcpy(rotating_privkey.data(), maybe_rotating_privkey->data(), rotating_privkey.size());
    return true;
}

};  // namespace session::config

// Ensure these are byte buffers and we can just use sizeof to build std::spans to interop with C++
static_assert((sizeof((pro_pro_config*)0)->rotating_privkey) == crypto_sign_ed25519_SECRETKEYBYTES);
static_assert((sizeof((pro_proof*)0)->gen_index_hash) == 32);
static_assert((sizeof((pro_proof*)0)->rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert((sizeof((pro_proof*)0)->sig) == crypto_sign_ed25519_BYTES);

LIBSESSION_C_API bool pro_proof_verify(pro_proof const* proof, uint8_t const* verify_pubkey) {
    auto verify_pubkey_span =
            std::span<const std::uint8_t>(verify_pubkey, crypto_sign_ed25519_PUBLICKEYBYTES);
    auto gen_index_hash =
            std::span<const std::uint8_t>(proof->gen_index_hash, sizeof proof->gen_index_hash);
    auto rotating_pubkey =
            std::span<const std::uint8_t>(proof->rotating_pubkey, sizeof proof->rotating_pubkey);
    auto sig = std::span<const std::uint8_t>(proof->sig, sizeof proof->sig);

    session::array_uc32 hash = proof_hash_internal(
            proof->version, gen_index_hash, rotating_pubkey, proof->expiry_unix_ts);
    bool result = proof_verify_internal(hash, sig, verify_pubkey_span);
    return result;
}

LIBSESSION_C_API bool pro_pro_verify(pro_pro_config const* pro, uint8_t const* verify_pubkey) {
    auto verify_pubkey_span =
            std::span<const std::uint8_t>(verify_pubkey, crypto_sign_ed25519_PUBLICKEYBYTES);
    auto rotating_privkey =
            std::span<const std::uint8_t>(pro->rotating_privkey, sizeof pro->rotating_privkey);
    auto gen_index_hash = std::span<const std::uint8_t>(
            pro->proof.gen_index_hash, sizeof pro->proof.gen_index_hash);
    auto rotating_pubkey = std::span<const std::uint8_t>(
            pro->proof.rotating_pubkey, sizeof pro->proof.rotating_pubkey);
    auto sig = std::span<const std::uint8_t>(pro->proof.sig, sizeof pro->proof.sig);

    bool result = pro_verify_internal(
            rotating_privkey,
            verify_pubkey_span,
            pro->proof.version,
            gen_index_hash,
            rotating_pubkey,
            pro->proof.expiry_unix_ts,
            sig);
    return result;
}
