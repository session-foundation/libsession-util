#include <fmt/core.h>
#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <session/config/pro.hpp>
#include <session/types.hpp>

namespace session::pro {

constexpr array_uc32 BACKEND_PUBKEY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static_assert(BACKEND_PUBKEY.size() == crypto_sign_ed25519_PUBLICKEYBYTES);

struct add_payment_request {
    std::uint8_t version;
    array_uc32 master_pkey;
    array_uc32 rotating_pkey;
    array_uc32 payment_token;
    array_uc32 master_sig;
    array_uc32 rotating_sig;
    std::string to_json() const;
};

struct get_proof_request {
    std::uint8_t version;
    array_uc32 master_pkey;
    array_uc32 rotating_pkey;
    std::chrono::seconds unix_ts_s;
    array_uc32 master_sig;
    array_uc32 rotating_sig;
    std::string to_json() const;
};

struct master_rotating_sigs {
    array_uc64 master_sig;
    array_uc64 rotating_sig;
};

struct revocation_item {
    array_uc32 gen_index_hash;
    std::chrono::seconds expiry_unix_ts;
};

master_rotating_sigs build_get_proof_sigs(const array_uc64& master_privkey, const array_uc64& rotating_privkey, std::chrono::seconds unix_ts);
master_rotating_sigs build_add_payment_sigs(const array_uc64& master_privkey, const array_uc64& rotating_privkey, const array_uc32& payment_token_hash, std::chrono::seconds unix_ts);

master_rotating_sigs build_get_proof_sigs(
        const array_uc64& master_privkey, const array_uc64& rotating_privkey, std::chrono::seconds unix_ts) {
    // Derive the public keys
    array_uc32 master_pubkey;
    array_uc32 rotating_pubkey;
    crypto_sign_ed25519_sk_to_pk(master_pubkey.data(), master_privkey.data());
    crypto_sign_ed25519_sk_to_pk(rotating_pubkey.data(), rotating_privkey.data());

    // Hash components to 32 bytes
    uint8_t version = 0;
    uint64_t unix_ts_s = unix_ts.count();
    array_uc32 hash_to_sign = {};
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, /*key*/ nullptr, 0, hash_to_sign.max_size());
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(&state, master_pubkey.data(), master_pubkey.size());
    crypto_generichash_blake2b_update(&state, rotating_pubkey.data(), rotating_pubkey.size());
    crypto_generichash_blake2b_update(&state, reinterpret_cast<uint8_t *>(&unix_ts_s), sizeof(unix_ts_s));
    crypto_generichash_blake2b_final(&state, hash_to_sign.data(), hash_to_sign.size());

    // Sign the hash with both keys
    master_rotating_sigs result = {};
    crypto_sign_ed25519_detached(result.master_sig.data(), nullptr, hash_to_sign.data(), hash_to_sign.size(), master_privkey.data());
    crypto_sign_ed25519_detached(result.rotating_sig.data(), nullptr, hash_to_sign.data(), hash_to_sign.size(), rotating_privkey.data());
    return result;
}

master_rotating_sigs build_add_payment_sigs(
        const array_uc64& master_privkey,
        const array_uc64& rotating_privkey,
        const array_uc32& payment_token_hash,
        std::chrono::seconds unix_ts) {
    // Derive the public keys
    array_uc32 master_pubkey;
    array_uc32 rotating_pubkey;
    crypto_sign_ed25519_sk_to_pk(master_pubkey.data(), master_privkey.data());
    crypto_sign_ed25519_sk_to_pk(rotating_pubkey.data(), rotating_privkey.data());

    // Hash components to 32 bytes
    uint8_t version = 0;
    array_uc32 hash_to_sign = {};
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, /*key*/ nullptr, 0, hash_to_sign.max_size());
    crypto_generichash_blake2b_update(&state, &version, sizeof(version));
    crypto_generichash_blake2b_update(&state, master_pubkey.data(), master_pubkey.size());
    crypto_generichash_blake2b_update(&state, rotating_pubkey.data(), rotating_pubkey.size());
    crypto_generichash_blake2b_update(&state, payment_token_hash.data(), payment_token_hash.size());
    crypto_generichash_blake2b_final(&state, hash_to_sign.data(), hash_to_sign.size());

    // Sign the hash with both keys
    master_rotating_sigs result = {};
    crypto_sign_ed25519_detached(result.master_sig.data(), nullptr, hash_to_sign.data(), hash_to_sign.size(), master_privkey.data());
    crypto_sign_ed25519_detached(result.rotating_sig.data(), nullptr, hash_to_sign.data(), hash_to_sign.size(), rotating_privkey.data());
    return result;
}

std::string get_proof_request::to_json() const {
    // TODO: Cleanup
    std::string result = fmt::format(
            R"({{
  "version": {},
  "master_pkey": "{}",
  "rotating_pkey": "{}",
  "unix_ts_s": {},
  "master_sig": "{}",
  "rotating_sig": "{}",
}})",
            0,
            oxenc::to_hex(master_pkey),
            oxenc::to_hex(rotating_pkey),
            unix_ts_s.count(),
            oxenc::to_hex(master_sig),
            oxenc::to_hex(rotating_sig));
    return result;
}

std::string add_payment_request::to_json() const {
    // TODO: Cleanup
    std::string result = fmt::format(
            R"({{
  "version": {},
  "master_pkey": "{}",
  "rotating_pkey": "{}",
  "payment_token": "{}",
  "master_sig": "{}",
  "rotating_sig": "{}",
}})",
            0,
            oxenc::to_hex(master_pkey),
            oxenc::to_hex(rotating_pkey),
            oxenc::to_hex(payment_token),
            oxenc::to_hex(master_sig),
            oxenc::to_hex(rotating_sig));
    return result;
}
} // namespace session::pro
