#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>
#include <stdint.h>
#include <oxenc/hex.h>
#include <fmt/core.h>

#include <chrono>

namespace session::pro {

constexpr std::array<uint8_t, 32> BACKEND_PUBKEY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static_assert(BACKEND_PUBKEY.size() == crypto_sign_ed25519_PUBLICKEYBYTES);

struct proof {
    uint8_t version;
    std::array<uint8_t, 32> gen_index_hash;
    std::array<uint8_t, 32> rotating_pubkey;
    std::chrono::seconds expiry_unix_ts;
    std::array<uint8_t, 64> sig;
};
static_assert(sizeof(((proof *)0)->rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(sizeof(((proof *)0)->sig) == crypto_sign_ed25519_BYTES);

struct add_payment_request {
    uint8_t version;
    std::array<uint8_t, 32> master_pkey;
    std::array<uint8_t, 32> rotating_pkey;
    std::array<uint8_t, 32> payment_token;
    std::array<uint8_t, 32> master_sig;
    std::array<uint8_t, 32> rotating_sig;
    std::string to_json() const;
};

struct get_proof_request {
    uint8_t version;
    std::array<uint8_t, 32> master_pkey;
    std::array<uint8_t, 32> rotating_pkey;
    std::chrono::seconds unix_ts_s;
    std::array<uint8_t, 32> master_sig;
    std::array<uint8_t, 32> rotating_sig;
    std::string to_json() const;
};

struct master_rotating_sigs {
    std::array<uint8_t, 64> master_sig;
    std::array<uint8_t, 64> rotating_sig;
};

struct revocation_item {
    std::array<uint8_t, 32> gen_index_hash;
    std::chrono::seconds expiry_unix_ts;
};

bool                 verify_proof(const proof& item);
master_rotating_sigs build_get_proof_sigs(std::array<uint8_t, 64> master_privkey, std::array<uint8_t, 64> rotating_privkey, std::chrono::seconds unix_ts);
master_rotating_sigs build_add_payment_sigs(std::array<uint8_t, 64> master_privkey, std::array<uint8_t, 64> rotating_privkey, std::array<uint8_t, 32> payment_token_hash, std::chrono::seconds unix_ts);


bool verify_proof(const proof& item) {
    uint64_t expiry_unix_ts_u64 = item.expiry_unix_ts.count();
    std::array<uint8_t, 32> hash = {};
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, /*key*/ nullptr, 0, hash.max_size());
    crypto_generichash_blake2b_update(&state, &item.version, sizeof(item.version));
    crypto_generichash_blake2b_update(
            &state, item.gen_index_hash.data(), item.gen_index_hash.size());
    crypto_generichash_blake2b_update(
            &state, item.rotating_pubkey.data(), item.rotating_pubkey.size());
    crypto_generichash_blake2b_update(
            &state, reinterpret_cast<uint8_t*>(&expiry_unix_ts_u64), sizeof(expiry_unix_ts_u64));
    crypto_generichash_blake2b_final(&state, hash.data(), hash.size());

    int verify_result = crypto_sign_ed25519_verify_detached(
            item.sig.data(), hash.data(), hash.size(), BACKEND_PUBKEY.data());
    bool result = verify_result == 0;
    return result;
}

master_rotating_sigs build_get_proof_sigs(
        std::array<uint8_t, 64> master_privkey,
        std::array<uint8_t, 64> rotating_privkey,
        std::chrono::seconds unix_ts) {
    // Derive the public keys
    std::array<uint8_t, 32> master_pubkey;
    std::array<uint8_t, 32> rotating_pubkey;
    crypto_sign_ed25519_sk_to_pk(master_pubkey.data(), master_privkey.data());
    crypto_sign_ed25519_sk_to_pk(rotating_pubkey.data(), rotating_privkey.data());

    // Hash components to 32 bytes
    uint8_t version = 0;
    uint64_t unix_ts_s = unix_ts.count();
    std::array<uint8_t, 32> hash_to_sign = {};
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
        std::array<uint8_t, 64> master_privkey,
        std::array<uint8_t, 64> rotating_privkey,
        std::array<uint8_t, 32> payment_token_hash,
        std::chrono::seconds unix_ts) {
    // Derive the public keys
    std::array<uint8_t, 32> master_pubkey;
    std::array<uint8_t, 32> rotating_pubkey;
    crypto_sign_ed25519_sk_to_pk(master_pubkey.data(), master_privkey.data());
    crypto_sign_ed25519_sk_to_pk(rotating_pubkey.data(), rotating_privkey.data());

    // Hash components to 32 bytes
    uint8_t version = 0;
    std::array<uint8_t, 32> hash_to_sign = {};
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
