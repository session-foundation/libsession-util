#include <fmt/core.h>
#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <session/pro.hpp>
#include <session/types.hpp>
#include <session/session_encrypt.hpp>
#include "SessionProtos.pb.h"

namespace session::pro {

static_assert(BACKEND_PUBKEY.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
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

DecryptIncomingWithPro decrypt_incoming_with_pro_metadata(
        std::span<const unsigned char> ed25519_privkey,
        std::span<const unsigned char> ciphertext,
        std::chrono::sys_seconds unix_ts) {
    DecryptIncomingWithPro result = {};
    std::tie(result.plaintext, result.ed25519_pubkey) = session::decrypt_incoming(ed25519_privkey, ciphertext);

    SessionProtos::Content content = {};
    if (!content.ParseFromArray(result.plaintext.data(), result.plaintext.size()))
        throw std::runtime_error{"Parse decrypted message for pro metadata failed"};

    if (content.has_promessageconfig()) {
        const SessionProtos::ProMessageConfig& config = content.promessageconfig();
        if (!config.has_proof())
            throw std::runtime_error("Parse decrypted message failed, pro config missing proof");
        if (!config.has_flags())
            throw std::runtime_error("Parse decrypted message failed, pro config missing flags");

        const SessionProtos::ProProof& proto_proof = config.proof();
        std::uint32_t proto_flags = config.flags();

        if ((proto_flags & ~session::pro::FeatureFlag_All) > 0)
            throw std::runtime_error("Parse decrypted message failed, pro config specified invalid flags");

        // Parse the proof from protobufs
        session::config::ProProof& proof = result.pro_proof;
        // clang-format off
        size_t proof_errors = 0;
        proof_errors += !proto_proof.has_version()           || proto_proof.version() != static_cast<std::uint32_t>(session::config::ProProofVersion_v0);
        proof_errors += !proto_proof.has_genindexhash()      || proto_proof.genindexhash().size() != proof.gen_index_hash.max_size();
        proof_errors += !proto_proof.has_rotatingpublickey() || proto_proof.rotatingpublickey().size() != proof.rotating_pubkey.max_size();
        proof_errors += !proto_proof.has_expiryunixts();
        proof_errors += !proto_proof.has_sig()               || proto_proof.sig().size() != proof.sig.max_size();
        // clang-format on

        if (proof_errors == 0)
            throw std::runtime_error("Parse decrypted message failed, pro metadata was malformed");

        // Fill out result, we have parsed successfully
        result.pro_flags = proto_flags;

        std::memcpy(
                proof.gen_index_hash.data(),
                proto_proof.genindexhash().data(),
                proto_proof.genindexhash().size());
        std::memcpy(
                proof.rotating_pubkey.data(),
                proto_proof.rotatingpublickey().data(),
                proto_proof.rotatingpublickey().size());
        proof.expiry_unix_ts =
                std::chrono::sys_seconds(std::chrono::seconds(proto_proof.expiryunixts()));
        std::memcpy(proof.sig.data(), proto_proof.sig().data(), proto_proof.sig().size());

        if (proof.verify(session::pro::BACKEND_PUBKEY))
            result.pro_status = Status::Valid;

        if (result.pro_status == Status::Valid) {
            if (unix_ts >= result.pro_proof.expiry_unix_ts)
                result.pro_status = Status::Expired;
        }
    }
    return result;
}

} // namespace session::pro
