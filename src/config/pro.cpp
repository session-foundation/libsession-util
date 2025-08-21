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
    // This must match the hashing routine at
    // https://github.com/Doy-lee/session-pro-backend/blob/9417e00adbff3bf608b7ae831f87045bdab06232/backend.py#L545-L558
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

bool proof_verify_signature_internal(
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

bool config_verify_signature_internal(
        std::span<const std::uint8_t> rotating_privkey,
        std::span<const std::uint8_t> verify_pubkey,
        std::uint8_t version,
        std::span<const std::uint8_t> gen_index_hash,
        std::span<const std::uint8_t> rotating_pubkey,
        std::uint64_t expiry_unix_ts,
        std::span<const std::uint8_t> sig) {

    session::array_uc32 hash =
            proof_hash_internal(version, gen_index_hash, rotating_pubkey, expiry_unix_ts);
    if (!proof_verify_signature_internal(hash, sig, verify_pubkey))
        return false;

    session::array_uc32 rederived_pk;
    [[maybe_unused]] session::cleared_uc64 rederived_sk;
    crypto_sign_ed25519_seed_keypair(
            rederived_pk.data(), rederived_sk.data(), rotating_privkey.data());

    bool result = false;
    if (rederived_pk.size() == rotating_pubkey.size())
        result = std::memcmp(rederived_pk.data(), rotating_pubkey.data(), rederived_pk.size()) == 0;

    return result;
}

bool proof_verify_message_internal(
        std::span<const uint8_t> rotating_pubkey,
        std::span<const uint8_t> sig,
        std::span<const uint8_t> msg) {
    // C++ throws on bad size, C uses a fixed sized array
    assert(rotating_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
    if (sig.size() != crypto_sign_ed25519_BYTES)
        return false;

    int verify_result = crypto_sign_ed25519_verify_detached(
            reinterpret_cast<const unsigned char*>(sig.data()),
            msg.data(),
            msg.size(),
            reinterpret_cast<const unsigned char*>(rotating_pubkey.data()));
    bool result = verify_result == 0;
    return result;
}

bool proof_is_active_internal(uint64_t expiry_unix_ts, uint64_t unix_ts_s) {
    bool result = unix_ts_s <= expiry_unix_ts;
    return result;
}
}  // namespace

namespace session::config {

static_assert(sizeof(((ProConfig*)0)->rotating_privkey) == crypto_sign_ed25519_SECRETKEYBYTES);
static_assert(sizeof(((ProProof*)0)->gen_index_hash) == 32);
static_assert(sizeof(((ProProof*)0)->rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(sizeof(((ProProof*)0)->sig) == crypto_sign_ed25519_BYTES);

bool ProProof::verify_signature(const std::span<const uint8_t>& verify_pubkey) const {
    if (verify_pubkey.size() != crypto_sign_ed25519_PUBLICKEYBYTES)
        throw std::invalid_argument{fmt::format(
                "Invalid verify_pubkey: Must be 32 byte Ed25519 public key (was: {})",
                verify_pubkey.size())};

    array_uc32 hash_to_sign = hash();
    bool result = proof_verify_signature_internal(hash_to_sign, sig, verify_pubkey);
    return result;
}

bool ProProof::verify_message(std::span<const uint8_t> sig, std::span<const uint8_t> msg) const {
    if (sig.size() != crypto_sign_ed25519_BYTES)
        throw std::invalid_argument{fmt::format(
                "Invalid signed_msg: Signature must be 64 bytes (was: {})", sig.size())};
    bool result = proof_verify_message_internal(rotating_pubkey, sig, msg);
    return result;
}

bool ProProof::is_active(std::chrono::sys_seconds unix_ts) const {
    bool result = proof_is_active_internal(
            expiry_unix_ts.time_since_epoch().count(), unix_ts.time_since_epoch().count());
    return result;
}

ProStatus ProProof::status(
        std::span<const uint8_t> verify_pubkey,
        std::chrono::sys_seconds unix_ts,
        const std::optional<ProSignedMessage>& signed_msg) {
    ProStatus result = ProStatus::Valid;
    // Verify the at the proof is verified by the Session Pro Backend key (e.g.: It was
    // issued by an authoritative backend)
    if (!verify_signature(verify_pubkey))
        result = ProStatus::InvalidProBackendSig;

    // Check if the message was signed if the user passed one in to verify against
    if (result == ProStatus::Valid && signed_msg) {
        if (!verify_message(signed_msg->sig, signed_msg->msg))
            result = ProStatus::InvalidUserSig;
    }

    // Check if the proof has expired
    if (result == ProStatus::Valid && !is_active(unix_ts))
        result = ProStatus::Expired;
    return result;
}

array_uc32 ProProof::hash() const {
    array_uc32 result = proof_hash_internal(
            version, gen_index_hash, rotating_pubkey, expiry_unix_ts.time_since_epoch().count());
    return result;
}

bool ProProof::load(const dict& root) {
    std::optional<uint8_t> version = maybe_int(root, "@");
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

bool ProConfig::verify_signature(const array_uc32& verify_pubkey) const {
    uint64_t expiry_unix_ts = proof.expiry_unix_ts.time_since_epoch().count();
    bool result = config_verify_signature_internal(
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

LIBSESSION_C_API bytes32 pro_proof_hash(pro_proof const* proof) {
    bytes32 result = {};
    if (proof) {
        session::array_uc32 hash = proof_hash_internal(
                proof->version,
                proof->gen_index_hash,
                proof->rotating_pubkey,
                proof->expiry_unix_ts);
        std::memcpy(result.data, hash.data(), hash.size());
    }
    return result;
}

LIBSESSION_C_API bool pro_proof_verify_signature(
        pro_proof const* proof, uint8_t const* verify_pubkey, size_t verify_pubkey_len) {
    if (!proof || verify_pubkey_len != crypto_sign_ed25519_PUBLICKEYBYTES)
        return false;
    auto verify_pubkey_span = std::span<const std::uint8_t>(verify_pubkey, verify_pubkey_len);
    session::array_uc32 hash = proof_hash_internal(
            proof->version, proof->gen_index_hash, proof->rotating_pubkey, proof->expiry_unix_ts);
    bool result = proof_verify_signature_internal(hash, proof->sig, verify_pubkey_span);
    return result;
}

LIBSESSION_C_API bool pro_proof_verify_message(
        pro_proof const* proof,
        uint8_t const* sig,
        size_t sig_len,
        uint8_t const* msg,
        size_t msg_len) {
    std::span<const uint8_t> sig_span = {sig, sig_len};
    std::span<const uint8_t> msg_span = {msg, msg_len};
    bool result = proof_verify_message_internal(proof->rotating_pubkey, sig_span, msg_span);
    return result;
}

LIBSESSION_C_API bool pro_proof_is_active(pro_proof const* proof, uint64_t unix_ts_s) {
    bool result = proof && proof_is_active_internal(proof->expiry_unix_ts, unix_ts_s);
    return result;
}

LIBSESSION_C_API PRO_STATUS pro_proof_status(
        pro_proof const* proof,
        const uint8_t* verify_pubkey,
        size_t verify_pubkey_len,
        uint64_t unix_ts_s,
        const pro_signed_message* signed_msg) {
    PRO_STATUS result = PRO_STATUS_VALID;
    if (!pro_proof_verify_signature(proof, verify_pubkey, verify_pubkey_len))
        result = PRO_STATUS_INVALID_PRO_BACKEND_SIG;

    // Check if the message was signed if the user passed one in to verify against
    if (result == PRO_STATUS_VALID && signed_msg) {
        if (!pro_proof_verify_message(
                    proof,
                    signed_msg->sig.data,
                    signed_msg->sig.size,
                    signed_msg->msg.data,
                    signed_msg->msg.size))
            result = PRO_STATUS_INVALID_USER_SIG;
    }

    // Check if the proof has expired
    if (result == PRO_STATUS_VALID && !pro_proof_is_active(proof, unix_ts_s))
        result = PRO_STATUS_EXPIRED;
    return result;
}

LIBSESSION_C_API bool pro_config_verify_signature(
        pro_pro_config const* pro, uint8_t const* verify_pubkey, size_t verify_pubkey_len) {
    auto verify_pubkey_span = std::span<const std::uint8_t>(verify_pubkey, verify_pubkey_len);
    bool result = config_verify_signature_internal(
            pro->rotating_privkey,
            verify_pubkey_span,
            pro->proof.version,
            pro->proof.gen_index_hash,
            pro->proof.rotating_pubkey,
            pro->proof.expiry_unix_ts,
            pro->proof.sig);
    return result;
}
