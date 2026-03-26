#include "session/session_encrypt.hpp"

#include <mlkem_native.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <session/session_encrypt.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>
#include <zstd.h>

#include <array>
#include <cassert>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "session/blinding.hpp"
#include "session/clock.hpp"
#include "session/hash.hpp"
#include "session/random.hpp"
#include "session/sodium_array.hpp"
#include "session/types.hpp"

using namespace std::literals;
using namespace session::literals;

namespace session {

namespace detail {
    // detail::to_hashable takes either an integral type, system_clock::time_point, or a string
    // type and converts it to a string_view by writing an integer value (using std::to_chars)
    // into the buffer space (which should be at least 20 bytes), and returning a string_view
    // into the written buffer space.  For strings/string_views the string_view is returned
    // directly from the argument. system_clock::time_points are converted into integral
    // milliseconds since epoch then treated as an integer value.
    template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    std::string_view to_hashable(const T& val, char*& buffer) {
        std::ostringstream ss;
        ss << val;

        std::string str = ss.str();
        std::copy(str.begin(), str.end(), buffer);
        std::string_view s(buffer, str.length());
        buffer += str.length();
        return s;
    }
    inline std::string_view to_hashable(
            const std::chrono::system_clock::time_point& val, char*& buffer) {
        return to_hashable(epoch_ms(val), buffer);
    }
    template <typename T, std::enable_if_t<std::is_convertible_v<T, std::string_view>, int> = 0>
    std::string_view to_hashable(const T& value, char*&) {
        return value;
    }

}  // namespace detail

// Version tag we prepend to encrypted-for-blinded-user messages.  This is here so we can detect if
// some future version changes the format (and if not even try to load it).
inline constexpr unsigned char BLINDED_ENCRYPT_VERSION = 0;

// Constants for v2 PFS+PQ message encryption/decryption

// BLAKE2b personalization for the key indicator shared secret (KISS): a 2-byte hash that lets the
// recipient cheaply identify which of their account keys was used without revealing it externally.
constexpr auto V2_KISS_PERS = "Session-Msg-KISS"_b2b_pers;

// BLAKE2b personalization for the inner-message signature hash.
constexpr auto V2_MSG_SIG_PERS = "SessionV2Message"_b2b_pers;

// X-Wing KDF domain separator from draft-connolly-cfrg-xwing-kem: the 6 ASCII bytes '\.//^\'.
// SHA3-256(ssₘ || ssₓ || E || X || V2_XWING_LABEL) produces the combined X-Wing shared secret.
constexpr auto V2_XWING_LABEL =  //
        R"(\./)"
        R"(/^\)"_uc;

// SHAKE256 domain prefix for deriving the XChaCha20+Poly1305 key and nonce from the X-Wing SS.
constexpr auto V2_SS_DOMAIN = "SessionV2MessageSS"_uc;

// Shared v2 wire-format layout constants (used in both encrypt and decrypt)
static constexpr size_t V2_AEAD_OVERHEAD = crypto_aead_xchacha20poly1305_ietf_ABYTES;
static constexpr size_t V2_NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t V2_HEADER_SIZE = 2 + 2 + 32 + MLKEM768_CIPHERTEXTBYTES;
static constexpr size_t V2_OUTER_OVERHEAD = V2_HEADER_SIZE + V2_AEAD_OVERHEAD;
static constexpr size_t V2_MIN_FINAL_SIZE = ((V2_OUTER_OVERHEAD + 256 + 255) / 256) * 256;

// Validates the v2 ciphertext prefix and minimum size; throws std::runtime_error on failure.
static void v2_check_header(std::span<const unsigned char> ciphertext) {
    if (ciphertext.size() < V2_MIN_FINAL_SIZE)
        throw std::runtime_error{"v2 ciphertext is too short"};
    if (ciphertext[0] != 0x00 || ciphertext[1] != 0x02)
        throw std::runtime_error{"v2 ciphertext has wrong version prefix"};
}

// X-Wing KDF: computes ss = SHA3-256(ssm||ssx||E||X||V2_XWING_LABEL) from key_buf (=ssm) and
// nonce_buf (=ssx), then squeezes k (32B) back into key_buf and n (V2_NONCE_SIZE B) into the
// first V2_NONCE_SIZE bytes of nonce_buf, overwriting the shared secrets with derived key material.
// E is the ephemeral X25519 pubkey; X is the account PFS X25519 pubkey.
static void v2_derive_xwing_key_nonce(
        cleared_uc32& key_buf,
        cleared_uc32& nonce_buf,
        std::span<const unsigned char, 32> E,
        std::span<const unsigned char, 32> X) {
    std::array<unsigned char, 32> ss;
    hash::sha3_256(ss, key_buf, nonce_buf, E, X, V2_XWING_LABEL);
    hash::shake256(V2_SS_DOMAIN, ss)(
            key_buf, std::span<unsigned char, V2_NONCE_SIZE>{nonce_buf.data(), V2_NONCE_SIZE});
    sodium_memzero(ss.data(), ss.size());
}

// Computes the 2-byte Key Indicator Shared Secret (KISS):
//   KISS = BLAKE2b_2(E || S, key=DH(sec, pub_for_dh), pers="Session-Msg-KISS")
// On encrypt: sender holds ephemeral secret e, DH partner is long-term S → call with
// encrypting=true On decrypt: recipient holds long-term secret s, DH partner is ephemeral E → call
// with encrypting=false
static std::array<unsigned char, 2> v2_kiss(
        std::span<const unsigned char, 32> sec,
        std::span<const unsigned char, 32> E,
        std::span<const unsigned char, 32> S,
        bool encrypting) {
    cleared_uc32 dh;
    if (0 != crypto_scalarmult(dh.data(), sec.data(), encrypting ? S.data() : E.data()))
        throw std::runtime_error{"X25519 DH (KISS) failed"};
    std::array<unsigned char, 2> kiss;
    hash::blake2b_key_pers(kiss, dh, V2_KISS_PERS, E, S);
    return kiss;
}

std::vector<unsigned char> sign_for_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char> recipient_pubkey,
        std::span<const unsigned char> message) {
    // If prefixed, drop it (and do this for the caller, too) so that everything after this
    // doesn't need to worry about whether it is prefixed or not.
    if (recipient_pubkey.size() == 33 && recipient_pubkey.front() == 0x05)
        recipient_pubkey = recipient_pubkey.subspan(1);
    else if (recipient_pubkey.size() != 32)
        throw std::invalid_argument{
                "Invalid recipient_pubkey: expected 32 bytes (33 with 05 prefix)"};

    std::vector<unsigned char> buf;
    buf.reserve(message.size() + 96);  // 32+32 now, but 32+64 when we reuse it for the sealed box
    buf.insert(buf.end(), message.begin(), message.end());
    buf.insert(
            buf.end(),
            ed25519_privkey.begin() + 32,
            ed25519_privkey.end());  // [32:] of a libsodium full seed value is the *pubkey*
    buf.insert(buf.end(), recipient_pubkey.begin(), recipient_pubkey.end());

    uc64 sig;
    if (0 != crypto_sign_ed25519_detached(
                     sig.data(), nullptr, buf.data(), buf.size(), ed25519_privkey.data()))
        throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};

    // We have M||A||Y for the sig, but now we want M||A||SIG so drop Y then append SIG:
    buf.resize(buf.size() - 32);
    buf.insert(buf.end(), sig.begin(), sig.end());

    return buf;
}

static constexpr auto BOX_HASHKEY = "SessionBoxEphemeralHashKey"_uc;

std::vector<unsigned char> encrypt_for_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char> recipient_pubkey,
        std::span<const unsigned char> message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey =
                recipient_pubkey.subspan(1);  // sign_for_recipient already checked that this is the
                                              // proper 0x05 prefix when present.

    std::vector<unsigned char> result;
    result.resize(signed_msg.size() + crypto_box_SEALBYTES);
    if (0 != crypto_box_seal(
                     result.data(), signed_msg.data(), signed_msg.size(), recipient_pubkey.data()))
        throw std::runtime_error{"Sealed box encryption failed"};

    return result;
}

std::vector<unsigned char> encrypt_for_recipient_deterministic(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char> recipient_pubkey,
        std::span<const unsigned char> message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey = recipient_pubkey.subspan(1);  // sign_for_recipient already checked that
                                                         // this is the proper 0x05 when present.

    // To make our ephemeral seed we're going to hash: SENDER_SEED || RECIPIENT_PK || MESSAGE with a
    // keyed blake2b hash.
    cleared_uchars<crypto_box_SEEDBYTES> seed;
    hash::blake2b_key(
            seed, BOX_HASHKEY, ed25519_privkey.seed(), recipient_pubkey.first(32), message);

    cleared_uchars<crypto_box_SECRETKEYBYTES> eph_sk;
    cleared_uchars<crypto_box_PUBLICKEYBYTES> eph_pk;

    crypto_box_seed_keypair(eph_pk.data(), eph_sk.data(), seed.data());

    // The nonce for a sealed box is not passed but is implicitly defined as the (unkeyed) blake2b
    // hash of:
    //     EPH_PUBKEY || RECIPIENT_PUBKEY
    cleared_uchars<crypto_box_NONCEBYTES> nonce;
    hash::blake2b(nonce, eph_pk, recipient_pubkey);

    // A sealed box is a regular box (using the ephermal keys and nonce), but with the ephemeral
    // pubkey prepended:
    static_assert(crypto_box_SEALBYTES == crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);

    std::vector<unsigned char> result;
    result.resize(crypto_box_SEALBYTES + signed_msg.size());
    std::memcpy(result.data(), eph_pk.data(), crypto_box_PUBLICKEYBYTES);
    if (0 != crypto_box_easy(
                     result.data() + crypto_box_PUBLICKEYBYTES,
                     signed_msg.data(),
                     signed_msg.size(),
                     nonce.data(),
                     recipient_pubkey.data(),
                     eph_sk.data()))
        throw std::runtime_error{"Crypto box encryption failed"};

    return result;
}

std::vector<unsigned char> encrypt_for_recipient_v2(
        const Ed25519PrivKeySpan& sender_ed25519_privkey,
        std::span<const unsigned char, 33> recipient_session_id,
        std::span<const unsigned char, 32> recipient_account_x25519,
        std::span<const unsigned char, 1184> recipient_account_mlkem768,
        std::span<const unsigned char> content,
        std::optional<std::span<const unsigned char, 64>> pro_signature) {

    auto sender_ed_pk = sender_ed25519_privkey.pubkey();

    // S = long-term X25519 pubkey of the recipient (session ID without the 0x05 prefix)
    std::span<const unsigned char, 32> S{recipient_session_id.data() + 1, 32};

    // Step 1: Generate ephemeral X25519 keypair e/E
    cleared_uc32 e;
    uc32 E;
    crypto_box_keypair(E.data(), e.data());

    // Two multi-purpose key buffers — each plays sequential, non-overlapping roles:
    //
    // enc_key_buf: ML-KEM shared secret ssm (step 4) → SHAKE256-derived enc key k (step 8)
    // enc_nonce_buf: eS DH result (step 2) → ML-KEM coins (step 4) → ssx DH result (step 5)
    //             → SHAKE256-derived enc nonce n in first 24 bytes (step 8)
    cleared_uc32 enc_key_buf;
    cleared_uc32 enc_nonce_buf;

    // Step 2: KISS = BLAKE2b_2(E || S, key=eS, pers="Session-Msg-KISS")
    // eS is the X25519 DH with the long-term key, used only for cheap key indicator obfuscation
    auto kiss = v2_kiss(e, E, S, /*encrypting=*/true);

    // Step 3: ki = M[0:2] ⊕ kiss  (encrypted key indicator; lets recipient quickly identify key)
    std::array<unsigned char, 2> ki{
            static_cast<unsigned char>(recipient_account_mlkem768[0] ^ kiss[0]),
            static_cast<unsigned char>(recipient_account_mlkem768[1] ^ kiss[1])};

    // Step 4: ML-KEM-768 encapsulate: ssₘ, mlkem_ct = Encapsulate(M)
    std::array<unsigned char, MLKEM768_CIPHERTEXTBYTES> mlkem_ct;
    random::fill(enc_nonce_buf);  // repurpose enc_nonce_buf as random ML-KEM coins
    if (0 != sr_mlkem768_enc_derand(
                     mlkem_ct.data(),
                     enc_key_buf.data(),
                     recipient_account_mlkem768.data(),
                     enc_nonce_buf.data()))
        throw std::runtime_error{"ML-KEM-768 encapsulation failed"};

    // Step 5: ssx = eX  (X25519 DH with account PFS key X, not long-term key S)
    if (0 != crypto_scalarmult(enc_nonce_buf.data(), e.data(), recipient_account_x25519.data()))
        throw std::runtime_error{"X25519 DH (account key) failed"};

    // Step 6: X-Wing KDF → enc key k (in enc_key_buf) and enc nonce n (in enc_nonce_buf[0:24])
    v2_derive_xwing_key_nonce(enc_key_buf, enc_nonce_buf, E, recipient_account_x25519);

    // Step 7: Build inner bt-encoded dict directly into the final result buffer.
    //
    // bt_bytes_encoded(n): total bytes to represent an n-byte bt string: decimal digits of n + 1 +
    // n
    constexpr auto bt_bytes_encoded = [](size_t n) constexpr -> size_t {
        size_t sz = 1 + n;  // ':' + n data bytes
        do {
            ++sz;
        } while (n /= 10);  // decimal digits of n
        return sz;
    };
    // Keys must be in ascending lexicographic order: "S" < "c" < "~" < "~P"
    constexpr size_t S_KEY_VAL = 3 + bt_bytes_encoded(32);    // "1:S" + "32:<sender ed pubkey>"
    constexpr size_t SIG_KEY_VAL = 3 + bt_bytes_encoded(64);  // "1:~" + "64:<signature>"
    constexpr size_t PRO_KEY_VAL = 4 + bt_bytes_encoded(64);  // "2:~P" + "64:<pro signature>"
    size_t inner_dict_size = 2                                // d...e dict delimiters
                           + S_KEY_VAL + 3 +
                             bt_bytes_encoded(content.size())  // "1:c" + "<content>"
                           + SIG_KEY_VAL + (pro_signature ? PRO_KEY_VAL : 0);

    // Total message must be a multiple of 256 bytes and at least V2_MIN_FINAL_SIZE bytes.
    size_t final_size =
            (std::max(V2_MIN_FINAL_SIZE, V2_OUTER_OVERHEAD + inner_dict_size) + 255) & ~size_t{255};
    size_t padded_inner_size = final_size - V2_OUTER_OVERHEAD;

    // Step 8: Allocate result (zero-initialized so padding bytes are already 0), write header,
    // build inner dict directly into result buffer, then encrypt in-place.
    // (c == m is explicitly supported by libsodium for AEAD functions)
    std::vector<unsigned char> result(final_size, 0);

    result[0] = 0x00;
    result[1] = 0x02;
    result[2] = ki[0];
    result[3] = ki[1];
    std::memcpy(result.data() + 4, E.data(), 32);
    std::memcpy(result.data() + 36, mlkem_ct.data(), MLKEM768_CIPHERTEXTBYTES);

    {
        oxenc::bt_dict_producer dict{
                reinterpret_cast<char*>(result.data() + V2_HEADER_SIZE), inner_dict_size};
        dict.append("S", sender_ed_pk);
        dict.append("c", content);
        // "~" signs BLAKE2b-64(body-so-far, key=recipient_session_id_33B, pers="SessionV2Message")
        dict.append_signature("~", [&](std::span<const unsigned char> body) {
            cleared_uc64 h;
            hash::blake2b_key_pers(h, recipient_session_id, V2_MSG_SIG_PERS, body);
            uc64 sig;
            if (0 !=
                crypto_sign_ed25519_detached(
                        sig.data(), nullptr, h.data(), h.size(), sender_ed25519_privkey.data()))
                throw std::runtime_error{"Failed to sign v2 message"};
            return sig;
        });
        if (pro_signature)
            dict.append("~P", *pro_signature);
        assert(dict.view().size() == inner_dict_size);
    }

    if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
                     result.data() + V2_HEADER_SIZE,  // c (output, in-place)
                     nullptr,
                     result.data() + V2_HEADER_SIZE,  // m (input, same buffer)
                     padded_inner_size,
                     nullptr,
                     0,
                     nullptr,
                     enc_nonce_buf.data(),  // nonce (24B read from 32B buffer)
                     enc_key_buf.data()))   // key
        throw std::runtime_error{"v2 message encryption failed"};

    return result;
}

std::array<unsigned char, 2> decrypt_incoming_v2_prefix(
        std::span<const unsigned char, 32> x25519_sec,
        std::span<const unsigned char, 32> x25519_pub,
        std::span<const unsigned char> ciphertext) {
    v2_check_header(ciphertext);
    auto E = ciphertext.subspan<4, 32>();
    auto kiss = v2_kiss(x25519_sec, E, x25519_pub, /*encrypting=*/false);
    return {static_cast<unsigned char>(ciphertext[2] ^ kiss[0]),
            static_cast<unsigned char>(ciphertext[3] ^ kiss[1])};
}

DecryptV2Result decrypt_incoming_v2(
        std::span<const unsigned char, 33> recipient_session_id,
        std::span<const unsigned char, 32> account_pfs_x25519_sec,
        std::span<const unsigned char, 32> account_pfs_x25519_pub,
        std::span<const unsigned char, 2400> account_pfs_mlkem768_sec,
        std::span<const unsigned char> ciphertext) {
    v2_check_header(ciphertext);

    auto E = ciphertext.subspan<4, 32>();
    auto mlkem_ct = ciphertext.subspan<36, MLKEM768_CIPHERTEXTBYTES>();

    cleared_uc32 key_buf;    // ssm → k
    cleared_uc32 nonce_buf;  // ssx → n

    // Step 1: ML-KEM-768 decapsulate → shared secret ssm in key_buf
    if (0 != sr_mlkem768_dec(key_buf.data(), mlkem_ct.data(), account_pfs_mlkem768_sec.data()))
        throw DecryptV2Error{"ML-KEM-768 decapsulation failed"};

    // Step 2: X25519 DH with account PFS key → shared secret ssx in nonce_buf
    if (0 != crypto_scalarmult(nonce_buf.data(), account_pfs_x25519_sec.data(), E.data()))
        throw DecryptV2Error{"X25519 DH (account key) failed"};

    // Step 3: X-Wing KDF → enc key k (in key_buf) and enc nonce n (in nonce_buf[0:24])
    v2_derive_xwing_key_nonce(key_buf, nonce_buf, E, account_pfs_x25519_pub);

    // Step 4: AEAD decrypt the inner payload
    size_t enc_size = ciphertext.size() - V2_HEADER_SIZE;
    std::vector<unsigned char> plain(enc_size - V2_AEAD_OVERHEAD);
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     plain.data(),
                     nullptr,
                     nullptr,
                     ciphertext.data() + V2_HEADER_SIZE,
                     enc_size,
                     nullptr,
                     0,
                     nonce_buf.data(),
                     key_buf.data()))
        throw DecryptV2Error{"v2 message decryption failed"};

    // Strip zero padding from end (the plaintext was padded to a multiple of 256 bytes)
    while (!plain.empty() && plain.back() == 0)
        plain.pop_back();

    // Step 5: Parse the bencoded inner dict
    oxenc::bt_dict_consumer dict{plain};

    auto sender_ed_pk = dict.require_span<unsigned char, 32>("S");
    auto content_sv = dict.require_span<unsigned char>("c");

    // Verify the Ed25519 signature over BLAKE2b(body, key=recipient_session_id, pers=…)
    dict.require_signature(
            "~", [&](std::span<const unsigned char> body, std::span<const unsigned char> sig) {
                if (sig.size() != 64)
                    throw std::runtime_error{"v2 message signature has wrong size"};
                uc64 h;
                hash::blake2b_key_pers(h, recipient_session_id, V2_MSG_SIG_PERS, body);
                if (0 != crypto_sign_ed25519_verify_detached(
                                 sig.data(), h.data(), h.size(), sender_ed_pk.data()))
                    throw std::runtime_error{"v2 message signature verification failed"};
            });

    // Optional "~P" pro signature (span into plain, copied once into result below)
    std::optional<std::span<const unsigned char, 64>> pro_sv;
    if (dict.skip_until("~P"))
        pro_sv = dict.consume_span<unsigned char, 64>();

    dict.finish();

    // Convert sender Ed25519 pubkey to X25519 and build the 33-byte session ID
    std::array<unsigned char, 32> sender_x25519;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x25519.data(), sender_ed_pk.data()))
        throw std::runtime_error{"sender ed25519 pubkey is invalid"};

    DecryptV2Result result;
    result.content.assign(content_sv.begin(), content_sv.end());
    result.sender_session_id[0] = 0x05;
    std::ranges::copy(sender_x25519, result.sender_session_id.begin() + 1);
    if (pro_sv)
        std::ranges::copy(*pro_sv, result.pro_signature.emplace().begin());
    return result;
}

// Calculate the shared encryption key, sending from blinded sender kS (k = S's blinding factor) to
// blinded receiver jR (j = R's blinding factor).
//
// The sender knows s, k, S, and jR, but not j/R individually.
// The receiver knows r, j, R, and kS, but not k/S individually.
//
// From the sender's perspective, then, we compute:
//
// BLAKE2b(s k[jR] || kS || [jR])
//
// The receiver can calulate the same value via:
//
// BLAKE2b(r j[kS] || [kS] || jR)
//
// (which will be the same because sR = rS, and so skjR = kjsR = kjrS = rjkS).
//
// For 15 blinding, however, the blinding factor depended only on the SOGS server pubkey, and so `j
// = k`, and so for *15* keys we don't do the double-blinding (i.e. the first terms above drop the
// double-blinding factors and become just sjR and rkS).
//
// Arguments.  "A" and "B" here are either sender and receiver, or receiver and sender, depending on
// the value of `sending`.
//
// seed -- A's 32-byte secret key (can also be 64 bytes; only the first 32 are used).
// kA -- A's 33-byte blinded id, beginning with 0x15 or 0x25
// jB -- A's 33-byte blinded id, beginning with 0x15 or 0x25 (must be the same prefix as kA).
// server_pk -- the server's pubkey (needed to compute A's `k` value)
// sending -- true if this for a message from A to B, false if this is from B to A.
static cleared_uc32 blinded_shared_secret(
        std::span<const unsigned char> seed,
        std::span<const unsigned char, 33> kA_prefixed,
        std::span<const unsigned char, 33> jB_prefixed,
        std::span<const unsigned char, 32> server_pk,
        bool sending) {

    // Because we're doing this generically, we use notation a/A/k for ourselves and b/jB for the
    // other person; this notion keeps everything exactly as above *except* for the concatenation in
    // the BLAKE2b hashed value: there we have to use kA || jB if we are the sender, but reverse the
    // order to jB || kA if we are the receiver.

    std::pair<uc32, cleared_uc32> blinded_key_pair;
    cleared_uc32 k;

    if (seed.size() != 64 && seed.size() != 32)
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    if (kA_prefixed[0] == 0x15 && jB_prefixed[0] == 0x15)
        blinded_key_pair = blind15_key_pair(seed, server_pk, &k);
    else if (kA_prefixed[0] == 0x25 && jB_prefixed[0] == 0x25)
        blinded_key_pair = blind25_key_pair(seed, server_pk, &k);
    else
        throw std::invalid_argument{"Both ids must start with the same 0x15 or 0x25 prefix"};

    bool blind25 = kA_prefixed[0] == 0x25;

    auto kA = kA_prefixed.subspan<1>();
    auto jB = jB_prefixed.subspan<1>();

    cleared_uc32 ka;
    // Not really switching to x25519 here, this is just an easy way to compute `a`
    crypto_sign_ed25519_sk_to_curve25519(ka.data(), seed.data());

    if (blind25)
        // Multiply a by k, so that we end up computing kajB = kjaB, which the other side can
        // compute as jkbA.
        crypto_core_ed25519_scalar_mul(ka.data(), ka.data(), k.data());
    // Else for 15 blinding we leave "ka" as just a, because j=k and so we don't need the
    // double-blind.

    cleared_uc32 shared_secret;
    if (0 != crypto_scalarmult_ed25519_noclamp(shared_secret.data(), ka.data(), jB.data()))
        throw std::runtime_error{"Shared secret generation failed"};

    auto& sender = sending ? kA : jB;
    auto& recipient = sending ? jB : kA;

    // H(kjsR || kS || jR):
    hash::blake2b(shared_secret, shared_secret, sender, recipient);

    return shared_secret;
}

std::vector<unsigned char> encrypt_for_blinded_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char, 32> server_pk,
        std::span<const unsigned char, 33> recipient_blinded_id,
        std::span<const unsigned char> message) {

    // Generate the blinded key pair & shared encryption key
    std::pair<uc32, cleared_uc32> blinded_key_pair;
    switch (recipient_blinded_id[0]) {
        case 0x15: blinded_key_pair = blind15_key_pair(ed25519_privkey, server_pk); break;

        case 0x25: blinded_key_pair = blind25_key_pair(ed25519_privkey, server_pk); break;

        default:
            throw std::invalid_argument{
                    "Invalid recipient_blinded_id: must start with 0x15 or 0x25"};
    }
    std::vector<unsigned char> blinded_id;
    blinded_id.reserve(33);
    blinded_id.insert(
            blinded_id.end(), recipient_blinded_id.begin(), recipient_blinded_id.begin() + 1);
    blinded_id.insert(
            blinded_id.end(), blinded_key_pair.first.begin(), blinded_key_pair.first.end());

    auto enc_key = blinded_shared_secret(
            ed25519_privkey,
            std::span<const unsigned char, 33>{blinded_id.data(), 33},
            recipient_blinded_id,
            server_pk,
            true);

    // Inner data: msg || A (i.e. the sender's ed25519 master pubkey, *not* kA blinded pubkey)
    std::vector<unsigned char> buf;
    buf.reserve(message.size() + 32);
    buf.insert(buf.end(), message.begin(), message.end());

    // append A (pubkey)
    auto pk = ed25519_privkey.pubkey();
    buf.insert(buf.end(), pk.begin(), pk.end());

    // Encrypt using xchacha20-poly1305
    cleared_uchars<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext;
    unsigned long long outlen = 0;
    ciphertext.resize(
            1 + buf.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES +
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Prepend with a version byte, so that the recipient can reliably detect if a future version is
    // no longer encrypting things the way it expects.
    ciphertext[0] = BLINDED_ENCRYPT_VERSION;

    if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
                     ciphertext.data() + 1,
                     &outlen,
                     buf.data(),
                     buf.size(),
                     nullptr,
                     0,
                     nullptr,
                     nonce.data(),
                     enc_key.data()))
        throw std::runtime_error{"Crypto aead encryption failed"};

    assert(outlen == ciphertext.size() - 1 - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // append the nonce, so that we have: data = b'\x00' + ciphertext + nonce
    std::memcpy(ciphertext.data() + (1 + outlen), nonce.data(), nonce.size());

    return ciphertext;
}

static constexpr size_t GROUPS_ENCRYPT_OVERHEAD =
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;

std::vector<unsigned char> encrypt_for_group(
        const Ed25519PrivKeySpan& user_ed25519_privkey,
        std::span<const unsigned char, 32> group_ed25519_pubkey,
        std::span<const unsigned char> group_enc_key,
        std::span<const unsigned char> plaintext,
        bool compress,
        size_t padding) {
    if (plaintext.size() > GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE)
        throw std::runtime_error{"Cannot encrypt plaintext: message size is too large"};

    static_assert(decltype(group_ed25519_pubkey)::extent == crypto_sign_ed25519_PUBLICKEYBYTES);
    if (group_enc_key.size() != 32 && group_enc_key.size() != 64)
        throw std::invalid_argument{"Invalid group_enc_key: expected 32 or 64 bytes"};

    std::vector<unsigned char> _compressed;
    if (compress) {
        _compressed = zstd_compress(plaintext);
        if (_compressed.size() < plaintext.size())
            plaintext = _compressed;
        else {
            _compressed.clear();
            compress = false;
        }
    }
    // `plaintext` is now pointing at either the original input data, or at `_compressed` local
    // variable containing the compressed form of that data.

    oxenc::bt_dict_producer dict{};

    // encoded data version (bump this if something changes in an incompatible way)
    dict.append("", 1);

    // Sender ed pubkey, by which the message can be validated.  Note that there are *two*
    // components to this validation: first the regular signature validation of the "s" signature we
    // add below, but then also validation that this Ed25519 converts to the Session ID of the
    // claimed sender of the message inside the encoded message data.
    dict.append(
            "a",
            std::string_view{reinterpret_cast<const char*>(user_ed25519_privkey.data()) + 32, 32});

    if (!compress)
        dict.append("d", to_string_view(plaintext));

    // We sign `plaintext || group_ed25519_pubkey` rather than just `plaintext` so that if this
    // encrypted data will not validate if cross-posted to any other group.  We don't actually
    // include the pubkey alongside, because that is implicitly known by the group members that
    // receive it.
    std::vector<unsigned char> to_sign(plaintext.size() + group_ed25519_pubkey.size());
    std::memcpy(to_sign.data(), plaintext.data(), plaintext.size());
    std::memcpy(
            to_sign.data() + plaintext.size(),
            group_ed25519_pubkey.data(),
            group_ed25519_pubkey.size());

    std::array<unsigned char, 64> signature;
    crypto_sign_ed25519_detached(
            signature.data(), nullptr, to_sign.data(), to_sign.size(), user_ed25519_privkey.data());
    dict.append("s", to_string_view(signature));

    if (compress)
        dict.append("z", to_string_view(plaintext));

    auto encoded = std::move(dict).str();

    // suppose size == 250, padding = 256
    // so size + overhead(40) == 290
    // need padding of (256 - (290 % 256)) = 256 - 34 = 222
    // thus 290 + 222 = 512
    size_t final_len = GROUPS_ENCRYPT_OVERHEAD + encoded.size();
    if (padding > 1 && final_len % padding != 0) {
        size_t to_append = padding - (final_len % padding);
        encoded.resize(encoded.size() + to_append);
    }

    std::vector<unsigned char> ciphertext;
    ciphertext.resize(GROUPS_ENCRYPT_OVERHEAD + encoded.size());
    randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::span<const unsigned char> nonce{
            ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES};
    if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
                     ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                     nullptr,
                     to_unsigned(encoded.data()),
                     encoded.size(),
                     nullptr,
                     0,
                     nullptr,
                     nonce.data(),
                     group_enc_key.data()))
        throw std::runtime_error{"Encryption failed"};

    return ciphertext;
}

std::pair<std::vector<unsigned char>, std::string> decrypt_incoming_session_id(
        const Ed25519PrivKeySpan& ed25519_privkey, std::span<const unsigned char> ciphertext) {
    auto [buf, sender_ed_pk] = decrypt_incoming(ed25519_privkey, ciphertext);

    // Convert the sender_ed_pk to the sender's session ID
    std::array<unsigned char, 32> sender_x_pk;

    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    std::string sender_session_id;
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return {buf, sender_session_id};
}

std::pair<std::vector<unsigned char>, std::string> decrypt_incoming_session_id(
        std::span<const unsigned char, 32> x25519_pubkey,
        std::span<const unsigned char, 32> x25519_seckey,
        std::span<const unsigned char> ciphertext) {
    auto [buf, sender_ed_pk] = decrypt_incoming(x25519_pubkey, x25519_seckey, ciphertext);

    // Convert the sender_ed_pk to the sender's session ID
    std::array<unsigned char, 32> sender_x_pk;

    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    std::string sender_session_id;
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return {buf, sender_session_id};
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> decrypt_incoming(
        const Ed25519PrivKeySpan& ed25519_privkey, std::span<const unsigned char> ciphertext) {
    cleared_uc32 x_sec;
    uc32 x_pub;
    crypto_sign_ed25519_sk_to_curve25519(x_sec.data(), ed25519_privkey.data());
    crypto_scalarmult_base(x_pub.data(), x_sec.data());

    return decrypt_incoming(x_pub, x_sec, ciphertext);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> decrypt_incoming(
        std::span<const unsigned char, 32> x25519_pubkey,
        std::span<const unsigned char, 32> x25519_seckey,
        std::span<const unsigned char> ciphertext) {

    if (ciphertext.size() < crypto_box_SEALBYTES + 32 + 64)
        throw std::runtime_error{"Invalid incoming message: ciphertext is too small"};
    const size_t outer_size = ciphertext.size() - crypto_box_SEALBYTES;
    const size_t msg_size = outer_size - 32 - 64;

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> result;
    auto& [buf, sender_ed_pk] = result;

    buf.resize(outer_size);
    int opened = crypto_box_seal_open(
            buf.data(),
            ciphertext.data(),
            ciphertext.size(),
            x25519_pubkey.data(),
            x25519_seckey.data());
    if (opened != 0)
        throw std::runtime_error{"Decryption failed"};

    uc64 sig;
    sender_ed_pk.assign(buf.begin() + msg_size, buf.begin() + msg_size + 32);
    std::memcpy(sig.data(), buf.data() + msg_size + 32, 64);
    buf.resize(buf.size() - 64);  // Remove SIG, then append Y so that we get M||A||Y to verify
    buf.insert(buf.end(), x25519_pubkey.begin(), x25519_pubkey.begin() + 32);

    if (0 != crypto_sign_ed25519_verify_detached(
                     sig.data(), buf.data(), buf.size(), sender_ed_pk.data()))
        throw std::runtime_error{"Signature verification failed"};

    // Everything is good, so just drop A and Y off the message
    buf.resize(buf.size() - 32 - 32);

    return result;
}

std::pair<std::vector<unsigned char>, std::string> decrypt_from_blinded_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char, 32> server_pk,
        std::span<const unsigned char, 33> sender_id,
        std::span<const unsigned char, 33> recipient_id,
        std::span<const unsigned char> ciphertext) {
    auto ed_pk = ed25519_privkey.pubkey();
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 1 +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{
                "Invalid ciphertext: too short to contain valid encrypted data"};

    cleared_uc32 dec_key;
    auto blinded_id = recipient_id[0] == 0x25 ? blinded25_id_from_ed(to_span(ed_pk), server_pk)
                                              : blinded15_id_from_ed(to_span(ed_pk), server_pk);

    if (to_string_view(sender_id) == to_string_view(blinded_id))
        dec_key = blinded_shared_secret(ed25519_privkey, sender_id, recipient_id, server_pk, true);
    else
        dec_key = blinded_shared_secret(ed25519_privkey, recipient_id, sender_id, server_pk, false);

    std::pair<std::vector<unsigned char>, std::string> result;
    auto& [buf, sender_session_id] = result;

    // v, ct, nc = data[0], data[1:-24], data[-24:]
    if (ciphertext[0] != BLINDED_ENCRYPT_VERSION)
        throw std::invalid_argument{
                "Invalid ciphertext: version is not " + std::to_string(BLINDED_ENCRYPT_VERSION)};

    std::vector<unsigned char> nonce;
    const size_t msg_size =
            (ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES - 1 -
             crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (msg_size < 32)
        throw std::invalid_argument{"Invalid ciphertext: innerBytes too short"};
    buf.resize(msg_size);

    unsigned long long buf_len = 0;

    nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::memcpy(
            nonce.data(),
            ciphertext.data() + msg_size + 1 + crypto_aead_xchacha20poly1305_ietf_ABYTES,
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(),
                     &buf_len,
                     nullptr,
                     ciphertext.data() + 1,
                     msg_size + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                     nullptr,
                     0,
                     nonce.data(),
                     dec_key.data()))
        throw std::invalid_argument{"Decryption failed"};

    assert(buf_len == buf.size());

    // Split up: the last 32 bytes are the sender's *unblinded* ed25519 key
    uc32 sender_ed_pk;
    std::memcpy(sender_ed_pk.data(), buf.data() + (buf.size() - 32), 32);

    // Convert the sender_ed_pk to the sender's session ID
    uc32 sender_x_pk;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    std::vector<unsigned char> session_id;  // Gets populated by the following ..._from_ed calls

    // Verify that the inner sender_ed_pk (A) yields the same outer kA we got with the message
    auto extracted_sender =
            recipient_id[0] == 0x25
                    ? blinded25_id_from_ed(to_span(sender_ed_pk), server_pk, &session_id)
                    : blinded15_id_from_ed(to_span(sender_ed_pk), server_pk, &session_id);

    bool matched = to_string_view(sender_id) == to_string_view(extracted_sender);
    if (!matched && extracted_sender[0] == 0x15) {
        // With 15-blinding we might need the negative instead:
        extracted_sender[31] ^= 0x80;
        matched = to_string_view(sender_id) == to_string_view(extracted_sender);
    }
    if (!matched)
        throw std::runtime_error{"Blinded sender id does not match the actual sender"};

    // Everything is good, so just drop the sender_ed_pk off the message and prepend the '05' prefix
    // to the sender session ID
    buf.resize(buf.size() - 32);
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return result;
}

DecryptGroupMessage decrypt_group_message(
        std::span<std::span<const unsigned char>> decrypt_ed25519_privkey_list,
        std::span<const unsigned char, 32> group_ed25519_pubkey,
        std::span<const unsigned char> ciphertext) {
    static_assert(decltype(group_ed25519_pubkey)::extent == crypto_sign_ed25519_PUBLICKEYBYTES);
    DecryptGroupMessage result = {};
    if (ciphertext.size() < GROUPS_ENCRYPT_OVERHEAD)
        throw std::runtime_error{"ciphertext is too small to be encrypted data"};

    // Note we only use the secret key of the decrypt_ed25519_privkey so we don't care about
    // generating the pubkey component if the user only passed in a 32 byte libsodium-style secret
    // key.

    std::vector<unsigned char> plain;

    auto nonce = ciphertext.subspan(0, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ciphertext = ciphertext.subspan(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    plain.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);

    bool decrypt_success = false;
    for (size_t index = 0; index < decrypt_ed25519_privkey_list.size(); index++) {
        const auto& decrypt_ed25519_privkey = decrypt_ed25519_privkey_list[index];
        if (decrypt_ed25519_privkey.size() != 32 && decrypt_ed25519_privkey.size() != 64)
            throw std::invalid_argument{"Invalid decrypt_ed25519_privkey: expected 32 or 64 bytes"};
        decrypt_success = 0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                                       plain.data(),
                                       nullptr,
                                       nullptr,
                                       ciphertext.data(),
                                       ciphertext.size(),
                                       nullptr,
                                       0,
                                       nonce.data(),
                                       decrypt_ed25519_privkey.data());
        if (decrypt_success) {
            result.index = index;
            break;
        }
    }

    if (!decrypt_success)  // none of the keys worked
        throw std::runtime_error{"unable to decrypt ciphertext with any current group keys"};

    //
    // Removing any null padding bytes from the end
    //
    if (auto it =
                std::find_if(plain.rbegin(), plain.rend(), [](unsigned char c) { return c != 0; });
        it != plain.rend())
        plain.resize(plain.size() - std::distance(plain.rbegin(), it));

    //
    // Now what we have less should be a bt_dict
    //
    if (plain.empty() || plain.front() != 'd' || plain.back() != 'e')
        throw std::runtime_error{"decrypted data is not a bencoded dict"};

    oxenc::bt_dict_consumer dict{to_string_view(plain)};

    if (!dict.skip_until(""))
        throw std::runtime_error{"group message version tag (\"\") is missing"};
    if (auto v = dict.consume_integer<int>(); v != 1)
        throw std::runtime_error{
                "group message version tag (" + std::to_string(v) +
                ") is not compatible (we support v1)"};

    if (!dict.skip_until("a"))
        throw std::runtime_error{"missing message author pubkey"};
    auto ed_pk = to_span(dict.consume_string_view());
    if (ed_pk.size() != 32)
        throw std::runtime_error{
                "message author pubkey size (" + std::to_string(ed_pk.size()) + ") is invalid"};

    std::array<unsigned char, 32> x_pk;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pk.data(), ed_pk.data()))
        throw std::runtime_error{
                "author ed25519 pubkey is invalid (unable to convert it to a session id)"};

    auto& [_, session_id, data] = result;
    session_id.reserve(66);
    session_id += "05";
    oxenc::to_hex(x_pk.begin(), x_pk.end(), std::back_inserter(session_id));

    std::span<const unsigned char> raw_data;
    if (dict.skip_until("d")) {
        raw_data = to_span(dict.consume_string_view());
        if (raw_data.empty())
            throw std::runtime_error{"uncompressed message data (\"d\") cannot be empty"};
    }

    if (!dict.skip_until("s"))
        throw std::runtime_error{"message signature is missing"};
    auto ed_sig = to_span(dict.consume_string_view());
    if (ed_sig.size() != 64)
        throw std::runtime_error{
                "message signature size (" + std::to_string(ed_sig.size()) + ") is invalid"};

    bool compressed = false;
    if (dict.skip_until("z")) {
        if (!raw_data.empty())
            throw std::runtime_error{
                    "message signature cannot contain both compressed (z) and uncompressed (d) "
                    "data"};
        raw_data = to_span(dict.consume_string_view());
        if (raw_data.empty())
            throw std::runtime_error{"compressed message data (\"z\") cannot be empty"};

        compressed = true;
    } else if (raw_data.empty())
        throw std::runtime_error{"message must contain compressed (z) or uncompressed (d) data"};

    // The value we verify is the raw data *followed by* the group Ed25519 pubkey.  (See the comment
    // in encrypt_message).
    std::vector<unsigned char> to_verify(raw_data.size() + group_ed25519_pubkey.size());
    std::memcpy(to_verify.data(), raw_data.data(), raw_data.size());
    std::memcpy(
            to_verify.data() + raw_data.size(),
            group_ed25519_pubkey.data(),
            group_ed25519_pubkey.size());
    if (0 != crypto_sign_ed25519_verify_detached(
                     ed_sig.data(), to_verify.data(), to_verify.size(), ed_pk.data()))
        throw std::runtime_error{"message signature failed validation"};

    if (compressed) {
        if (auto decomp = zstd_decompress(raw_data, GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE)) {
            data = std::move(*decomp);
        } else
            throw std::runtime_error{"message decompression failed"};
    } else
        data.assign(raw_data.begin(), raw_data.end());

    return result;
}

std::string decrypt_ons_response(
        std::string_view lowercase_name,
        std::span<const unsigned char> ciphertext,
        std::optional<std::span<const unsigned char, 24>> nonce) {
    // Handle old Argon2-based encryption used before HF16
    if (!nonce) {
        if (ciphertext.size() < crypto_secretbox_MACBYTES)
            throw std::invalid_argument{"Invalid ciphertext: expected to be greater than 16 bytes"};

        uc32 key;
        std::array<unsigned char, crypto_pwhash_SALTBYTES> salt = {0};

        if (0 != crypto_pwhash(
                         key.data(),
                         key.size(),
                         lowercase_name.data(),
                         lowercase_name.size(),
                         salt.data(),
                         crypto_pwhash_OPSLIMIT_MODERATE,
                         crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13))
            throw std::runtime_error{"Failed to generate key"};

        std::vector<unsigned char> msg;
        msg.resize(ciphertext.size() - crypto_secretbox_MACBYTES);
        std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce = {0};

        if (0 !=
            crypto_secretbox_open_easy(
                    msg.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data()))
            throw std::runtime_error{"Failed to decrypt"};

        std::string session_id = oxenc::to_hex(msg.begin(), msg.end());
        return session_id;
    }

    static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == 24);
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{"Invalid ciphertext: expected to be greater than 16 bytes"};

    // Hash the ONS name using BLAKE2b
    //
    // xchacha-based encryption
    // key = H(name, key=H(name))
    uc32 key;
    uc32 name_hash;
    auto name_bytes = to_unsigned(lowercase_name.data());
    crypto_generichash_blake2b(
            name_hash.data(), name_hash.size(), name_bytes, lowercase_name.size(), nullptr, 0);
    crypto_generichash_blake2b(
            key.data(),
            key.size(),
            name_bytes,
            lowercase_name.size(),
            name_hash.data(),
            name_hash.size());

    std::vector<unsigned char> buf;
    unsigned long long buf_len = 0;
    buf.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(),
                     &buf_len,
                     nullptr,
                     ciphertext.data(),
                     ciphertext.size(),
                     nullptr,
                     0,
                     nonce->data(),
                     key.data()))
        throw std::runtime_error{"Failed to decrypt"};

    if (buf_len != 33)
        throw std::runtime_error{"Invalid decrypted value: expected to be 33 bytes"};

    std::string session_id = oxenc::to_hex(buf.begin(), buf.end());
    return session_id;
}

std::vector<unsigned char> decrypt_push_notification(
        std::span<const unsigned char> payload, std::span<const unsigned char, 32> enc_key) {
    if (payload.size() <
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{"Invalid payload: too short to contain valid encrypted data"};

    std::vector<unsigned char> buf;
    std::vector<unsigned char> nonce;
    const size_t msg_size =
            (payload.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES -
             crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned long long buf_len = 0;
    buf.resize(msg_size);
    nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::memcpy(nonce.data(), payload.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(),
                     &buf_len,
                     nullptr,
                     payload.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                     payload.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                     nullptr,
                     0,
                     nonce.data(),
                     enc_key.data()))
        throw std::runtime_error{"Failed to decrypt; perhaps the secret key is invalid?"};

    // Removing any null padding bytes from the end
    if (auto it = std::find_if(buf.rbegin(), buf.rend(), [](unsigned char c) { return c != 0; });
        it != buf.rend())
        buf.resize(buf.size() - std::distance(buf.rbegin(), it));

    return buf;
}

template <typename Func, typename... T>
std::string compute_hash(Func hasher, const T&... args) {
    // Allocate a buffer of 20 bytes per integral value (which is the largest the any integral
    // value can be when stringified).
    std::array<
            char,
            (0 + ... +
             (std::is_integral_v<T> || std::is_same_v<T, std::chrono::system_clock::time_point>
                      ? 20
                      : 0))>
            buffer;
    auto* b = buffer.data();
    return hasher({detail::to_hashable(args, b)...});
}

std::string compute_hash_blake2b_b64(std::vector<std::string_view> parts) {
    constexpr size_t HASH_SIZE = 32;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, HASH_SIZE);
    for (const auto& s : parts)
        crypto_generichash_update(
                &state, reinterpret_cast<const unsigned char*>(s.data()), s.size());
    std::array<unsigned char, HASH_SIZE> hash;
    crypto_generichash_final(&state, hash.data(), HASH_SIZE);

    std::string b64hash = oxenc::to_base64(hash.begin(), hash.end());
    // Trim padding:
    while (!b64hash.empty() && b64hash.back() == '=')
        b64hash.pop_back();
    return b64hash;
}

std::vector<unsigned char> encrypt_xchacha20(
        std::span<const unsigned char> plaintext, std::span<const unsigned char, 32> key) {

    std::vector<unsigned char> ciphertext;
    ciphertext.resize(
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

    // Generate random nonce, and stash it at the beginning of ciphertext:
    randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    auto* c = reinterpret_cast<unsigned char*>(ciphertext.data()) +
              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            c,
            &clen,
            plaintext.data(),
            plaintext.size(),
            nullptr,
            0,        // additional data
            nullptr,  // nsec (always unused)
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            key.data());
    assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen <= ciphertext.size());
    ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen);
    return ciphertext;
}

std::vector<unsigned char> decrypt_xchacha20(
        std::span<const unsigned char> ciphertext, std::span<const unsigned char, 32> key) {
    if (ciphertext.size() <
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{
                "Invalid ciphertext: too short to contain valid encrypted data"};

    // Extract nonce from the beginning of the ciphertext:
    auto nonce = ciphertext.subspan(0, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ciphertext = ciphertext.subspan(nonce.size());

    std::vector<unsigned char> plaintext;
    plaintext.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    auto* m = reinterpret_cast<unsigned char*>(plaintext.data());
    unsigned long long mlen;
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     m,
                     &mlen,
                     nullptr,  // nsec (always unused)
                     ciphertext.data(),
                     ciphertext.size(),
                     nullptr,
                     0,  // additional data
                     nonce.data(),
                     key.data()))
        throw std::runtime_error{"Could not decrypt (XChaCha20-Poly1305)"};
    assert(mlen <= plaintext.size());
    plaintext.resize(mlen);
    return plaintext;
}

}  // namespace session

// Helpers: construct const unsigned char spans from raw C pointers.
// Used in C API wrappers to avoid verbose std::span<const unsigned char, N>{ptr, N} casts.
template <size_t N>
static constexpr std::span<const unsigned char, N> cspan(const unsigned char* p) noexcept {
    return std::span<const unsigned char, N>(p, N);
}
static std::span<const unsigned char> cspan(const unsigned char* p, size_t n) noexcept {
    return {p, n};
}

extern "C" {

using namespace session;

LIBSESSION_C_API bool session_encrypt_for_recipient_deterministic(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* recipient_pubkey,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_for_recipient_deterministic(
                cspan<64>(ed25519_privkey),
                cspan<32>(recipient_pubkey),
                cspan(plaintext_in, plaintext_len));

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_encrypt_for_blinded_recipient(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* community_pubkey,
        const unsigned char* recipient_blinded_id,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_for_blinded_recipient(
                cspan<64>(ed25519_privkey),
                cspan<32>(community_pubkey),
                cspan<33>(recipient_blinded_id),
                cspan(plaintext_in, plaintext_len));

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API session_encrypt_group_message session_encrypt_for_group(
        const unsigned char* user_ed25519_privkey,
        size_t user_ed25519_privkey_len,
        const unsigned char* group_ed25519_pubkey,
        size_t group_ed25519_pubkey_len,
        const unsigned char* group_enc_key,
        size_t group_enc_key_len,
        const unsigned char* plaintext,
        size_t plaintext_len,
        bool compress,
        size_t padding,
        char* error,
        size_t error_len) {
    session_encrypt_group_message result = {};
    try {
        std::vector<unsigned char> result_cpp = encrypt_for_group(
                Ed25519PrivKeySpan::from(user_ed25519_privkey, user_ed25519_privkey_len),
                cspan<32>(group_ed25519_pubkey),
                cspan(group_enc_key, group_enc_key_len),
                cspan(plaintext, plaintext_len),
                compress,
                padding);
        result = {
                .success = true,
                .ciphertext = session::span_u8_copy_or_throw(result_cpp.data(), result_cpp.size()),
        };
    } catch (const std::exception& e) {
        std::string error_cpp = e.what();
        result.error_len_incl_null_terminator =
                snprintf_clamped(
                        error, error_len, "%.*s", (int)error_cpp.size(), error_cpp.data()) +
                1;
    }
    return result;
}

LIBSESSION_C_API bool session_decrypt_incoming(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_incoming_session_id(
                cspan<64>(ed25519_privkey), cspan(ciphertext_in, ciphertext_len));
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_incoming_legacy_group(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* x25519_pubkey,
        const unsigned char* x25519_seckey,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_incoming_session_id(
                cspan<32>(x25519_pubkey),
                cspan<32>(x25519_seckey),
                cspan(ciphertext_in, ciphertext_len));
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_for_blinded_recipient(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* community_pubkey,
        const unsigned char* sender_id,
        const unsigned char* recipient_id,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_from_blinded_recipient(
                cspan<64>(ed25519_privkey),
                cspan<32>(community_pubkey),
                cspan<33>(sender_id),
                cspan<33>(recipient_id),
                cspan(ciphertext_in, ciphertext_len));
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API session_decrypt_group_message_result session_decrypt_group_message(
        const span_u8* decrypt_ed25519_privkey_list,
        size_t decrypt_ed25519_privkey_len,
        const unsigned char* group_ed25519_pubkey,
        size_t group_ed25519_pubkey_len,
        const unsigned char* ciphertext,
        size_t ciphertext_len,
        char* error,
        size_t error_len) {
    session_decrypt_group_message_result result = {};
    for (size_t index = 0; index < decrypt_ed25519_privkey_len; index++) {
        std::span<const unsigned char> key = {
                decrypt_ed25519_privkey_list[index].data, decrypt_ed25519_privkey_list[index].size};

        DecryptGroupMessage result_cpp = {};
        try {
            result_cpp = decrypt_group_message(
                    {&key, 1}, cspan<32>(group_ed25519_pubkey), cspan(ciphertext, ciphertext_len));
            result = {
                    .success = true,
                    .index = index,
                    .plaintext = session::span_u8_copy_or_throw(
                            result.plaintext.data, result.plaintext.size),
            };
            assert(result_cpp.session_id.size() == sizeof(result.session_id));
            std::memcpy(result.session_id, result_cpp.session_id.data(), sizeof(result.session_id));
            break;
        } catch (const std::exception& e) {
            std::string error_cpp = e.what();
            result.error_len_incl_null_terminator =
                    snprintf_clamped(
                            error, error_len, "%.*s", (int)error_cpp.size(), error_cpp.data()) +
                    1;
        }
    }
    return result;
}

LIBSESSION_C_API bool session_decrypt_ons_response(
        const char* name_in,
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* nonce_in,
        char* session_id_out) {
    try {
        std::optional<std::span<const unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>>
                nonce;
        if (nonce_in)
            nonce = cspan<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>(nonce_in);

        auto session_id =
                session::decrypt_ons_response(name_in, cspan(ciphertext_in, ciphertext_len), nonce);

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_push_notification(
        const unsigned char* payload_in,
        size_t payload_len,
        const unsigned char* enc_key_in,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto plaintext = session::decrypt_push_notification(
                cspan(payload_in, payload_len), cspan<32>(enc_key_in));

        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_encrypt_xchacha20(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* key_in,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext =
                session::encrypt_xchacha20(cspan(plaintext_in, plaintext_len), cspan<32>(key_in));

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_xchacha20(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* key_in,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto plaintext =
                session::decrypt_xchacha20(cspan(ciphertext_in, ciphertext_len), cspan<32>(key_in));

        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
