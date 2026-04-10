#include "session/blinding.hpp"
#include "session/blinding.h"

#include <fmt/format.h>
#include <oxenc/hex.h>
#include <oxen/log/format.hpp>
#include <session/format.hpp>

#include <cassert>
#include <stdexcept>

#include "session/crypto/ed25519.hpp"
#include "session/export.h"
#include "session/hash.hpp"
#include "session/platform.h"
#include "session/platform.hpp"
#include "session/xed25519.hpp"

namespace session {

using namespace std::literals;
using namespace oxen::log::literals;

b32 blind15_factor(std::span<const std::byte, 32> server_pk) {
    auto blind_hash = hash::blake2b<64>(server_pk);

    b32 k;
    ed25519::scalar_reduce(k, blind_hash);
    return k;
}

b32 blind25_factor(
        std::span<const std::byte> session_id, std::span<const std::byte, 32> server_pk) {

    b64 blind_hash;
    if (session_id.size() == 32)
        hash::blake2b(blind_hash, "05"_hex_b, session_id, server_pk);
    else
        hash::blake2b(blind_hash, session_id, server_pk);

    b32 k;
    ed25519::scalar_reduce(k, blind_hash);
    return k;
}

namespace {

    void blind_id_impl(
            std::span<const std::byte> session_id,
            std::span<const std::byte> server_pk,
            std::span<const std::byte, 32> blind_factor,
            std::span<std::byte, 33> out,
            std::byte prefix) {
        if (session_id.size() == 33)
            session_id = session_id.subspan(1);
        if (session_id.size() != 32)
            throw std::invalid_argument{"Invalid session id"};

        ed25519::scalarmult_noclamp(out.last<32>(), blind_factor, xed25519::pubkey(session_id.first<32>()));
        out[0] = prefix;
    }

    void blind15_id_impl(
            std::span<const std::byte> session_id,
            std::span<const std::byte, 32> server_pk,
            std::span<std::byte, 33> out) {
        blind_id_impl(session_id, server_pk, blind15_factor(server_pk), out, std::byte{0x15});
    }

    void blind25_id_impl(
            std::span<const std::byte> session_id,
            std::span<const std::byte, 32> server_pk,
            std::span<std::byte, 33> out) {
        blind_id_impl(session_id, server_pk, blind25_factor(session_id, server_pk), out, std::byte{0x25});
    }

    // Parses server_pk from either 32 raw bytes or 64 hex digits.
    b32 parse_server_pk(std::string_view server_pk_in, std::string_view func_name) {
        b32 server_pk;
        if (server_pk_in.size() == 32)
            std::memcpy(server_pk.data(), server_pk_in.data(), 32);
        else if (server_pk_in.size() == 64 && oxenc::is_hex(server_pk_in))
            oxenc::from_hex(server_pk_in.begin(), server_pk_in.end(), server_pk.begin());
        else
            throw std::invalid_argument{
                    "{}: Invalid server_pk: expected 32 bytes or 64 hex"_format(func_name)};
        return server_pk;
    }

    // Common final portion of blind15/blind25 signing: given blinded pubkey A, blinded scalar a,
    // nonce r, and message, computes and returns the 64-byte signature.
    b64 blinded_sign_finish(
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> a,
            std::span<const std::byte, 32> r,
            std::span<const std::byte> message) {
        b64 result;
        auto sig_R = std::span{result}.first<32>();
        auto sig_S = std::span{result}.last<32>();

        ed25519::scalarmult_base_noclamp(sig_R, r);

        b64 hram;
        hash::sha512(hram, sig_R, A, message);

        ed25519::scalar_reduce(sig_S, hram);     // S = H(R||A||M)
        ed25519::scalar_mul(sig_S, sig_S, a);    // S = H(R||A||M) a
        ed25519::scalar_add(sig_S, sig_S, r);    // S = r + H(R||A||M) a

        return result;
    }

}  // namespace

b33 blind15_id(
        std::span<const std::byte> session_id, std::span<const std::byte, 32> server_pk) {
    if (session_id.size() == 33) {
        if (session_id[0] != std::byte{0x05})
            throw std::invalid_argument{"blind15_id: session_id must start with 0x05"};
        session_id = session_id.subspan(1);
    } else if (session_id.size() != 32) {
        throw std::invalid_argument{"blind15_id: session_id must be 32 or 33 bytes"};
    }

    b33 result;
    blind15_id_impl(session_id, server_pk, result);
    return result;
}

std::array<std::string, 2> blind15_id(std::string_view session_id, std::string_view server_pk) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{"blind15_id: session_id must be hex (66 digits)"};
    if (session_id[0] != '0' || session_id[1] != '5')
        throw std::invalid_argument{"blind15_id: session_id must start with 05"};
    if (server_pk.size() != 64 || !oxenc::is_hex(server_pk))
        throw std::invalid_argument{"blind15_id: server_pk must be hex (64 digits)"};

    b33 raw_sid;
    oxenc::from_hex(session_id.begin(), session_id.end(), raw_sid.begin());
    b32 raw_server_pk;
    oxenc::from_hex(server_pk.begin(), server_pk.end(), raw_server_pk.begin());

    b33 blinded;
    blind15_id_impl(raw_sid, raw_server_pk, blinded);
    std::array<std::string, 2> result;
    result[0] = oxenc::to_hex(blinded);
    blinded.back() ^= std::byte{0x80};
    result[1] = oxenc::to_hex(blinded);
    return result;
}

b33 blind25_id(
        std::span<const std::byte> session_id, std::span<const std::byte, 32> server_pk) {
    if (session_id.size() == 33) {
        if (session_id[0] != std::byte{0x05})
            throw std::invalid_argument{"blind25_id: session_id must start with 0x05"};
    } else if (session_id.size() != 32) {
        throw std::invalid_argument{"blind25_id: session_id must be 32 or 33 bytes"};
    }

    b33 result;
    blind25_id_impl(session_id, server_pk, result);
    return result;
}

std::string blind25_id(std::string_view session_id, std::string_view server_pk) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{"blind25_id: session_id must be hex (66 digits)"};
    if (session_id[0] != '0' || session_id[1] != '5')
        throw std::invalid_argument{"blind25_id: session_id must start with 05"};
    if (server_pk.size() != 64 || !oxenc::is_hex(server_pk))
        throw std::invalid_argument{"blind25_id: server_pk must be hex (64 digits)"};

    b33 raw_sid;
    oxenc::from_hex(session_id.begin(), session_id.end(), raw_sid.begin());
    b32 raw_server_pk;
    oxenc::from_hex(server_pk.begin(), server_pk.end(), raw_server_pk.begin());

    b33 blinded;
    blind25_id_impl(raw_sid, raw_server_pk, blinded);
    return oxenc::to_hex(blinded);
}

b33 blinded15_id_from_ed(
        std::span<const std::byte, 32> ed_pubkey,
        std::span<const std::byte, 32> server_pk,
        std::optional<b33>* session_id) {
    if (session_id && !session_id->has_value())
        session_id->emplace(ed25519::pk_to_session_id(ed_pubkey));

    b33 result;
    auto k = blind15_factor(server_pk);
    ed25519::scalarmult_noclamp(
            std::span<std::byte, 32>{result.data() + 1, 32}, k, ed_pubkey);
    result[0] = std::byte{0x15};
    return result;
}

b33 blinded25_id_from_ed(
        std::span<const std::byte, 32> ed_pubkey,
        std::span<const std::byte, 32> server_pk,
        std::optional<b33>* session_id) {
    std::optional<b33> tmp_session_id;
    if (!session_id)
        session_id = &tmp_session_id;
    if (!session_id->has_value())
        session_id->emplace(ed25519::pk_to_session_id(ed_pubkey));

    auto k = blind25_factor(**session_id, server_pk);

    b33 result;
    // Blinded25 ids are always constructed using the absolute value of the ed pubkey, so if
    // negative we need to clear the sign bit to make it positive before computing the blinded
    // pubkey.
    b32 pos_ed_pubkey;
    std::ranges::copy(ed_pubkey, pos_ed_pubkey.begin());
    pos_ed_pubkey[31] &= std::byte{0x7f};

    ed25519::scalarmult_noclamp(
            std::span<std::byte, 32>{result.data() + 1, 32}, k, pos_ed_pubkey);
    result[0] = std::byte{0x25};
    return result;
}

std::pair<b32, cleared_b32> blind15_key_pair(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::span<const std::byte, 32> server_pk,
        b32* k) {
    std::pair<b32, cleared_b32> result;
    auto& [A, a] = result;

    /// Generate the blinding factor (storing into `*k`, if a pointer was provided)
    b32 k_tmp;
    if (!k)
        k = &k_tmp;
    *k = blind15_factor(server_pk);

    // Calculate the private scalar `a`
    ed25519::sk_to_private(a, ed25519_sk.seed());

    // Turn a, A into their blinded versions
    ed25519::scalar_mul(a, *k, a);
    ed25519::scalarmult_base_noclamp(A, a);

    return result;
}

std::pair<b32, cleared_b32> blind25_key_pair(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::span<const std::byte, 32> server_pk,
        b32* k_prime) {
    b33 session_id;
    session_id[0] = std::byte{0x05};
    ed25519::pk_to_x25519(std::span{session_id}.last<32>(), ed25519_sk.pubkey());

    auto X = std::span{session_id}.last<32>();

    /// Generate the blinding factor (storing into `*k`, if a pointer was provided)
    b32 k_tmp;
    if (!k_prime)
        k_prime = &k_tmp;
    *k_prime = blind25_factor(X, server_pk);

    // For a negative pubkey we use k' = -k so that k'A == kA when A is positive, and k'A = -kA =
    // k|A| when A is negative.
    if ((ed25519_sk.pubkey()[31] & std::byte{0x80}) != std::byte{})
        ed25519::scalar_negate(*k_prime, *k_prime);

    std::pair<b32, cleared_b32> result;
    auto& [A, a] = result;

    // Generate the private key (scalar), a; (the sodium function naming here is misleading; this
    // call actually has nothing to do with conversion to X25519, it just so happens that the
    // conversion method is the easiest way to get `a` out of libsodium).
    a = ed25519::sk_to_x25519(ed25519_sk);

    // Turn a, A into their blinded versions
    ed25519::scalar_mul(a, *k_prime, a);
    ed25519::scalarmult_base_noclamp(A, a);

    return result;
}

static constexpr auto version_blinding_hash_key_sig = "VersionCheckKey_sig"_bytes;

std::pair<b32, cleared_b64> blind_version_key_pair(const ed25519::PrivKeySpan& ed25519_sk) {
    cleared_b32 blind_seed;
    hash::blake2b_key(blind_seed, version_blinding_hash_key_sig, ed25519_sk.seed());
    return ed25519::keypair(blind_seed);
}

static constexpr auto hash_key_seed = "SessCommBlind25_seed"_bytes;
static constexpr auto hash_key_sig = "SessCommBlind25_sig"_bytes;

b64 blind25_sign(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::span<const std::byte, 32> server_pk,
        std::span<const std::byte> message) {
    auto [A, a] = blind25_key_pair(ed25519_sk, server_pk);

    b32 seedhash;
    hash::blake2b_key(seedhash, hash_key_seed, ed25519_sk.seed());

    b64 r_hash;
    hash::blake2b_key(r_hash, hash_key_sig, seedhash, A, message);

    b32 r;
    ed25519::scalar_reduce(r, r_hash);

    return blinded_sign_finish(A, a, r, message);
}

b64 blind25_sign(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::string_view server_pk_in,
        std::span<const std::byte> message) {
    return blind25_sign(ed25519_sk, parse_server_pk(server_pk_in, "blind25_sign"), message);
}

b64 blind15_sign(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::span<const std::byte, 32> server_pk,
        std::span<const std::byte> message) {
    auto [blind_15_pk, blind_15_sk] = blind15_key_pair(ed25519_sk, server_pk);

    // H_rh = sha512(s.encode()).digest()[32:]
    b64 hrh;
    hash::sha512(hrh, ed25519_sk);

    // r = salt.crypto_core_ed25519_scalar_reduce(sha512_multipart(H_rh, kA, message_parts))
    b64 r_hash;
    hash::sha512(r_hash, std::span{hrh}.last<32>(), blind_15_pk, message);

    b32 r;
    ed25519::scalar_reduce(r, r_hash);

    return blinded_sign_finish(blind_15_pk, blind_15_sk, r, message);
}

b64 blind15_sign(
        const ed25519::PrivKeySpan& ed25519_sk,
        std::string_view server_pk_in,
        std::span<const std::byte> message) {
    return blind15_sign(ed25519_sk, parse_server_pk(server_pk_in, "blind15_sign"), message);
}

b64 blind_version_sign_request(
        const ed25519::PrivKeySpan& ed25519_sk,
        uint64_t timestamp,
        std::string_view method,
        std::string_view path,
        std::optional<std::span<const std::byte>> body) {
    auto [pk, sk] = blind_version_key_pair(ed25519_sk);

    // Signature should be on `TIMESTAMP || METHOD || PATH || BODY`
    auto ts = "{}"_format(timestamp);
    std::vector<std::byte> buf;
    buf.reserve(ts.size() + method.size() + path.size() + (body ? body->size() : 0));
    auto app = [&](std::string_view sv) {
        auto s = to_span(sv);
        buf.insert(buf.end(), s.begin(), s.end());
    };
    app(ts);
    app(method);
    app(path);
    if (body)
        buf.insert(buf.end(), body->begin(), body->end());

    return ed25519::sign(sk, buf);
}

b64 blind_version_sign(
        const ed25519::PrivKeySpan& ed25519_sk, Platform platform, uint64_t timestamp) {
    std::string_view url;
    switch (platform) {
        case Platform::android: url = "/session_version?platform=android"; break;
        case Platform::ios: url = "/session_version?platform=ios"; break;
        case Platform::desktop:
        default: url = "/session_version?platform=desktop"; break;
    }
    return blind_version_sign_request(ed25519_sk, timestamp, "GET", url, std::nullopt);
}

bool session_id_matches_blinded_id(
        std::string_view session_id, std::string_view blinded_id, std::string_view server_pk) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{
                "session_id_matches_blinded_id: session_id must be hex (66 digits)"};
    if (session_id[0] != '0' || session_id[1] != '5')
        throw std::invalid_argument{"session_id_matches_blinded_id: session_id must start with 05"};
    if (blinded_id[1] != '5' && (blinded_id[0] != '1' || blinded_id[0] != '2'))
        throw std::invalid_argument{
                "session_id_matches_blinded_id: blinded_id must start with 15 or 25"};
    if (server_pk.size() != 64 || !oxenc::is_hex(server_pk))
        throw std::invalid_argument{
                "session_id_matches_blinded_id: server_pk must be hex (64 digits)"};

    std::string converted_blind_id1, converted_blind_id2;
    std::vector<std::byte> converted_blind_id1_raw;

    switch (blinded_id[0]) {
        case '1': {
            auto [converted_blind_id1, converted_blind_id2] = blind15_id(session_id, server_pk);
            return (blinded_id == converted_blind_id1 || blinded_id == converted_blind_id2);
        }

        // blind25 doesn't run into the negative issue that blind15 did
        case '2': return blinded_id == blind25_id(session_id, server_pk);
        default: throw std::invalid_argument{"Invalid blinded_id: must start with 15 or 25"};
    }
}

}  // namespace session

using namespace session;

LIBSESSION_C_API bool session_blind15_key_pair(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        unsigned char* blinded_pk_out,
        unsigned char* blinded_sk_out) {
    try {
        auto [b_pk, b_sk] = session::blind15_key_pair(
                {ed25519_seckey, 64}, to_byte_span<32>(server_pk));
        std::memcpy(blinded_pk_out, b_pk.data(), b_pk.size());
        std::memcpy(blinded_sk_out, b_sk.data(), b_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind25_key_pair(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        unsigned char* blinded_pk_out,
        unsigned char* blinded_sk_out) {
    try {
        auto [b_pk, b_sk] = session::blind25_key_pair(
                {ed25519_seckey, 64}, to_byte_span<32>(server_pk));
        std::memcpy(blinded_pk_out, b_pk.data(), b_pk.size());
        std::memcpy(blinded_sk_out, b_sk.data(), b_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind_version_key_pair(
        const unsigned char* ed25519_seckey,
        unsigned char* blinded_pk_out,
        unsigned char* blinded_sk_out) {
    try {
        auto [b_pk, b_sk] = session::blind_version_key_pair({ed25519_seckey, 64});
        std::memcpy(blinded_pk_out, b_pk.data(), b_pk.size());
        std::memcpy(blinded_sk_out, b_sk.data(), b_sk.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind15_sign(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        const unsigned char* msg,
        size_t msg_len,
        unsigned char* blinded_sig_out) {
    try {
        auto sig = session::blind15_sign(
                {ed25519_seckey, 64},
                {reinterpret_cast<const char*>(server_pk), 32},
                to_byte_span(msg, msg_len));
        std::memcpy(blinded_sig_out, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind25_sign(
        const unsigned char* ed25519_seckey,
        const unsigned char* server_pk,
        const unsigned char* msg,
        size_t msg_len,
        unsigned char* blinded_sig_out) {
    try {
        auto sig = session::blind25_sign(
                {ed25519_seckey, 64},
                {reinterpret_cast<const char*>(server_pk), 32},
                to_byte_span(msg, msg_len));
        std::memcpy(blinded_sig_out, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind_version_sign_request(
        const unsigned char* ed25519_seckey,
        size_t timestamp,
        const char* method,
        const char* path,
        const unsigned char* body,
        size_t body_len,
        unsigned char* blinded_sig_out) {
    std::string_view method_sv{method};
    std::string_view path_sv{path};

    std::optional<std::span<const std::byte>> body_sv{std::nullopt};
    if (body)
        body_sv = to_byte_span(body, body_len);

    try {
        auto sig = session::blind_version_sign_request(
                {ed25519_seckey, 64}, timestamp, method_sv, path_sv, body_sv);
        std::memcpy(blinded_sig_out, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_blind_version_sign(
        const unsigned char* ed25519_seckey,
        CLIENT_PLATFORM platform,
        size_t timestamp,
        unsigned char* blinded_sig_out) {
    try {
        auto sig = session::blind_version_sign(
                {ed25519_seckey, 64}, static_cast<Platform>(platform), timestamp);
        std::memcpy(blinded_sig_out, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_id_matches_blinded_id(
        const char* session_id, const char* blinded_id, const char* server_pk) {
    try {
        return session::session_id_matches_blinded_id(
                {session_id, 66}, {blinded_id, 66}, {server_pk, 64});
    } catch (...) {
        return false;
    }
}
