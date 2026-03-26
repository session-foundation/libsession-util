#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;
using namespace std::literals;
using namespace oxenc::literals;

namespace {

// Fixed sender seed, shared across all test cases.
constexpr auto SENDER_SEED =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"_hex_u;

struct SenderKeys {
    std::array<unsigned char, 32> ed_pk;
    std::array<unsigned char, 64> ed_sk;
    std::array<unsigned char, 33> session_id;  // 0x05-prefixed long-term X25519 pubkey

    SenderKeys() {
        crypto_sign_ed25519_seed_keypair(ed_pk.data(), ed_sk.data(), SENDER_SEED.data());
        std::array<unsigned char, 32> curve_pk;
        REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data()));
        session_id[0] = 0x05;
        std::ranges::copy(curve_pk, session_id.begin() + 1);
    }
};

// Bundles an owned data buffer with a SwarmMessage whose data span points into it,
// keeping lifetime correct: the buffer must outlive any SwarmMessage referencing it.
struct OwnedMessage {
    std::vector<unsigned char> data;
    SwarmMessage msg;

    explicit OwnedMessage(
            std::span<const unsigned char> d,
            std::string hash = "testhash",
            sys_ms ts = from_epoch_ms(1000),
            sys_ms exp = from_epoch_ms(9999)) :
            data{d.begin(), d.end()}, msg{data, std::move(hash), ts, exp} {}
};

// Cast the std::byte pubkeys returned by TestHelper into unsigned-char spans.
template <std::size_t N>
std::span<const unsigned char, N> as_uc(const std::array<std::byte, N>& a) {
    return std::span<const unsigned char, N>{reinterpret_cast<const unsigned char*>(a.data()), N};
}

}  // namespace

// ── V1 happy path ────────────────────────────────────────────────────────────────────────────────

TEST_CASE("_handle_direct_messages: v1 receive", "[core][dm]") {
    SenderKeys sender;

    std::vector<ReceivedMessage> received;
    std::vector<MessageDecryptFailure> failures;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };
    cbs.message_decrypt_failed = [&](const SwarmMessage&, MessageDecryptFailure r) {
        failures.push_back(r);
    };

    TempCore recipient{cbs};

    uc33 recip_session_id;
    std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());

    // Minimal valid SessionProtos::Content: field 15 (sigTimestamp) = 1.
    constexpr auto plaintext = "7801"_hex_u;
    auto encoded = encode_for_1o1(plaintext, sender.ed_sk, 1234ms, recip_session_id, std::nullopt);

    OwnedMessage om{std::span{encoded}, "hash_v1", from_epoch_ms(1234), from_epoch_ms(9999)};
    recipient->receive_messages({&om.msg, 1}, config::Namespace::Default, true);

    REQUIRE(failures.empty());
    REQUIRE(received.size() == 1);
    const auto& msg = received[0];
    CHECK(msg.hash == "hash_v1");
    CHECK(msg.timestamp == from_epoch_ms(1234));
    CHECK(msg.expiry == from_epoch_ms(9999));
    CHECK(msg.version == 1);
    CHECK(msg.sender_session_id == sender.session_id);
    CHECK(std::ranges::equal(msg.content, plaintext));
    CHECK_FALSE(msg.pro_signature.has_value());
}

// ── V2 happy path ────────────────────────────────────────────────────────────────────────────────

TEST_CASE("_handle_direct_messages: v2 receive", "[core][dm]") {
    SenderKeys sender;

    std::vector<ReceivedMessage> received;
    std::vector<MessageDecryptFailure> failures;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };
    cbs.message_decrypt_failed = [&](const SwarmMessage&, MessageDecryptFailure r) {
        failures.push_back(r);
    };

    TempCore recipient{cbs};
    // Trigger account key generation before querying the pubkeys.
    recipient->devices.active_account_keys();

    auto [x25519_bytes, mlkem_bytes] = TestHelper::active_account_pubkeys(*recipient);
    std::array<unsigned char, 33> recip_session_id;
    std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());

    constexpr auto content = "deadbeef"_hex_u;
    auto ct = encrypt_for_recipient_v2(
            sender.ed_sk,
            recip_session_id,
            as_uc(x25519_bytes),
            as_uc(mlkem_bytes),
            content,
            std::nullopt);

    OwnedMessage om{std::span{ct}, "hash_v2", from_epoch_ms(5678), from_epoch_ms(8888)};
    recipient->receive_messages({&om.msg, 1}, config::Namespace::Default, true);

    REQUIRE(failures.empty());
    REQUIRE(received.size() == 1);
    const auto& msg = received[0];
    CHECK(msg.hash == "hash_v2");
    CHECK(msg.timestamp == from_epoch_ms(5678));
    CHECK(msg.expiry == from_epoch_ms(8888));
    CHECK(msg.version == 2);
    CHECK(msg.sender_session_id == sender.session_id);
    CHECK(std::ranges::equal(msg.content, content));
    CHECK_FALSE(msg.pro_signature.has_value());
}

// ── Failure paths ────────────────────────────────────────────────────────────────────────────────

TEST_CASE("_handle_direct_messages: failure paths", "[core][dm]") {
    SenderKeys sender;

    std::vector<ReceivedMessage> received;
    std::vector<MessageDecryptFailure> failures;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };
    cbs.message_decrypt_failed = [&](const SwarmMessage&, MessageDecryptFailure r) {
        failures.push_back(r);
    };

    TempCore recipient{cbs};

    auto deliver = [&](std::span<const unsigned char> data) {
        OwnedMessage om{data};
        recipient->receive_messages({&om.msg, 1}, config::Namespace::Default, true);
    };

    SECTION("empty data → bad_format") {
        deliver(std::span<const unsigned char>{});
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::bad_format);
    }

    SECTION("0x00 0x03 → unknown_version") {
        deliver("0003010203"_hex_u);
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::unknown_version);
    }

    SECTION("v2 too short for prefix decryption → bad_format") {
        // Prefix decryption needs at least version(2) + ki(2) + ephemeral_E(32) = 36 bytes.
        deliver("00020102030405060708"_hex_u);
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::bad_format);
    }

    SECTION("v2 key indicator matches no account key → no_pfs_key") {
        // Encrypt for a different Core; the key indicator will be unrecognisable to recipient.
        TempCore other;
        other->devices.active_account_keys();
        auto [x25519_bytes, mlkem_bytes] = TestHelper::active_account_pubkeys(*other);
        std::array<unsigned char, 33> other_session_id;
        std::ranges::copy(other->globals.session_id(), other_session_id.begin());

        auto ct = encrypt_for_recipient_v2(
                sender.ed_sk,
                other_session_id,
                as_uc(x25519_bytes),
                as_uc(mlkem_bytes),
                "01"_hex_u,
                std::nullopt);
        deliver(std::span{ct});
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::no_pfs_key);
    }

    SECTION("v2 key indicator matches but AEAD MAC fails → decrypt_failed") {
        // Encrypt a valid v2 message for recipient, then corrupt the xchacha ciphertext tail to
        // cause MAC authentication failure (DecryptV2Error), exhausting all candidate keys.
        recipient->devices.active_account_keys();
        auto [x25519_bytes, mlkem_bytes] = TestHelper::active_account_pubkeys(*recipient);
        std::array<unsigned char, 33> recip_session_id;
        std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());

        auto ct = encrypt_for_recipient_v2(
                sender.ed_sk,
                recip_session_id,
                as_uc(x25519_bytes),
                as_uc(mlkem_bytes),
                "01"_hex_u,
                std::nullopt);
        // Wire format: [0,1]=version, [2,3]=ki, [4,35]=E, [36,1123]=mlkem_ct, [1124+]=xchacha.
        // Flip the final byte of the xchacha ciphertext to corrupt the AEAD tag.
        REQUIRE(ct.size() > 1124 + 16);
        ct.back() ^= 0xff;
        deliver(std::span{ct});
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::decrypt_failed);
    }

    SECTION("v1 malformed ciphertext → decrypt_failed") {
        deliver("0102030405060708"_hex_u);
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::decrypt_failed);
    }
}

// ── Callback exception safety ────────────────────────────────────────────────────────────────────

TEST_CASE(
        "_handle_direct_messages: exception in message_received is swallowed and processing "
        "continues",
        "[core][dm]") {
    SenderKeys sender;

    int call_count = 0;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&&) {
        ++call_count;
        throw std::runtime_error("deliberate test exception");
    };

    TempCore recipient{cbs};

    uc33 recip_session_id;
    std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());

    // Minimal valid SessionProtos::Content: field 15 (sigTimestamp) = 1.
    constexpr auto plaintext = "7801"_hex_u;
    auto e1 = encode_for_1o1(plaintext, sender.ed_sk, 1000ms, recip_session_id, std::nullopt);
    auto e2 = encode_for_1o1(plaintext, sender.ed_sk, 2000ms, recip_session_id, std::nullopt);

    OwnedMessage om1{std::span{e1}, "h1"};
    OwnedMessage om2{std::span{e2}, "h2"};
    std::array<SwarmMessage, 2> msgs{om1.msg, om2.msg};

    // The thrown exception must not propagate, and both messages must reach the callback.
    CHECK_NOTHROW(recipient->receive_messages(msgs, config::Namespace::Default, true));
    CHECK(call_count == 2);
}
