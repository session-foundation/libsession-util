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
    auto encoded =
            encode_dm_v1(plaintext, sender.ed_sk, clock_now_ms(), recip_session_id, std::nullopt);

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
    CHECK(msg.pfs_encrypted);
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

    SECTION("v2 AEAD MAC corrupted → no_pfs_key") {
        // Encrypt a valid v2 message for recipient, then corrupt the xchacha ciphertext tail to
        // cause MAC authentication failure on both the PFS key loop and the non-PFS fallback.
        // Both paths throw DecryptV2Error, so no_pfs_key is fired (nothing could decrypt it).
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
        CHECK(failures[0] == MessageDecryptFailure::no_pfs_key);
    }

    SECTION("v1 malformed ciphertext → decrypt_failed") {
        deliver("0102030405060708"_hex_u);
        CHECK(received.empty());
        REQUIRE(failures.size() == 1);
        CHECK(failures[0] == MessageDecryptFailure::decrypt_failed);
    }
}

// ── Non-PFS fallback ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("_handle_direct_messages: v2 non-PFS fallback receive", "[core][dm]") {
    SenderKeys sender;

    std::vector<ReceivedMessage> received;
    std::vector<MessageDecryptFailure> failures;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };
    cbs.message_decrypt_failed = [&](const SwarmMessage&, MessageDecryptFailure r) {
        failures.push_back(r);
    };

    TempCore recipient{cbs};
    // Do NOT call active_account_keys() — sender has no PFS keys for this recipient.

    std::array<unsigned char, 33> recip_session_id;
    std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());

    constexpr auto content = "cafebabe"_hex_u;
    auto ct = encrypt_for_recipient_v2_nopfs(sender.ed_sk, recip_session_id, content, std::nullopt);

    OwnedMessage om{std::span{ct}, "hash_nopfs", from_epoch_ms(3333), from_epoch_ms(7777)};
    recipient->receive_messages({&om.msg, 1}, config::Namespace::Default, true);

    REQUIRE(failures.empty());
    REQUIRE(received.size() == 1);
    const auto& msg = received[0];
    CHECK(msg.hash == "hash_nopfs");
    CHECK(msg.timestamp == from_epoch_ms(3333));
    CHECK(msg.expiry == from_epoch_ms(7777));
    CHECK(msg.version == 2);
    CHECK(msg.sender_session_id == sender.session_id);
    CHECK(std::ranges::equal(msg.content, content));
    CHECK_FALSE(msg.pro_signature.has_value());
    CHECK_FALSE(msg.pfs_encrypted);
}

TEST_CASE(
        "_handle_direct_messages: v2 non-PFS fallback succeeds when ki collides with PFS key",
        "[core][dm]") {
    // A non-PFS message whose decrypted ki happens to match the 2-byte ML-KEM prefix of one of
    // the recipient's real PFS account keys.  The PFS key loop runs but throws DecryptV2Error
    // (wrong key derivation); the non-PFS fallback then succeeds.
    //
    // The ki is XOR-encrypted: wire_ki = plaintext_ki ⊕ kiss, where kiss is derived from the
    // ephemeral key pair.  decrypt_incoming_v2_prefix recovers plaintext_ki.  We construct
    // the collision deterministically by patching the wire_ki bytes after encrypting:
    //   new_wire_ki[i] = wire_ki[i] ⊕ plaintext_ki[i] ⊕ target_ki[i]
    // which sets plaintext_ki to target_ki without touching E or the ciphertext body.
    SenderKeys sender;

    std::vector<ReceivedMessage> received;
    std::vector<MessageDecryptFailure> failures;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };
    cbs.message_decrypt_failed = [&](const SwarmMessage&, MessageDecryptFailure r) {
        failures.push_back(r);
    };

    TempCore recipient{cbs};
    recipient->devices.active_account_keys();

    std::array<unsigned char, 33> recip_session_id;
    std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());
    auto seed_access = recipient->globals.account_seed();
    auto x25519_sec = seed_access.x25519_key();
    std::span<const unsigned char, 32> x25519_pub{recip_session_id.data() + 1, 32};

    // The target ki is the first 2 bytes of the recipient's active ML-KEM public key.
    auto [x25519_bytes, mlkem_bytes] = TestHelper::active_account_pubkeys(*recipient);
    std::array<unsigned char, 2> target_ki{
            static_cast<unsigned char>(mlkem_bytes[0]), static_cast<unsigned char>(mlkem_bytes[1])};

    constexpr auto content = "deadc0de"_hex_u;
    auto ct = encrypt_for_recipient_v2_nopfs(sender.ed_sk, recip_session_id, content, std::nullopt);

    // Recover the current plaintext ki so we can XOR it out and XOR the target in.
    auto current_ki = decrypt_incoming_v2_prefix(x25519_sec, x25519_pub, ct);
    ct[2] ^= current_ki[0] ^ target_ki[0];
    ct[3] ^= current_ki[1] ^ target_ki[1];

    // Verify the patch: the decrypted ki should now equal target_ki.
    REQUIRE(decrypt_incoming_v2_prefix(x25519_sec, x25519_pub, ct) == target_ki);

    OwnedMessage om{std::span{ct}, "hash_ki_collision"};
    recipient->receive_messages({&om.msg, 1}, config::Namespace::Default, true);

    REQUIRE(failures.empty());
    REQUIRE(received.size() == 1);
    CHECK(std::ranges::equal(received[0].content, content));
    CHECK_FALSE(received[0].pfs_encrypted);
}

// ── PFS ki-prefix collision within the loop ──────────────────────────────────────────────────────

TEST_CASE(
        "_handle_direct_messages: PFS decryption succeeds when ki collides within the PFS loop",
        "[core][dm]") {
    // Verify that when active_account_keys(ki) returns multiple candidates (because two account
    // keys share the same 2-byte ML-KEM prefix), the loop continues past a DecryptV2Error on the
    // wrong key and succeeds with the correct key.
    //
    // We find a colliding pair via the birthday paradox: rotating account keys until any two
    // generated keys share the same 2-byte ML-KEM prefix.  Expected ~321 rotations on average
    // (sqrt(pi * 65536 / 2)), each taking < 1 ms, so the total cost is well under a second.
    SenderKeys sender;

    std::vector<ReceivedMessage> received;
    std::vector<MessageDecryptFailure> failures;
    callbacks cbs;
    cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };
    cbs.message_decrypt_failed = [&](const SwarmMessage&, MessageDecryptFailure r) {
        failures.push_back(r);
    };

    TempCore recipient{cbs};

    std::array<unsigned char, 33> recip_session_id;
    std::ranges::copy(recipient->globals.session_id(), recip_session_id.begin());

    // Generate the first account key and record (prefix → pubkeys) as we rotate.
    recipient->devices.active_account_keys();

    using Prefix = std::array<unsigned char, 2>;
    using PubkeyPair = std::pair<std::array<std::byte, 32>, std::array<std::byte, 1184>>;
    std::map<Prefix, PubkeyPair> seen;

    // Record the current active key; returns the earlier key's pubkeys if its prefix collides.
    auto record_active = [&]() -> std::optional<PubkeyPair> {
        auto [x, m] = TestHelper::active_account_pubkeys(*recipient);
        Prefix pfx{static_cast<unsigned char>(m[0]), static_cast<unsigned char>(m[1])};
        if (auto it = seen.find(pfx); it != seen.end())
            return it->second;
        seen.emplace(pfx, PubkeyPair{x, m});
        return std::nullopt;
    };

    record_active();

    PubkeyPair target_pubkeys;
    bool found = false;
    for (int i = 0; i < 500'000 && !found; ++i) {
        recipient->devices.rotate_account_keys();
        if (auto match = record_active()) {
            target_pubkeys = *match;
            found = true;
        }
    }
    REQUIRE(found);

    // Encrypt with the earlier (now-rotated) key that shares the active key's ki prefix.
    // active_account_keys(ki) returns [active_key (wrong), rotated_target (right)], so Core
    // tries the wrong key first (DecryptV2Error), then succeeds with the right one.
    constexpr auto content = "feedface"_hex_u;
    auto ct = encrypt_for_recipient_v2(
            sender.ed_sk,
            recip_session_id,
            as_uc(target_pubkeys.first),
            as_uc(target_pubkeys.second),
            content,
            std::nullopt);

    OwnedMessage om{std::span{ct}, "hash_ki_pfs_collision"};
    recipient->receive_messages({&om.msg, 1}, config::Namespace::Default, true);

    REQUIRE(failures.empty());
    REQUIRE(received.size() == 1);
    CHECK(std::ranges::equal(received[0].content, content));
    CHECK(received[0].pfs_encrypted);
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
    auto e1 = encode_dm_v1(plaintext, sender.ed_sk, clock_now_ms(), recip_session_id, std::nullopt);
    auto e2 = encode_dm_v1(plaintext, sender.ed_sk, clock_now_ms(), recip_session_id, std::nullopt);

    OwnedMessage om1{std::span{e1}, "h1"};
    OwnedMessage om2{std::span{e2}, "h2"};
    std::array<SwarmMessage, 2> msgs{om1.msg, om2.msg};

    // The thrown exception must not propagate, and both messages must reach the callback.
    CHECK_NOTHROW(recipient->receive_messages(msgs, config::Namespace::Default, true));
    CHECK(call_count == 2);
}
