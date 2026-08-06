#include <SessionProtos.pb.h>

#include <catch2/catch_test_macros.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/util.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;
using namespace std::literals;
using namespace oxenc::literals;

namespace {

// Returns the session_id of a Core as a std::byte array.
std::array<std::byte, 33> sid_bytes(Core& c) {
    std::array<std::byte, 33> result;
    auto sid = c.globals.session_id();
    std::memcpy(result.data(), sid.data(), 33);
    return result;
}

// Minimal valid SessionProtos::Content protobuf: field 15 (sigTimestamp) = 1.
constexpr auto MINIMAL_CONTENT = "7801"_hex_b;

// A valid session ID for tests that don't need actual decryption on the other side.
constexpr auto DUMMY_SID =
        "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

std::span<const std::byte> content_bytes() {
    static const auto bytes = std::as_bytes(std::span{MINIMAL_CONTENT});
    return bytes;
}

}  // namespace

// ── V2 PFS send + receive round-trip ────────────────────────────────────────────────────────────

TEST_CASE("send_dm: v2 PFS round-trip", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<MessageSendStatus> statuses;
    std::vector<std::byte> captured_payload;

    callbacks sender_cbs;
    sender_cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };
    sender_cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                                   config::Namespace ns,
                                   std::vector<std::byte> payload,
                                   std::chrono::milliseconds,
                                   std::function<void(bool)> on_stored) {
        CHECK(ns == config::Namespace::Default);
        captured_payload = std::move(payload);
        on_stored(true);
    };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};

    recipient->devices.active_account_keys();
    auto [x25519_pub, mlkem_pub] = TestHelper::active_account_pubkeys(*recipient);
    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_cache(*sender, recip_sid, x25519_pub, mlkem_pub);

    auto msg_id = sender->send_dm(recip_sid, content_bytes(), clock_now_ms());
    CHECK(msg_id == 1);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::success);

    // Feed the captured payload into recipient to verify decryption.
    REQUIRE(!captured_payload.empty());
    SwarmMessage sm;
    sm.data = captured_payload;
    sm.hash = "send_test_hash";
    sm.timestamp = clock_now_ms();
    sm.expiry = clock_now_ms() + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    CHECK(received[0].version == 2);
    CHECK(received[0].pfs_encrypted);
    CHECK(std::ranges::equal(received[0].content, MINIMAL_CONTENT));
}

// ── V1 fallback (NAK, force_v2=false) ───────────────────────────────────────────────────────────

TEST_CASE("send_dm: v1 fallback on NAK", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<MessageSendStatus> statuses;
    std::vector<std::byte> captured_payload;

    callbacks sender_cbs;
    sender_cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };
    sender_cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                                   config::Namespace,
                                   std::vector<std::byte> payload,
                                   std::chrono::milliseconds,
                                   std::function<void(bool)> on_stored) {
        captured_payload = std::move(payload);
        on_stored(true);
    };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};

    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_nak(*sender, recip_sid);

    sender->send_dm(recip_sid, content_bytes(), clock_now_ms());

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::success);

    REQUIRE(!captured_payload.empty());
    SwarmMessage sm;
    sm.data = captured_payload;
    sm.hash = "v1_hash";
    sm.timestamp = clock_now_ms();
    sm.expiry = clock_now_ms() + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    CHECK(received[0].version == 1);
    CHECK_FALSE(received[0].pfs_encrypted);
}

// ── V2 non-PFS (force_v2=true, NAK) ────────────────────────────────────────────────────────────

TEST_CASE("send_dm: v2 non-PFS with force_v2", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<MessageSendStatus> statuses;
    std::vector<std::byte> captured_payload;

    callbacks sender_cbs;
    sender_cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };
    sender_cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                                   config::Namespace,
                                   std::vector<std::byte> payload,
                                   std::chrono::milliseconds,
                                   std::function<void(bool)> on_stored) {
        captured_payload = std::move(payload);
        on_stored(true);
    };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};

    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_nak(*sender, recip_sid);

    sender->send_dm(
            recip_sid, content_bytes(), clock_now_ms(), std::nullopt, 14 * 24h, /*force_v2=*/true);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::success);

    REQUIRE(!captured_payload.empty());
    SwarmMessage sm;
    sm.data = captured_payload;
    sm.hash = "nopfs_hash";
    sm.timestamp = clock_now_ms();
    sm.expiry = clock_now_ms() + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    CHECK(received[0].version == 2);
    CHECK_FALSE(received[0].pfs_encrypted);
}

// ── No network error (NAK, no send_to_swarm, no network) ───────────────────────────────────────

TEST_CASE("send_dm: no_network when no callback and no network", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };

    TempCore sender{cbs};
    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::no_network);
}

// ── No network, no cache → immediate no_network ────────────────────────────────────────────────

TEST_CASE("send_dm: no_network when no cache and no network", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };

    TempCore sender{cbs};

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    // No cache entry and no network → immediate no_network.
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0] == MessageSendStatus::no_network);
}

// ── send_to_swarm callback receives correct arguments ───────────────────────────────────────────

TEST_CASE("send_dm: send_to_swarm callback receives expected args", "[core][send_dm]") {
    config::Namespace captured_ns{};
    std::chrono::milliseconds captured_ttl{};
    std::array<std::byte, 33> captured_pubkey{};
    bool callback_called = false;

    callbacks cbs;
    cbs.send_to_swarm = [&](std::span<const std::byte, 33> pk,
                            config::Namespace ns,
                            std::vector<std::byte>,
                            std::chrono::milliseconds ttl,
                            std::function<void(bool)> on_stored) {
        std::ranges::copy(pk, captured_pubkey.begin());
        captured_ns = ns;
        captured_ttl = ttl;
        callback_called = true;
        on_stored(true);
    };

    TempCore sender{cbs};
    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    auto custom_ttl = std::chrono::milliseconds{7 * 24h};
    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms(), std::nullopt, custom_ttl);

    REQUIRE(callback_called);
    CHECK(captured_ns == config::Namespace::Default);
    CHECK(captured_ttl == custom_ttl);
    CHECK(std::ranges::equal(captured_pubkey, DUMMY_SID));
}

// ── Network error status ────────────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: network_error when store fails", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };
    cbs.send_to_swarm = [](std::span<const std::byte, 33>,
                           config::Namespace,
                           std::vector<std::byte>,
                           std::chrono::milliseconds,
                           std::function<void(bool)> on_stored) { on_stored(false); };

    TempCore sender{cbs};
    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::network_error);
}

// ── Monotonic message IDs ───────────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: message IDs are monotonically increasing", "[core][send_dm]") {
    callbacks cbs;
    cbs.send_to_swarm = [](auto, auto, auto, auto, auto on_stored) { on_stored(true); };

    TempCore sender{cbs};
    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    auto id1 = sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());
    auto id2 = sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());
    auto id3 = sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    CHECK(id1 == 1);
    CHECK(id2 == 2);
    CHECK(id3 == 3);
}

// ── Network fallback when send_to_swarm is not set ──────────────────────────────────────────────

TEST_CASE("send_dm: dispatches via network when send_to_swarm is not set", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };
    // Deliberately not setting send_to_swarm — should fall back to the network object.

    TempCore sender{cbs};
    auto mock_net = std::make_shared<MockNetwork>();
    sender->set_network(mock_net);

    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    // The sending status fires immediately; the network dispatch is async via MockNetwork.
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0] == MessageSendStatus::sending);

    // MockNetwork should have captured a store request.
    REQUIRE(mock_net->sent_requests.size() == 1);
    CHECK(mock_net->sent_requests[0].request.endpoint == "store");

    // Simulate a successful store response.
    mock_net->sent_requests[0].callback(true, false, 200, {}, "{}");

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[1] == MessageSendStatus::success);
}

// ── Content protobuf overload ───────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: Content overload round-trip", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<std::byte> captured_payload;

    callbacks sender_cbs;
    sender_cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                                   config::Namespace,
                                   std::vector<std::byte> payload,
                                   std::chrono::milliseconds,
                                   std::function<void(bool)> on_stored) {
        captured_payload = std::move(payload);
        on_stored(true);
    };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};

    recipient->devices.active_account_keys();
    auto [x25519_pub, mlkem_pub] = TestHelper::active_account_pubkeys(*recipient);
    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_cache(*sender, recip_sid, x25519_pub, mlkem_pub);

    auto ts = clock_now_ms();
    SessionProtos::Content content;
    content.mutable_datamessage()->set_body("hello from the Content overload");

    sender->send_dm(recip_sid, content, ts);

    REQUIRE(!captured_payload.empty());
    SwarmMessage sm;
    sm.data = captured_payload;
    sm.hash = "content_overload_hash";
    sm.timestamp = ts;
    sm.expiry = ts + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    SessionProtos::Content decoded;
    REQUIRE(decoded.ParseFromArray(
            received[0].content.data(), static_cast<int>(received[0].content.size())));
    CHECK(decoded.datamessage().body() == "hello from the Content overload");

    // An unset sigTimestamp is filled in from sent_timestamp.
    CHECK(decoded.sigtimestamp() == static_cast<uint64_t>(ts.time_since_epoch().count()));
}

TEST_CASE("send_dm: Content overload preserves a matching sigTimestamp", "[core][send_dm]") {
    std::vector<std::byte> captured_payload;

    callbacks cbs;
    cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                            config::Namespace,
                            std::vector<std::byte> payload,
                            std::chrono::milliseconds,
                            std::function<void(bool)> on_stored) {
        captured_payload = std::move(payload);
        on_stored(true);
    };

    TempCore sender{cbs};
    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    auto ts = clock_now_ms();
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    content.mutable_datamessage()->set_body("explicit timestamp");

    CHECK_NOTHROW(sender->send_dm(DUMMY_SID, content, ts));
    CHECK(!captured_payload.empty());
}

TEST_CASE("send_dm: Content overload rejects a mismatched sigTimestamp", "[core][send_dm]") {
    TempCore sender{};

    auto ts = clock_now_ms();
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()) + 5000);
    content.mutable_datamessage()->set_body("mismatched");

    CHECK_THROWS_AS(sender->send_dm(DUMMY_SID, content, ts), std::invalid_argument);
}

// ── Sends queued behind a PFS key fetch ─────────────────────────────────────────────────────────

TEST_CASE("send_dm: a send queued behind a key fetch is released when the fetch settles",
          "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;
    std::vector<PfsKeyFetch> fetches;
    std::vector<std::byte> captured;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s) { statuses.push_back(s); };
    cbs.pfs_keys_fetched = [&](std::span<const std::byte, 33>, PfsKeyFetch r) {
        fetches.push_back(r);
    };
    cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                            config::Namespace,
                            std::vector<std::byte> payload,
                            std::chrono::milliseconds,
                            std::function<void(bool)> on_stored) {
        captured = std::move(payload);
        on_stored(true);
    };

    TempCore sender{cbs};
    auto mock = std::make_shared<MockNetwork>();
    sender->set_network(mock);

    // Nothing cached for this recipient, so the send is queued behind a key fetch.
    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0] == MessageSendStatus::awaiting_keys);
    CHECK(captured.empty());
    REQUIRE(mock->sent_requests.size() == 1);
    CHECK(mock->sent_requests[0].request.endpoint == "retrieve");

    // A *failed* fetch must still release the send rather than stranding it forever.
    mock->sent_requests[0].callback(false, true, 0, {}, std::nullopt);

    REQUIRE(fetches.size() == 1);
    CHECK(fetches[0] == PfsKeyFetch::failed);
    CHECK(!captured.empty());
    REQUIRE(statuses.size() >= 2);
    CHECK(statuses.back() == MessageSendStatus::success);
}

TEST_CASE("send_dm: every send queued for one recipient is released by a single fetch",
          "[core][send_dm]") {
    std::vector<PfsKeyFetch> fetches;
    int stored = 0;

    callbacks cbs;
    cbs.pfs_keys_fetched = [&](std::span<const std::byte, 33>, PfsKeyFetch r) {
        fetches.push_back(r);
    };
    cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                            config::Namespace,
                            std::vector<std::byte>,
                            std::chrono::milliseconds,
                            std::function<void(bool)> on_stored) {
        stored++;
        on_stored(true);
    };

    TempCore sender{cbs};
    auto mock = std::make_shared<MockNetwork>();
    sender->set_network(mock);

    for (int i = 0; i < 3; i++)
        sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    CHECK(stored == 0);
    REQUIRE(!mock->sent_requests.empty());

    // Settling one fetch drains the whole queue for that recipient.
    mock->sent_requests[0].callback(false, true, 0, {}, std::nullopt);

    CHECK(stored == 3);
    CHECK(fetches.size() == 1);
}
