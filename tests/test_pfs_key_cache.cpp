#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace std::literals;

// Wraps a single bt-dict message payload as a mock AccountPubkeys retrieve response.
static nlohmann::json make_pubkey_response(std::span<const std::byte> msg_data) {
    nlohmann::json resp;
    resp["results"] = nlohmann::json::array();
    nlohmann::json res_item;
    res_item["namespace"] = static_cast<int16_t>(config::Namespace::AccountPubkeys);
    res_item["messages"] = nlohmann::json::array();
    nlohmann::json msg_item;
    msg_item["data"] = oxenc::to_base64(
            std::string_view{reinterpret_cast<const char*>(msg_data.data()), msg_data.size()});
    res_item["messages"].push_back(msg_item);
    resp["results"].push_back(res_item);
    return resp;
}

TEST_CASE("prefetch_pfs_keys throws without network", "[core][pfs]") {
    TempCore c;
    TempCore remote;
    auto session_id = remote->globals.session_id();
    std::array<unsigned char, 33> sid;
    std::ranges::copy(session_id, sid.begin());
    CHECK_THROWS_AS(c->prefetch_pfs_keys(sid), std::logic_error);
}

TEST_CASE("prefetch_pfs_keys fetches and caches remote account pubkeys", "[core][pfs]") {
    TempCore c;
    auto mock_net = std::make_shared<MockNetwork>();
    c->set_network(mock_net);

    // Build a "remote" account whose pubkeys we want to fetch.
    TempCore remote;
    auto remote_msg = remote->devices.build_account_pubkey_message();

    auto session_id_span = remote->globals.session_id();
    std::array<unsigned char, 33> sid;
    std::ranges::copy(session_id_span, sid.begin());

    SECTION("Fetches and stores pubkeys when cache is absent") {
        c->prefetch_pfs_keys(sid);

        REQUIRE(mock_net->sent_requests.size() == 1);
        auto req = nlohmann::json::parse(*mock_net->sent_requests[0].request.body);
        CHECK(req["method"] == "retrieve");
        CHECK(req["params"]["pubkey"] == oxenc::to_hex(sid));
        CHECK(req["params"]["namespaces"] ==
              nlohmann::json::array({static_cast<int16_t>(config::Namespace::AccountPubkeys)}));

        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());

        auto entry = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(entry.has_value());
        // fetched_at should be close to now.
        auto age = clock_now_s() - from_epoch_s(entry->fetched_at);
        CHECK(age >= 0s);
        CHECK(age < 5s);

        // The stored pubkeys must match those from the remote's active account key.
        auto [expected_x25519, expected_mlkem768] = TestHelper::active_account_pubkeys(*remote);
        CHECK(entry->pubkey_x25519 == expected_x25519);
        CHECK(entry->pubkey_mlkem768 == expected_mlkem768);
    }

    SECTION("Skips fetch when cache is fresh") {
        // First fetch: populates the cache.
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        REQUIRE(TestHelper::pfs_cache_entry(*c, sid).has_value());
        mock_net->sent_requests.clear();

        // Second fetch within PFS_KEY_FRESH_DURATION: must not send another request.
        c->prefetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.empty());
    }

    SECTION("Re-fetches when cache is stale (older than PFS_KEY_FRESH_DURATION)") {
        // First fetch.
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        mock_net->sent_requests.clear();

        // Advance clock past the fresh threshold.
        ScopedClockOffset stale{core::Core::PFS_KEY_FRESH_DURATION + 1s};
        c->prefetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.size() == 1);
    }
}

TEST_CASE("prefetch_pfs_keys handles malformed responses gracefully", "[core][pfs]") {
    TempCore c;
    auto mock_net = std::make_shared<MockNetwork>();
    c->set_network(mock_net);

    TempCore remote;
    auto session_id_span = remote->globals.session_id();
    std::array<unsigned char, 33> sid;
    std::ranges::copy(session_id_span, sid.begin());

    SECTION("Garbage bt-dict data: no cache entry written") {
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);

        nlohmann::json bad_response;
        bad_response["results"] = nlohmann::json::array();
        nlohmann::json res_item;
        res_item["namespace"] = static_cast<int16_t>(config::Namespace::AccountPubkeys);
        res_item["messages"] = nlohmann::json::array();
        nlohmann::json msg_item;
        // "not a bt-dict" is valid base64 but not a valid bt-dict.
        msg_item["data"] = oxenc::to_base64("not a bt-dict");
        res_item["messages"].push_back(msg_item);
        bad_response["results"].push_back(res_item);

        // Must not throw or crash; cache must remain empty.
        mock_net->sent_requests[0].callback(true, false, 200, {}, bad_response.dump());
        CHECK_FALSE(TestHelper::pfs_cache_entry(*c, sid).has_value());
    }

    SECTION("Bad signature: no cache entry written") {
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);

        // Build a valid-looking message but sign it with the wrong key (our own account).
        auto wrong_msg = c->devices.build_account_pubkey_message();
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(wrong_msg).dump());
        CHECK_FALSE(TestHelper::pfs_cache_entry(*c, sid).has_value());
    }

    SECTION("Network failure: no cache entry written") {
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);

        mock_net->sent_requests[0].callback(false, false, 0, {}, std::nullopt);
        CHECK_FALSE(TestHelper::pfs_cache_entry(*c, sid).has_value());
    }
}
