#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"

using namespace session;

// Helpers to build a mock batch response carrying a single message in the Devices result slot.
// _poll() sends a three-namespace batch (Default at index 0, Devices at index 1, AccountPubkeys
// at index 2) and processes results positionally, so msg_data/hash go in results[1]; the other
// slots are empty.  The ns parameter is accepted for readability at call sites but is otherwise
// unused.
static nlohmann::json make_response(
        int16_t /*ns*/, std::vector<std::byte> msg_data, std::string hash) {
    nlohmann::json msg_item;
    msg_item["data"] = oxenc::to_base64(msg_data);
    msg_item["hash"] = std::move(hash);

    nlohmann::json empty;
    empty["messages"] = nlohmann::json::array();
    nlohmann::json devices_body;
    devices_body["messages"] = nlohmann::json::array({std::move(msg_item)});

    nlohmann::json response;
    response["results"] = nlohmann::json::array(
            {nlohmann::json{{"code", 200}, {"body", empty}},
             nlohmann::json{{"code", 200}, {"body", std::move(devices_body)}},
             nlohmann::json{{"code", 200}, {"body", std::move(empty)}}});
    return response;
}

TEST_CASE("Core automatic polling", "[core][poll]") {
    bool received = false;
    core::callbacks cbs;
    cbs.device_link_request = [&](int,
                                  const core::device::Info&,
                                  std::span<const std::string_view>) { received = true; };

    TempCore core{cbs};
    auto mock_net = std::make_shared<MockNetwork>();
    // Use a fixed non-zero pubkey for the node.
    mock_net->current_node.remote_pubkey[0] = std::byte{0x01};

    core->set_network(mock_net);

    // Trigger poll via TestHelper
    TestHelper::poll(*core);

    REQUIRE(mock_net->sent_requests.size() == 1);
    auto& sent = mock_net->sent_requests[0];

    CHECK(sent.request.endpoint == "batch");
    auto batch_json = parse_json(*sent.request.body);
    auto& reqs = batch_json["requests"];
    REQUIRE(reqs.size() == 3);
    // Subrequest 0: Default (ns 0) — requires auth.
    CHECK(reqs[0]["method"] == "retrieve");
    CHECK(reqs[0]["params"]["namespace"] == 0);
    CHECK(reqs[0]["params"].contains("signature"));
    // Subrequest 1: Devices (ns 21) — requires auth.
    CHECK(reqs[1]["method"] == "retrieve");
    auto& params = reqs[1]["params"];
    CHECK(params["pubkey"] == oxenc::to_hex(core->globals.session_id()));
    CHECK(params["namespace"] == 21);
    CHECK(params.contains("pubkey_ed25519"));
    CHECK(params.contains("timestamp"));
    CHECK(params.contains("signature"));
    // No prior hash for this node yet, so no last_hash in any subrequest.
    CHECK_FALSE(params.contains("last_hash"));
    // Subrequest 2: AccountPubkeys (ns -21) — no auth required.
    CHECK(reqs[2]["method"] == "retrieve");
    CHECK(reqs[2]["params"]["namespace"] == -21);
    CHECK_FALSE(reqs[2]["params"].contains("signature"));

    // Build a valid link request from a second device sharing the same account seed.
    cleared_b32 seed_bytes;
    {
        auto seed_acc = core->globals.account_seed();
        std::ranges::copy(std::as_bytes(seed_acc.seed()), seed_bytes.begin());
    }
    TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
    auto outer_msg = linker->devices.build_link_request().message;

    sent.callback(true, false, 200, {}, make_response(21, outer_msg, "hash1").dump());

    // Verify last_hash was stored under this specific node's pubkey.
    CHECK(TestHelper::namespace_last_hash(*core, 21, mock_net->current_node.remote_pubkey) ==
          "hash1");
    CHECK(received);

    // Poll again with the same node — should include last_hash in the Devices subrequest.
    mock_net->sent_requests.clear();
    TestHelper::poll(*core);

    REQUIRE(mock_net->sent_requests.size() == 1);
    auto batch_json2 = parse_json(*mock_net->sent_requests[0].request.body);
    CHECK(batch_json2["requests"][1]["params"]["last_hash"] == "hash1");
}

TEST_CASE(
        "Polling uses per-node last_hash to avoid missing messages on swarm-member switch",
        "[core][poll]") {
    TempCore c;
    auto mock_net = std::make_shared<MockNetwork>();

    // Two distinct service nodes with different pubkeys.
    network::service_node node_a, node_b;
    node_a.remote_pubkey[0] = std::byte{0xAA};
    node_b.remote_pubkey[0] = std::byte{0xBB};

    c->set_network(mock_net);

    // ── First poll: node A, no prior state ──────────────────────────────────────
    mock_net->current_node = node_a;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = parse_json(
                *mock_net->sent_requests[0].request.body)["requests"][1]["params"];
        // No prior hash for any node — must not send last_hash.
        CHECK_FALSE(p.contains("last_hash"));
    }
    // Respond with hash "xyz" from node A.
    mock_net->sent_requests[0].callback(
            true, false, 200, {}, make_response(21, {std::byte{0x01}}, "xyz").dump());
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_a.remote_pubkey) == "xyz");
    CHECK_FALSE(TestHelper::namespace_last_hash(*c, 21, node_b.remote_pubkey).has_value());

    // ── Second poll: still node A — must use A's stored hash ────────────────────
    mock_net->sent_requests.clear();
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = parse_json(
                *mock_net->sent_requests[0].request.body)["requests"][1]["params"];
        CHECK(p["last_hash"] == "xyz");
    }

    // ── Third poll: switch to node B — no stored hash for B, so request everything ──
    mock_net->sent_requests.clear();
    mock_net->current_node = node_b;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = parse_json(
                *mock_net->sent_requests[0].request.body)["requests"][1]["params"];
        // B has no recorded hash — must not send last_hash so we get everything.
        CHECK_FALSE(p.contains("last_hash"));
    }
    // Respond with hash "zyx" from node B (the message that B happens to have seen first).
    mock_net->sent_requests[0].callback(
            true, false, 200, {}, make_response(21, {std::byte{0x02}}, "zyx").dump());
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_b.remote_pubkey) == "zyx");
    // A's hash is untouched.
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_a.remote_pubkey) == "xyz");

    // ── Fourth poll: back to node A — must still use A's hash, not B's ──────────
    mock_net->sent_requests.clear();
    mock_net->current_node = node_a;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = parse_json(
                *mock_net->sent_requests[0].request.body)["requests"][1]["params"];
        CHECK(p["last_hash"] == "xyz");
    }
}
