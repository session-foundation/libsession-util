#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"

using namespace session;

class MockNetwork : public network::Network {
  public:
    MockNetwork() : network::Network(network::config::Config{}) {}

    struct SentRequest {
        network::Request request;
        network::network_response_callback_t callback;
    };
    std::vector<SentRequest> sent_requests;

    // The node returned by get_swarm; tests can change this to simulate swarm-member switches.
    network::service_node current_node;

    void send_request(
            network::Request request, network::network_response_callback_t callback) override {
        sent_requests.push_back({std::move(request), std::move(callback)});
    }

    void get_swarm(
            session::network::x25519_pubkey /*swarm_pubkey*/,
            bool /*ignore_strike_count*/,
            std::function<
                    void(network::swarm_id_t swarm_id, std::vector<network::service_node> swarm)>
                    callback) override {
        callback(0, {current_node});
    }
};

// Helpers to build a mock retrieve response carrying a single message in one namespace.
static nlohmann::json make_response(
        int16_t ns, std::vector<unsigned char> msg_data, std::string hash) {
    nlohmann::json response;
    response["results"] = nlohmann::json::array();
    nlohmann::json res_item;
    res_item["namespace"] = ns;
    res_item["messages"] = nlohmann::json::array();
    nlohmann::json msg_item;
    msg_item["data"] = oxenc::to_base64(msg_data);
    msg_item["hash"] = std::move(hash);
    res_item["messages"].push_back(msg_item);
    response["results"].push_back(res_item);
    return response;
}

TEST_CASE("Core automatic polling", "[core][poll]") {
    auto db_path = std::filesystem::temp_directory_path() / "test_poll.db";
    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);

    bool received = false;
    core::callbacks callbacks;
    callbacks.device_link_request = [&](int,
                                        const core::device::Info&,
                                        std::span<const std::string_view>) { received = true; };

    {
        core::Core core{db_path, callbacks};
        auto mock_net = std::make_shared<MockNetwork>();
        // Use a fixed non-zero pubkey for the node.
        mock_net->current_node.remote_pubkey[0] = 0x01;

        core.set_network(mock_net);

        // Trigger poll via TestHelper
        TestHelper::poll(core);

        REQUIRE(mock_net->sent_requests.size() == 1);
        auto& sent = mock_net->sent_requests[0];

        auto req_json = nlohmann::json::parse(*sent.request.body);
        CHECK(req_json["method"] == "retrieve");
        auto& params = req_json["params"];
        CHECK(params["pubkey"] == oxenc::to_hex(core.globals.session_id()));
        CHECK(params["namespaces"] == nlohmann::json::array({21, -21}));
        CHECK(params.contains("timestamp"));
        CHECK(params.contains("signature"));
        // No prior hash for this node yet, so no last_hashes in request.
        CHECK_FALSE(params.contains("last_hashes"));

        // Build a valid link request from a second device sharing the same account seed.
        cleared_b32 seed_bytes;
        {
            auto seed_acc = core.globals.account_seed();
            std::ranges::copy(seed_acc.buf.first<32>(), seed_bytes.begin());
        }
        TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
        auto link_msg = linker->devices.build_link_request().message;
        const auto* p = reinterpret_cast<const unsigned char*>(link_msg.data());
        std::vector<unsigned char> outer_msg{p, p + link_msg.size()};

        sent.callback(
                true, false, 200, {}, make_response(21, outer_msg, "hash1").dump());

        // Verify last_hash was stored under this specific node's pubkey.
        CHECK(TestHelper::namespace_last_hash(core, 21, mock_net->current_node.remote_pubkey) ==
              "hash1");
        CHECK(received);

        // Poll again with the same node — should include last_hash.
        mock_net->sent_requests.clear();
        TestHelper::poll(core);

        REQUIRE(mock_net->sent_requests.size() == 1);
        auto req_json2 = nlohmann::json::parse(*mock_net->sent_requests[0].request.body);
        CHECK(req_json2["params"]["last_hashes"]["21"] == "hash1");
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}

TEST_CASE("Polling uses per-node last_hash to avoid missing messages on swarm-member switch",
          "[core][poll]") {
    TempCore c;
    auto mock_net = std::make_shared<MockNetwork>();

    // Two distinct service nodes with different pubkeys.
    network::service_node node_a, node_b;
    node_a.remote_pubkey[0] = 0xAA;
    node_b.remote_pubkey[0] = 0xBB;

    c->set_network(mock_net);

    // ── First poll: node A, no prior state ──────────────────────────────────────
    mock_net->current_node = node_a;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto params =
                nlohmann::json::parse(*mock_net->sent_requests[0].request.body)["params"];
        // No prior hash for any node — must not send last_hashes.
        CHECK_FALSE(params.contains("last_hashes"));
    }
    // Respond with hash "xyz" from node A.
    mock_net->sent_requests[0].callback(
            true, false, 200, {}, make_response(21, {0x01}, "xyz").dump());
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_a.remote_pubkey) == "xyz");
    CHECK_FALSE(TestHelper::namespace_last_hash(*c, 21, node_b.remote_pubkey).has_value());

    // ── Second poll: still node A — must use A's stored hash ────────────────────
    mock_net->sent_requests.clear();
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto params =
                nlohmann::json::parse(*mock_net->sent_requests[0].request.body)["params"];
        CHECK(params["last_hashes"]["21"] == "xyz");
    }

    // ── Third poll: switch to node B — no stored hash for B, so request everything ──
    mock_net->sent_requests.clear();
    mock_net->current_node = node_b;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto params =
                nlohmann::json::parse(*mock_net->sent_requests[0].request.body)["params"];
        // B has no recorded hash — must not send last_hashes so we get everything.
        CHECK_FALSE(params.contains("last_hashes"));
    }
    // Respond with hash "zyx" from node B (the message that B happens to have seen first).
    mock_net->sent_requests[0].callback(
            true, false, 200, {}, make_response(21, {0x02}, "zyx").dump());
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_b.remote_pubkey) == "zyx");
    // A's hash is untouched.
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_a.remote_pubkey) == "xyz");

    // ── Fourth poll: back to node A — must still use A's hash, not B's ──────────
    mock_net->sent_requests.clear();
    mock_net->current_node = node_a;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto params =
                nlohmann::json::parse(*mock_net->sent_requests[0].request.body)["params"];
        CHECK(params["last_hashes"]["21"] == "xyz");
    }
}
