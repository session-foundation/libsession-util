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
        // Return a dummy swarm
        std::vector<network::service_node> swarm;
        network::service_node node;
        node.remote_pubkey = network::ed25519_pubkey{};  // zeroed key
        swarm.push_back(node);
        callback(0, swarm);
    }
};

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

        // Build a valid link request from a second device sharing the same account seed.
        // The link request is encrypted with the account seed, so the receiving core can only
        // decrypt it if both devices share that seed.
        cleared_b32 seed_bytes;
        {
            auto seed_acc = core.globals.account_seed();
            std::ranges::copy(seed_acc.buf.first<32>(), seed_bytes.begin());
        }
        TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
        auto link_msg = linker->devices.build_link_request().message;
        const auto* p = reinterpret_cast<const unsigned char*>(link_msg.data());
        std::vector<unsigned char> outer_msg{p, p + link_msg.size()};

        // Prepare a mock response
        nlohmann::json response;
        response["results"] = nlohmann::json::array();
        nlohmann::json res_item;
        res_item["namespace"] = 21;
        res_item["messages"] = nlohmann::json::array();
        nlohmann::json msg_item;
        msg_item["data"] = oxenc::to_base64(outer_msg);
        msg_item["hash"] = "hash1";
        res_item["messages"].push_back(msg_item);
        response["results"].push_back(res_item);

        sent.callback(true, false, 200, {}, response.dump());

        // Verify last_hash was updated in DB
        CHECK(TestHelper::namespace_last_hash(core, 21) == "hash1");
        CHECK(received);

        // Poll again, should include last_hash
        mock_net->sent_requests.clear();
        TestHelper::poll(core);

        REQUIRE(mock_net->sent_requests.size() == 1);
        auto req_json2 = nlohmann::json::parse(*mock_net->sent_requests[0].request.body);
        CHECK(req_json2["params"]["last_hashes"]["21"] == "hash1");
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}
