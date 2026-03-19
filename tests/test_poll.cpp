#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/config/encrypt.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>
#include <session/sqlite.hpp>

#include "test_helper.hpp"
#include "utils.hpp"

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

    auto test_keys = get_deterministic_test_keys();

    bool received = false;
    core::callbacks callbacks;
    callbacks.device_link_request = [&](int,
                                        const core::device::Info&,
                                        std::span<const std::string_view>) { received = true; };

    {
        core::Core core{callbacks, db_path, sqlite::argon2id_password{"test"}};
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

        // Prepare a valid encrypted link request message using the core's actual seed
        std::vector<unsigned char> outer_msg;
        {
            // Plaintext: {"I": <id>, "i": {"n": "test", "p": <pk>, "k": <ed_pk>}}
            std::vector<unsigned char> plaintext;
            oxenc::bt_dict_producer p;
            auto dev_id =
                    "0101010101010101010101010101010101010101010101010101010101010101"_hexbytes;
            p.append("I", dev_id);
            {
                auto sub = p.append_dict("i");
                sub.append("k", test_keys.ed_pk1);
                sub.append("n", "test device");
                sub.append("p", test_keys.curve_pk1);
            }
            auto p_span = p.span<unsigned char>();
            plaintext.assign(p_span.begin(), p_span.end());

            // Encrypt with the core's actual seed
            auto core_seed = core.globals.account_seed();
            auto seed_span = session::to_span(core_seed.buf).first(32);
            auto encrypted = config::encrypt(plaintext, seed_span, "link-request");

            // Outer: {"": "L", "L": <encrypted>}
            oxenc::bt_dict_producer outer;
            outer.append("", "L");
            outer.append("L", encrypted);
            auto outer_span = outer.span<unsigned char>();
            outer_msg.assign(outer_span.begin(), outer_span.end());
        }

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
        CHECK(core.globals.get_text("_last_hash_21") == "hash1");
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
