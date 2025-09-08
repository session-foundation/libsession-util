#include <fmt/core.h>
#include <session/network/routing/onion_request_router.hpp>
#include <sodium/randombytes.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <llarp/contact/router_id.hpp>
#include <nlohmann/json.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <session/curve25519.hpp>
#include <session/ed25519.hpp>
#include <session/network/key_types.hpp>
#include <session/onionreq/hop_encryption.hpp>
#include <tuple>

#include "utils.hpp"

using namespace session;
using namespace session::onionreq;
using namespace session::network;

namespace session::network {
    class TestOnionRequestRouter {
        public:
        static void set_paths(OnionRequestRouter& router, RequestCategory category, std::vector<OnionPath> paths) {
            router._paths.emplace(category, paths);
        }

        static uint16_t failure_count(OnionRequestRouter& router, RequestCategory category, std::string path_id) {
            for (auto& path : router._paths[category]) {
                if (path.id == path_id)
                    return path.failure_count;
            }

            return -1;
        }

        static void handle_transport_response(
            OnionRequestRouter& router,
            std::string path_id,
            Request original_request,
            std::shared_ptr<session::onionreq::Builder> builder,
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response_body,
            network_response_callback_t callback) {
            router._handle_transport_response(path_id, original_request, builder, success, timeout, status_code, std::move(headers), std::move(response_body), std::move(callback));
        }
    };

namespace {
    class TestSnodePool: public SnodePool, public CallTracker {
        public:
            TestSnodePool(config::SnodePoolConfig config, std::shared_ptr<oxen::quic::Loop> loop, network_fetcher_t direct_fetcher = 
                [](Request, network_response_callback_t){}) : SnodePool(std::move(config), std::move(loop), std::move(direct_fetcher)) {}

            void record_node_failure(const service_node& node, bool permanent = false) override {
                if (check_should_ignore_and_log_call("record_node_failure(node)"))
                    return;
                return SnodePool::record_node_failure(node, permanent);
            }

            void record_node_failure(const ed25519_pubkey& key, bool permanent = false) override {
                if (check_should_ignore_and_log_call("record_node_failure(key)"))
                    return;
                return SnodePool::record_node_failure(key, permanent);
            }

            void refresh_if_needed(
                const std::vector<service_node>& in_use_nodes,
                std::function<void()> on_refresh_complete = nullptr) override {
                if (check_should_ignore_and_log_call("refresh_if_needed"))
                    return;
                return SnodePool::refresh_if_needed(in_use_nodes, on_refresh_complete);
            }

            void get_swarm(
                session::network::x25519_pubkey swarm_pubkey,
                std::function<void(swarm::swarm_id_t, std::vector<service_node>)> callback) override {
                if (check_should_ignore_and_log_call("get_swarm"))
                    return;
                return SnodePool::get_swarm(swarm_pubkey, callback);
            }

            std::vector<service_node> get_unused_nodes(
                size_t count, const std::vector<service_node>& exclude = {}) override {
                if (check_should_ignore_and_log_call("get_unused_nodes"))
                    return {};
                return SnodePool::get_unused_nodes(count, exclude);
            }
    };

    class TestTransport: public ITransport, public CallTracker {
        public:
            void suspend() override { func_called("suspend"); };
            void resume(bool automatically_reconnect = true) override { func_called("resume"); };
            void close_connections() override { func_called("close_connections"); };

            ConnectionStatus get_status() const override { return ConnectionStatus::unknown; };
            void verify_connectivity(
                    service_node node,
                    std::chrono::milliseconds timeout,
                    const std::string& request_id,
                    std::function<void(bool success)> callback) override {
                func_called("verify_connectivity");
            };
            void add_failure_listener(
                    const ed25519_pubkey& pubkey, std::function<void()> listener) override { func_called("add_failure_listener"); };
            void remove_failure_listeners(const ed25519_pubkey& pubkey) override { func_called("remove_failure_listeners"); };

            void send_request(Request request, network_response_callback_t callback) override { func_called("send_request"); };
    };

    struct Result {
        bool success;
        bool timeout;
        int16_t status_code;
        std::vector<std::pair<std::string, std::string>> headers;
        std::optional<std::string> response;
    };
}   // namespace

TEST_CASE("Network", "[network][onion_request_router][handle_errors]") {
    config::SnodePoolConfig pool_config = {
        std::nullopt,
        std::chrono::minutes{5},
        std::chrono::minutes{5},
        false,
        network::opt::retry_delay{50ms, 200ms},
        opt::netid::Target::testnet,
        {},
        0,
        0,
        0,
        false
    };
    config::OnionRequestRouterConfig config = {
        network::opt::retry_delay{50ms, 200ms},
        50ms,
        3,
        3,
        10,
        true,
        true,
        {{RequestCategory::standard, 1}}
    };
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto target = service_node{ed_pk, oxen::quic::ipv4{"127.0.0.1"}, 20001, 30001, {2, 11, 0}, 0};
    auto target2 = service_node{ed_pk2, oxen::quic::ipv4{"127.0.0.1"}, 20002, 30002, {2, 11, 0}, 0};
    auto target3 = service_node{ed_pk2, oxen::quic::ipv4{"127.0.0.1"}, 20003, 30003, {2, 11, 0}, 0};
    auto target4 = service_node{ed_pk2, oxen::quic::ipv4{"127.0.0.1"}, 20004, 30004, {2, 11, 0}, 0};
    auto path = OnionPath{"Test", {target2, target3, target4}};
    auto request = Request{
        "AAAA",
        target,
        "info",
        to_vector("test"),
        RequestCategory::standard,
        0ms};
    auto builder = std::make_shared<session::onionreq::Builder>(request.destination, request.endpoint, path.nodes);
    Result result;

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop);
    auto transport = std::make_shared<TestTransport>();
    std::optional<OnionRequestRouter> router;

    // Check the handling of the codes which make no changes
    auto codes_with_no_changes = {400, 404, 406, 425};

    for (auto code : codes_with_no_changes) {
        snode_pool->reset_calls();
        router.emplace(config, loop, snode_pool, transport);
        TestOnionRequestRouter::set_paths(*router, RequestCategory::standard, {path});
        TestOnionRequestRouter::handle_transport_response(*router, "Test", request, builder, false, false, code, {}, std::nullopt, [&result](bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response) {
            result = {success, timeout, status_code, headers, response};
        });

        CHECK_FALSE(result.success);
        CHECK_FALSE(result.timeout);
        CHECK(result.status_code == code);
        CHECK_FALSE(result.response.has_value());
        CHECK(snode_pool->did_not_call("record_node_failure(node)"));
        CHECK(snode_pool->did_not_call("record_node_failure(key)"));
        CHECK(TestOnionRequestRouter::failure_count(*router, RequestCategory::standard, "Test") == 0);
    }
}
}
