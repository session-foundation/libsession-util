#include <fmt/core.h>
#include <session/network/session_network_old.h>
#include <sodium/randombytes.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <llarp/contact/router_id.hpp>
#include <nlohmann/json.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <session/curve25519.hpp>
#include <session/ed25519.hpp>
#include <session/network/session_network_old.hpp>
#include <session/onionreq/hop_encryption.hpp>
#include <session/network/key_types.hpp>
#include <tuple>

#include "utils.hpp"

using namespace session;
using namespace session::onionreq;
using namespace session::network;

namespace {
struct TestServer {
    std::shared_ptr<oxen::quic::Loop> loop;
    std::shared_ptr<oxen::quic::Endpoint> endpoint;
    service_node node;

    ~TestServer() {
        loop->call_get([&]() { endpoint->close_conns(); });
        endpoint.reset();
        loop.reset();
    }
};

struct Result {
    bool success;
    bool timeout;
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;
    std::optional<std::string> response;
};

service_node test_node(
        const std::vector<unsigned char> ed_pk, const uint16_t index, const bool unique_ip = true) {
    return service_node{
            ed_pk,
            {2, 8, 0},
            INVALID_SWARM_ID,
            (unique_ip ? fmt::format("0.0.0.{}", index) : "1.1.1.1"),
            index};
}

std::optional<service_node> node_for_destination(network_destination destination) {
    if (auto* dest = std::get_if<service_node>(&destination))
        return *dest;

    return std::nullopt;
}

}  // namespace

namespace session::network {
class TestNetwork : public Network {
  public:
    std::unordered_map<std::string, int> call_counts;
    std::mutex call_counts_mutex;
    std::condition_variable call_cv;

    std::vector<std::string> calls_to_ignore;
    std::chrono::milliseconds retry_delay_value = 0ms;
    std::optional<std::optional<onion_path>> find_valid_path_response;
    std::optional<request_info> last_request_info;
    bool handle_onion_requests_as_plaintext = false;

    TestNetwork(
            std::optional<fs::path> cache_path,
            bool use_testnet,
            bool single_path_mode,
            bool pre_build_paths) :
            Network{cache_path, use_testnet, single_path_mode, pre_build_paths} {
        paths_changed = [this](std::vector<std::vector<service_node>>) {
            func_called("paths_changed");
        };
    }

    oxen::quic::Loop& get_loop() { return *loop; }
    std::shared_ptr<oxen::quic::Loop> get_loop_ptr() { return loop; }

    void set_suspended(bool suspended_) { suspended = suspended_; }

    bool get_suspended() { return suspended; }

    ConnectionStatus get_status() { return status; }

    void set_endpoint(oxen::quic::Address address) {
        loop->call([this, address]() {
            endpoint = oxen::quic::Endpoint::endpoint(
                    *loop,
                    address,
                    oxen::quic::opt::alpns{"oxenstorage"},
                    oxen::quic::opt::disable_mtu_discovery{});
        });
    }

    void set_snode_cache(std::vector<service_node> cache) {
        // Need to set the `last_snode_cache_update` to `10s` ago because otherwise it'll be
        // considered invalid when checking the cache validity
        snode_cache = cache;
        last_snode_cache_update = (std::chrono::system_clock::now() - 10s);
    }

    void set_unused_connections(std::deque<connection_info> unused_connections_) {
        unused_connections = unused_connections_;
    }

    void set_in_progress_connections(
            std::unordered_map<std::string, service_node> in_progress_connections_) {
        in_progress_connections = in_progress_connections_;
    }

    void add_path(PathType path_type, std::vector<service_node> nodes) {
        paths[path_type].emplace_back(
                onion_path{"Test", {nodes[0], nullptr, nullptr, nullptr}, nodes, 0});
    }

    void set_paths(PathType path_type, std::vector<onion_path> paths_) {
        paths[path_type] = paths_;
    }

    std::vector<onion_path> get_paths(PathType path_type) { return paths[path_type]; }

    void set_all_swarms(std::vector<std::pair<swarm_id_t, std::vector<service_node>>> all_swarms_) {
        all_swarms = all_swarms_;
    }

    void set_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            swarm_id_t swarm_id,
            std::vector<service_node> swarm) {
        swarm_cache[swarm_pubkey.hex()] = {swarm_id, swarm};
    }

    std::pair<swarm_id_t, std::vector<service_node>> get_cached_swarm(
            session::network::x25519_pubkey swarm_pubkey) {
        return swarm_cache[swarm_pubkey.hex()];
    }

    swarm_id_t get_swarm_id(std::string swarm_pubkey_hex) {
        if (swarm_pubkey_hex.size() == 66)
            swarm_pubkey_hex = swarm_pubkey_hex.substr(2);

        auto pk = x25519_pubkey::from_hex(swarm_pubkey_hex);
        std::promise<swarm_id_t> prom;
        get_swarm(pk, [&prom](swarm_id_t result, std::vector<service_node>) {
            prom.set_value(result);
        });
        return prom.get_future().get();
    }

    void set_failure_count(service_node node, uint8_t failure_count) {
        snode_failure_counts[node.to_string()] = failure_count;
    }

    uint8_t get_failure_count(service_node node) {
        return snode_failure_counts.try_emplace(node.to_string(), 0).first->second;
    }

    uint8_t get_failure_count(PathType path_type, onion_path path) {
        auto current_paths = paths[path_type];
        auto target_path = std::find_if(
                current_paths.begin(), current_paths.end(), [&path](const auto& path_it) {
                    return path_it.nodes[0] == path.nodes[0];
                });

        if (target_path != current_paths.end())
            return target_path->failure_count;

        return 0;
    }

    void set_path_build_queue(std::deque<PathType> path_build_queue_) {
        path_build_queue = path_build_queue_;
    }

    std::deque<PathType> get_path_build_queue() { return path_build_queue; }

    void set_path_build_failures(int path_build_failures_) {
        path_build_failures = path_build_failures_;
    }

    int get_path_build_failures() { return path_build_failures; }

    void set_unused_nodes(std::vector<service_node> unused_nodes_) { unused_nodes = unused_nodes_; }

    std::vector<service_node> get_unused_nodes() { return Network::get_unused_nodes(); }

    std::vector<service_node> get_unused_nodes_value() { return unused_nodes; }

    void add_pending_request(PathType path_type, request_info info) {
        request_queue[path_type].emplace_back(
                std::move(info),
                [](bool,
                   bool,
                   int16_t,
                   std::vector<std::pair<std::string, std::string>>,
                   std::optional<std::string>) {});
    }

    std::shared_ptr<TestServer> create_test_node(uint16_t port) {
        oxen::quic::opt::inbound_alpns server_alpns{"oxenstorage"};
        auto server_key_pair =
                session::ed25519::ed25519_key_pair(to_span(fmt::format("{:032}", port)));
        auto server_x25519_pubkey = session::curve25519::to_curve25519_pubkey(
                {server_key_pair.first.data(), server_key_pair.first.size()});
        auto server_x25519_seckey = session::curve25519::to_curve25519_seckey(
                {server_key_pair.second.data(), server_key_pair.second.size()});
        auto creds = oxen::quic::GNUTLSCreds::make_from_ed_seckey(
                to_string_view(server_key_pair.second));
        oxen::quic::Address server_local{port};
        session::onionreq::HopEncryption decryptor{
                x25519_seckey::from_bytes(to_span(server_x25519_seckey)),
                x25519_pubkey::from_bytes(to_span(server_x25519_pubkey)),
                true};

        auto server_cb = [&](oxen::quic::message m) {
            nlohmann::json response{{"hf", {1, 0, 0}}, {"t", 1234567890}, {"version", {2, 8, 0}}};
            m.respond(response.dump(), false);
        };

        auto onion_cb = [&](oxen::quic::message m) {
            nlohmann::json response{{"hf", {2, 0, 0}}, {"t", 1234567890}, {"version", {2, 8, 0}}};
            m.respond(response.dump(), false);
        };

        oxen::quic::stream_constructor_callback server_constructor =
                [&](oxen::quic::Connection& c, oxen::quic::Endpoint& e, std::optional<int64_t>) {
                    auto s = e.loop.make_shared<oxen::quic::BTRequestStream>(c, e);
                    s->register_handler("info", server_cb);
                    s->register_handler("onion_req", onion_cb);
                    return s;
                };

        auto loop = std::make_shared<oxen::quic::Loop>();
        auto endpoint = oxen::quic::Endpoint::endpoint(*loop, server_local, server_alpns);
        endpoint->listen(creds, server_constructor);

        auto node = service_node{
                to_string_view(server_key_pair.first),
                {2, 8, 0},
                INVALID_SWARM_ID,
                "127.0.0.1"s,
                endpoint->local().port()};

        return std::make_shared<TestServer>(loop, endpoint, node);
    }

    std::pair<std::vector<std::shared_ptr<TestServer>>, onion_path> create_test_path() {
        std::vector<std::shared_ptr<TestServer>> path_servers;
        std::vector<service_node> path_nodes;
        path_nodes.reserve(3);

        for (auto i = 0; i < 3; ++i) {
            path_servers.emplace_back(create_test_node(static_cast<uint16_t>(5360 + i)));
            path_nodes.emplace_back(path_servers[i]->node);
        }

        std::promise<std::pair<connection_info, std::optional<std::string>>> prom;
        establish_connection(
                "Test",
                path_nodes[0],
                3s,
                [&prom](connection_info conn_info, std::optional<std::string> error) {
                    prom.set_value({std::move(conn_info), error});
                });

        // Wait for the result to be set
        auto result = prom.get_future().get();
        REQUIRE(result.first.is_valid());
        return {path_servers, onion_path{"Test", std::move(result.first), path_nodes, uint8_t{0}}};
    }

    // Overridden Functions

    std::chrono::milliseconds retry_delay(int, std::chrono::milliseconds) override {
        return retry_delay_value;
    }

    void update_disk_cache_throttled(bool force_immediate_write) override {
        if (check_should_ignore_and_log_call("update_disk_cache_throttled"))
            return;

        Network::update_disk_cache_throttled(force_immediate_write);
    }

    void establish_and_store_connection(std::string request_id) override {
        if (check_should_ignore_and_log_call("establish_and_store_connection"))
            return;

        Network::establish_and_store_connection(request_id);
    }

    void refresh_snode_cache(std::optional<std::string> existing_request_id) override {
        if (check_should_ignore_and_log_call("refresh_snode_cache"))
            return;

        Network::refresh_snode_cache(existing_request_id);
    }

    void build_path(std::string path_id, PathType path_type) override {
        if (check_should_ignore_and_log_call("build_path"))
            return;

        Network::build_path(path_id, path_type);
    }

    std::optional<onion_path> find_valid_path(
            request_info info, std::vector<onion_path> paths) override {
        if (check_should_ignore_and_log_call("find_valid_path"))
            return std::nullopt;

        if (find_valid_path_response)
            return *find_valid_path_response;

        return Network::find_valid_path(info, paths);
    }

    void check_request_queue_timeouts(std::optional<std::string> request_timeout_id) override {
        if (check_should_ignore_and_log_call("check_request_queue_timeouts"))
            return;

        Network::check_request_queue_timeouts(request_timeout_id);
    }

    void _send_onion_request(
            request_info info, network_response_callback_t handle_response) override {
        last_request_info = info;

        if (check_should_ignore_and_log_call("_send_onion_request"))
            return;

        Network::_send_onion_request(std::move(info), std::move(handle_response));
    }

    // Exposing Private Functions

    void establish_connection(
            std::string request_id,
            service_node target,
            std::optional<std::chrono::milliseconds> timeout,
            std::function<void(connection_info info, std::optional<std::string> error)> callback) {
        Network::establish_connection(request_id, target, timeout, std::move(callback));
    }

    void build_path_if_needed(PathType path_type, bool found_valid_path) override {
        return Network::build_path_if_needed(path_type, found_valid_path);
    }

    void send_request(
            request_info info, connection_info conn, network_response_callback_t handle_response) {
        Network::send_request(info, conn, std::move(handle_response));
    }

    void handle_errors(
            request_info info,
            connection_info conn_info,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response,
            std::optional<network_response_callback_t> handle_response) override {
        func_called("handle_errors");
        Network::handle_errors(
                info,
                conn_info,
                timeout,
                status_code,
                headers,
                response,
                std::move(handle_response));
    }

    std::tuple<
            int16_t,
            std::vector<std::pair<std::string, std::string>>,
            std::optional<std::string>>
    process_v3_onion_response(session::onionreq::Builder builder, std::string response) override {
        func_called("process_v3_onion_response");

        if (handle_onion_requests_as_plaintext)
            return {200, {}, response};

        return Network::process_v3_onion_response(builder, response);
    }

    std::tuple<
            int16_t,
            std::vector<std::pair<std::string, std::string>>,
            std::optional<std::string>>
    process_v4_onion_response(session::onionreq::Builder builder, std::string response) override {
        func_called("process_v4_onion_response");

        if (handle_onion_requests_as_plaintext)
            return {200, {}, response};

        return Network::process_v4_onion_response(builder, response);
    }

    // Mocking Functions

    template <typename... Strings>
    void ignore_calls_to(Strings&&... __args) {
        (calls_to_ignore.emplace_back(std::forward<Strings>(__args)), ...);
    }

    bool check_should_ignore_and_log_call(const std::string& name) {
        func_called(name);

        return std::find(calls_to_ignore.begin(), calls_to_ignore.end(), name) !=
               calls_to_ignore.end();
    }

    void func_called(const std::string& name) {
        bool notify = false;
        {
            std::lock_guard<std::mutex> lock(call_counts_mutex);
            ++call_counts[name];
            notify = true;
        }

        if (notify)
            call_cv.notify_all();
    }

    void reset_calls() {
        std::lock_guard<std::mutex> lock_counts(call_counts_mutex);
        call_counts.clear();
    }

    int get_call_count(const std::string& name) {
        std::lock_guard<std::mutex> lock(call_counts_mutex);
        auto it = call_counts.find(name);
        return (it != call_counts.end()) ? it->second : 0;
    }

    bool called(const std::string& name, int times = 1) { return (get_call_count(name) >= times); }

    [[nodiscard]] bool called(
            const std::string& name, std::chrono::milliseconds timeout, int times = 1) {
        if (times <= 0)
            times = 1;

        std::unique_lock<std::mutex> lock(call_counts_mutex);

        auto predicate = [&]() {
            auto it = call_counts.find(name);
            return (it != call_counts.end() && it->second >= times);
        };

        return call_cv.wait_for(lock, timeout, predicate);
    }

    bool did_not_call(const std::string& name) {
        std::lock_guard<std::mutex> lock(call_counts_mutex);
        return !call_counts.contains(name);
    }

    [[nodiscard]] bool did_not_call(const std::string& name, std::chrono::milliseconds duration) {
        std::unique_lock<std::mutex> lock(call_counts_mutex);
        auto predicate = [&]() { return call_counts.contains(name); };

        if (predicate())
            return false;  // Already called

        bool was_called_during_wait = call_cv.wait_for(lock, duration, predicate);
        return !was_called_during_wait;
    }
};
}  // namespace session::network

TEST_CASE("Network", "[network][parse_url]") {
    auto [proto1, host1, port1, path1] = parse_url("HTTPS://example.com/test");
    auto [proto2, host2, port2, path2] = parse_url("http://example2.com:1234/test/123456");
    auto [proto3, host3, port3, path3] = parse_url("https://example3.com");
    auto [proto4, host4, port4, path4] = parse_url("https://example4.com/test?value=test");

    CHECK(proto1 == "https://");
    CHECK(proto2 == "http://");
    CHECK(proto3 == "https://");
    CHECK(proto4 == "https://");
    CHECK(host1 == "example.com");
    CHECK(host2 == "example2.com");
    CHECK(host3 == "example3.com");
    CHECK(host4 == "example4.com");
    CHECK(port1.value_or(9999) == 9999);
    CHECK(port2.value_or(9999) == 1234);
    CHECK(port3.value_or(9999) == 9999);
    CHECK(port4.value_or(9999) == 9999);
    CHECK(path1.value_or("NULL") == "/test");
    CHECK(path2.value_or("NULL") == "/test/123456");
    CHECK(path3.value_or("NULL") == "NULL");
    CHECK(path4.value_or("NULL") == "/test?value=test");
}

TEST_CASE("Network", "[network][handle_errors]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;
    auto x_pk_hex = "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72";
    auto target = test_node(ed_pk, 0);
    auto target2 = test_node(ed_pk2, 1);
    auto target3 = test_node(ed_pk2, 2);
    auto target4 = test_node(ed_pk2, 3);
    auto path =
            onion_path{"Test", {target, nullptr, nullptr, nullptr}, {target, target2, target3}, 0};
    auto mock_request = request_info{
            "AAAA",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            std::nullopt,
            PathType::standard,
            0ms,
            std::nullopt,
            std::chrono::system_clock::now(),
            std::nullopt,
            true};
    Result result;
    std::optional<TestNetwork> network;

    // Check the handling of the codes which make no changes
    auto codes_with_no_changes = {400, 404, 406, 425};

    for (auto code : codes_with_no_changes) {
        network.emplace(std::nullopt, true, true, false);
        network->set_suspended(true);  // Make no requests in this test
        network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
        network->set_paths(PathType::standard, {path});
        network->handle_errors(
                mock_request,
                {target, nullptr, nullptr, nullptr},
                false,
                code,
                {},
                std::nullopt,
                [&result](
                        bool success,
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
        CHECK(network->get_failure_count(target) == 0);
        CHECK(network->get_failure_count(target2) == 0);
        CHECK(network->get_failure_count(target3) == 0);
        CHECK(network->get_failure_count(PathType::standard, path) == 0);
    }

    // Check general error handling (first failure)
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->set_paths(PathType::standard, {path});
    network->handle_errors(
            mock_request,
            {target, nullptr, nullptr, nullptr},
            false,
            500,
            {},
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(network->get_failure_count(target) == 0);
    CHECK(network->get_failure_count(target2) == 0);
    CHECK(network->get_failure_count(target3) == 0);
    CHECK(network->get_failure_count(PathType::standard, path) == 1);

    // Check general error handling with no response (too many path failures)
    path = onion_path{"Test", {target, nullptr, nullptr, nullptr}, {target, target2, target3}, 9};
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->set_paths(PathType::standard, {path});
    network->handle_errors(
            mock_request,
            {target, nullptr, nullptr, nullptr},
            false,
            500,
            {},
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK_FALSE(result.response.has_value());
    CHECK(network->get_failure_count(target) == 3);                    // Guard node dropped
    CHECK(network->get_failure_count(target2) == 1);                   // Other nodes incremented
    CHECK(network->get_failure_count(target3) == 1);                   // Other nodes incremented
    CHECK(network->get_failure_count(PathType::standard, path) == 0);  // Path dropped and reset

    // Check general error handling with a path and specific node failure
    path = onion_path{"Test", {target, nullptr, nullptr, nullptr}, {target, target2, target3}, 0};
    auto response = std::string{"Next node not found: "} + ed25519_pubkey::from_bytes(ed_pk2).hex();
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->set_snode_cache({target, target2, target3, target4});
    network->set_unused_nodes({target4});
    network->set_paths(PathType::standard, {path});
    network->handle_errors(
            mock_request,
            {target, nullptr, nullptr, nullptr},
            false,
            500,
            {},
            response,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(result.response == response);
    CHECK(network->get_failure_count(target) == 0);
    CHECK(network->get_failure_count(target2) == 3);  // Node will have been dropped
    CHECK(network->get_failure_count(target3) == 0);
    CHECK(network->get_paths(PathType::standard).front().nodes[1] != target2);
    CHECK(network->get_failure_count(PathType::standard, path) ==
          1);  // Incremented because conn_info is invalid

    // Check a 421 with no swarm data throws (no good way to handle this case)
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->set_paths(PathType::standard, {path});
    network->handle_errors(
            mock_request,
            {target, nullptr, nullptr, nullptr},
            false,
            421,
            {},
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 421);
    CHECK(network->get_failure_count(target) == 0);
    CHECK(network->get_failure_count(target2) == 0);
    CHECK(network->get_failure_count(target3) == 0);
    CHECK(network->get_failure_count(PathType::standard, path) == 1);

    // Check a non redirect 421 triggers a retry using a different node
    auto mock_request2 = request_info{
            "BBBB",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            std::nullopt,
            std::chrono::system_clock::now(),
            std::nullopt,
            true};
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->set_swarm(x25519_pubkey::from_hex(x_pk_hex), 1, {target, target2, target3});
    network->set_paths(PathType::standard, {path});
    network->reset_calls();
    network->handle_errors(
            mock_request2,
            {target, nullptr, nullptr, nullptr},
            false,
            421,
            {},
            std::nullopt,
            [](bool,
               bool,
               int16_t,
               std::vector<std::pair<std::string, std::string>>,
               std::optional<std::string>) {});
    CHECK(network->called("_send_onion_request", 100ms));
    REQUIRE(network->last_request_info.has_value());
    CHECK(node_for_destination(network->last_request_info->destination) !=
          node_for_destination(mock_request2.destination));

    // Check that when a retry request of a 421 receives it's own 421 that it tries
    // to update the snode cache
    auto mock_request3 = request_info{
            "BBBB",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            std::nullopt,
            std::chrono::system_clock::now(),
            request_info::RetryReason::redirect,
            true};
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to(
            "_send_onion_request", "update_disk_cache_throttled", "refresh_snode_cache");
    network->set_paths(PathType::standard, {path});
    network->handle_errors(
            mock_request3,
            {target, nullptr, nullptr, nullptr},
            false,
            421,
            {},
            std::nullopt,
            [](bool,
               bool,
               int16_t,
               std::vector<std::pair<std::string, std::string>>,
               std::optional<std::string>) {});
    CHECK(network->called("refresh_snode_cache", 100ms));

    // Check when the retry after refreshing the snode cache due to a 421 receives it's own 421 it
    // is handled like any other error
    auto mock_request4 = request_info{
            "BBBB",
            target,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            std::nullopt,
            std::chrono::system_clock::now(),
            request_info::RetryReason::redirect_swarm_refresh,
            true};
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->set_paths(PathType::standard, {path});
    network->handle_errors(
            mock_request4,
            {target, nullptr, nullptr, nullptr},
            false,
            421,
            {},
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 421);
    CHECK(network->get_failure_count(target) == 0);
    CHECK(network->get_failure_count(target2) == 0);
    CHECK(network->get_failure_count(target3) == 0);
    CHECK(network->get_failure_count(PathType::standard, path) == 1);

    // Check a timeout with a sever destination doesn't impact the failure counts
    auto server = ServerDestination{
            "https",
            "open.getsession.org",
            "/rooms",
            x25519_pubkey::from_hex("a03c383cf63c3c4efe67acc52112a6dd734b3a946b9545f488aaa93da79912"
                                    "38"),
            443,
            std::nullopt,
            "GET"};
    auto mock_request5 = request_info{
            "CCCC",
            server,
            "test",
            std::nullopt,
            std::nullopt,
            x25519_pubkey::from_hex(x_pk_hex),
            PathType::standard,
            0ms,
            std::nullopt,
            std::chrono::system_clock::now(),
            std::nullopt,
            false};
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->handle_errors(
            mock_request5,
            {target, nullptr, nullptr, nullptr},
            true,
            -1,
            {},
            "Test",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK(result.timeout);
    CHECK(result.status_code == -1);
    CHECK(network->get_failure_count(target) == 0);
    CHECK(network->get_failure_count(target2) == 0);
    CHECK(network->get_failure_count(target3) == 0);
    CHECK(network->get_failure_count(PathType::standard, path) == 0);

    // Check a server response starting with '500 Internal Server Error' is reported as a `500`
    // error and doesn't affect the failure count
    network.emplace(std::nullopt, true, true, false);
    network->set_suspended(true);  // Make no requests in this test
    network->ignore_calls_to("_send_onion_request", "update_disk_cache_throttled");
    network->handle_errors(
            mock_request4,
            {target, nullptr, nullptr, nullptr},
            false,
            -1,
            {},
            "500 Internal Server Error",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(network->get_failure_count(target) == 0);
    CHECK(network->get_failure_count(target2) == 0);
    CHECK(network->get_failure_count(target3) == 0);
    CHECK(network->get_failure_count(PathType::standard, path) == 0);
}

TEST_CASE("Network", "[network][get_unused_nodes]") {
    const auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::optional<TestNetwork> network;
    std::vector<service_node> snode_cache;
    std::vector<service_node> unused_nodes;
    for (uint16_t i = 0; i < 12; ++i)
        snode_cache.emplace_back(test_node(ed_pk, i));
    auto invalid_info = connection_info{snode_cache[0], nullptr, nullptr, nullptr};
    auto path =
            onion_path{"Test", invalid_info, {snode_cache[0], snode_cache[1], snode_cache[2]}, 0};

    auto compare_service_nodes = [](const service_node& a, const service_node& b) {
        if (auto cmp = oxen::quic::Address(a) <=> oxen::quic::Address(b); cmp != 0)
            return cmp < 0;

        return std::tie(a.get_remote_key(), a.swarm_id, a.storage_server_version) <
               std::tie(b.get_remote_key(), b.swarm_id, b.storage_server_version);
    };

    // Should shuffle the result
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    CHECK(network->get_unused_nodes() != network->get_unused_nodes());

    // Should contain the entire snode cache initially
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    unused_nodes = network->get_unused_nodes();
    std::stable_sort(unused_nodes.begin(), unused_nodes.end(), compare_service_nodes);
    CHECK(unused_nodes == snode_cache);

    // Should exclude nodes used in paths
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_paths(PathType::standard, {path});
    unused_nodes = network->get_unused_nodes();
    std::stable_sort(unused_nodes.begin(), unused_nodes.end(), compare_service_nodes);
    CHECK(unused_nodes == std::vector<service_node>{snode_cache.begin() + 3, snode_cache.end()});

    // Should exclude nodes in unused connections
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    unused_nodes = network->get_unused_nodes();
    std::stable_sort(unused_nodes.begin(), unused_nodes.end(), compare_service_nodes);
    CHECK(unused_nodes == std::vector<service_node>{snode_cache.begin() + 1, snode_cache.end()});

    // Should exclude nodes in in-progress connections
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_in_progress_connections({{"Test", snode_cache.front()}});
    unused_nodes = network->get_unused_nodes();
    std::stable_sort(unused_nodes.begin(), unused_nodes.end(), compare_service_nodes);
    CHECK(unused_nodes == std::vector<service_node>{snode_cache.begin() + 1, snode_cache.end()});

    // Should exclude nodes destinations in pending requests
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->add_pending_request(
            PathType::standard,
            request_info::make(
                    snode_cache.front(),
                    std::nullopt,
                    std::nullopt,
                    1s,
                    std::nullopt,
                    PathType::standard));
    unused_nodes = network->get_unused_nodes();
    std::stable_sort(unused_nodes.begin(), unused_nodes.end(), compare_service_nodes);
    CHECK(unused_nodes == std::vector<service_node>{snode_cache.begin() + 1, snode_cache.end()});

    // Should exclude nodes which have passed the failure threshold
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_failure_count(snode_cache.front(), 10);
    unused_nodes = network->get_unused_nodes();
    std::stable_sort(unused_nodes.begin(), unused_nodes.end(), compare_service_nodes);
    CHECK(unused_nodes == std::vector<service_node>{snode_cache.begin() + 1, snode_cache.end()});

    // Should exclude nodes which have the same IP if one was excluded
    std::vector<service_node> same_ip_snode_cache;
    auto unique_node = service_node{ed_pk, {2, 8, 0}, INVALID_SWARM_ID, "0.0.0.20", uint16_t{20}};
    for (uint16_t i = 0; i < 11; ++i)
        same_ip_snode_cache.emplace_back(test_node(ed_pk, i, false));
    same_ip_snode_cache.emplace_back(unique_node);
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(same_ip_snode_cache);
    network->set_failure_count(same_ip_snode_cache.front(), 10);
    unused_nodes = network->get_unused_nodes();
    REQUIRE(unused_nodes.size() == 1);
    CHECK(unused_nodes.front() == unique_node);
}

TEST_CASE("Network", "[network][build_path]") {
    const auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::optional<TestNetwork> network;
    std::vector<service_node> snode_cache;
    for (uint16_t i = 0; i < 12; ++i)
        snode_cache.emplace_back(test_node(ed_pk, i));
    auto invalid_info = connection_info{snode_cache[0], nullptr, nullptr, nullptr};

    // Nothing should happen if the network is suspended
    network.emplace(std::nullopt, true, false, false);
    network->set_suspended(true);
    network->build_path("Test1", PathType::standard);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));

    // If there are no unused connections it puts the path build in the queue and calls
    // establish_and_store_connection
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->build_path("Test1", PathType::standard);
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});
    CHECK(network->called("establish_and_store_connection", 100ms));

    // If the unused nodes are empty it refreshes them
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_in_progress_connections({{"TestInProgress", snode_cache.front()}});
    network->build_path("Test1", PathType::standard);
    CHECK(network->get_unused_nodes_value().size() == snode_cache.size() - 3);
    CHECK(network->get_path_build_queue().empty());

    // It should exclude nodes that are already in existing paths
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_in_progress_connections({{"TestInProgress", snode_cache.front()}});
    network->add_path(PathType::standard, {snode_cache.begin() + 1, snode_cache.begin() + 1 + 3});
    network->build_path("Test1", PathType::standard);
    CHECK(network->get_unused_nodes_value().size() == (snode_cache.size() - 3 - 3));
    CHECK(network->get_path_build_queue().empty());

    // If there aren't enough unused nodes it resets the failure count, re-queues the path build and
    // triggers a snode cache refresh
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("refresh_snode_cache");
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_path_build_failures(10);
    network->add_path(PathType::standard, snode_cache);
    network->build_path("Test1", PathType::standard);
    CHECK(network->get_path_build_failures() == 0);
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});
    CHECK(network->called("refresh_snode_cache", 100ms));

    // If it can't build a path after excluding nodes with the same IP it increments the
    // failure count and re-tries the path build after a small delay
    network.emplace(std::nullopt, true, false, false);
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->set_unused_nodes(std::vector<service_node>{
            snode_cache[0], snode_cache[0], snode_cache[0], snode_cache[0]});
    network->build_path("Test1", PathType::standard);
    network->ignore_calls_to("build_path");  // Ignore the 2nd loop
    CHECK(network->get_path_build_failures() == 1);
    CHECK(network->get_path_build_queue().empty());
    CHECK(network->called("build_path", 100ms, 2));

    // It stores a successful non-standard path and kicks of queued requests but doesn't update the
    // status or call the 'paths_changed' hook
    network.emplace(std::nullopt, true, false, false);
    network->find_valid_path_response =
            onion_path{"Test", invalid_info, {snode_cache.begin(), snode_cache.begin() + 3}, 0};
    network->ignore_calls_to("_send_onion_request");
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->add_pending_request(
            PathType::download,
            request_info::make(
                    snode_cache.back(),
                    std::nullopt,
                    std::nullopt,
                    1s,
                    std::nullopt,
                    PathType::download));
    network->build_path("Test1", PathType::download);
    CHECK(network->called("_send_onion_request", 100ms));
    CHECK(network->get_paths(PathType::download).size() == 1);

    // It stores a successful 'standard' path, updates the status, calls the 'paths_changed' hook
    // and kicks of queued requests
    network.emplace(std::nullopt, true, false, false);
    network->find_valid_path_response =
            onion_path{"Test", invalid_info, {snode_cache.begin(), snode_cache.begin() + 3}, 0};
    network->ignore_calls_to("_send_onion_request");
    network->set_snode_cache(snode_cache);
    network->set_unused_connections({invalid_info});
    network->add_pending_request(
            PathType::standard,
            request_info::make(
                    snode_cache.back(),
                    std::nullopt,
                    std::nullopt,
                    1s,
                    std::nullopt,
                    PathType::standard));
    network->build_path("Test1", PathType::standard);
    CHECK(network->called("_send_onion_request", 100ms));
    CHECK(network->get_paths(PathType::standard).size() == 1);
    CHECK(network->get_status() == ConnectionStatus::connected);
    CHECK(network->called("paths_changed"));
}

TEST_CASE("Network", "[network][find_valid_path]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto target = test_node(ed_pk, 1);
    auto test_service_node = service_node{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            {2, 8, 0},
            INVALID_SWARM_ID,
            "144.76.164.202",
            uint16_t{35400}};
    auto network = TestNetwork(std::nullopt, true, false, false);
    auto info = request_info::make(target, std::nullopt, std::nullopt, 0ms);
    auto invalid_path = onion_path{
            "Test",
            {test_service_node, nullptr, nullptr, nullptr},
            {test_service_node},
            uint8_t{0}};

    // It returns nothing when given no path options
    CHECK_FALSE(network.find_valid_path(info, {}).has_value());

    // It ignores invalid paths
    CHECK_FALSE(network.find_valid_path(info, {invalid_path}).has_value());

    // Need to get a valid path for subsequent tests
    std::promise<std::pair<connection_info, std::optional<std::string>>> prom;

    network.establish_connection(
            "Test",
            test_service_node,
            3s,
            [&prom](connection_info conn_info, std::optional<std::string> error) {
                prom.set_value({std::move(conn_info), error});
            });

    // Wait for the result to be set
    auto result = prom.get_future().get();
    REQUIRE(result.first.is_valid());
    auto valid_path = onion_path{
            "Test",
            std::move(result.first),
            std::vector<service_node>{test_service_node},
            uint8_t{0}};

    // It excludes paths which include the IP of the target
    auto shared_ip_info = request_info::make(test_service_node, std::nullopt, std::nullopt, 0ms);
    CHECK_FALSE(network.find_valid_path(shared_ip_info, {valid_path}).has_value());

    // It returns a path when there is a valid one
    CHECK(network.find_valid_path(info, {valid_path}).has_value());

    // In 'single_path_mode' it does allow the path to include the IP of the target (so that
    // requests can still be made)
    auto network_single_path = TestNetwork(std::nullopt, true, true, false);
    CHECK(network_single_path.find_valid_path(shared_ip_info, {valid_path}).has_value());
}

TEST_CASE("Network", "[network][build_path_if_needed]") {
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto target = test_node(ed_pk, 0);
    ;
    std::optional<TestNetwork> network;
    auto invalid_path = onion_path{
            "Test", connection_info{target, nullptr, nullptr, nullptr}, {target}, uint8_t{0}};

    // It does not add additional path builds if there is already a path and it's in
    // 'single_path_mode'
    network.emplace(std::nullopt, true, true, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path});
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));
    CHECK(network->get_path_build_queue().empty());

    // Adds a path build to the queue
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {});
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->called("establish_and_store_connection", 100ms));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Can only add the correct number of 'standard' path builds to the queue
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->build_path_if_needed(PathType::standard, false);
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->called("establish_and_store_connection", 100ms, 2));
    network->reset_calls();  // This triggers 'call_soon' so we need to wait until they are enqueued
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));
    CHECK(network->get_path_build_queue() ==
          std::deque<PathType>{PathType::standard, PathType::standard});

    // Can add additional 'standard' path builds if below the minimum threshold
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path});
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->called("establish_and_store_connection", 100ms));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Can add more path builds if there are enough active paths of the same type, no pending paths
    // and no `found_path` was provided
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path, invalid_path});
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->called("establish_and_store_connection", 100ms));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Cannot add more path builds if there are already enough active paths of the same type and a
    // `found_path` was provided
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path, invalid_path});
    network->build_path_if_needed(PathType::standard, true);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));
    CHECK(network->get_path_build_queue().empty());

    // Cannot add more path builds if there is already a build of the same type in the queue and the
    // number of active and pending builds of the same type meet the limit
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->set_paths(PathType::standard, {invalid_path});
    network->set_path_build_queue({PathType::standard});
    network->build_path_if_needed(PathType::standard, false);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));
    CHECK(network->get_path_build_queue() == std::deque<PathType>{PathType::standard});

    // Can only add the correct number of 'download' path builds to the queue
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->build_path_if_needed(PathType::download, false);
    network->build_path_if_needed(PathType::download, false);
    CHECK(network->called("establish_and_store_connection", 100ms, 2));
    network->reset_calls();  // This triggers 'call_soon' so we need to wait until they are enqueued
    network->build_path_if_needed(PathType::download, false);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));
    CHECK(network->get_path_build_queue() ==
          std::deque<PathType>{PathType::download, PathType::download});

    // Can only add the correct number of 'upload' path builds to the queue
    network.emplace(std::nullopt, true, false, false);
    network->ignore_calls_to("establish_and_store_connection");
    network->build_path_if_needed(PathType::upload, false);
    network->build_path_if_needed(PathType::upload, false);
    CHECK(network->called("establish_and_store_connection", 100ms, 2));
    network->reset_calls();  // This triggers 'call_soon' so we need to wait until they are enqueued
    network->build_path_if_needed(PathType::upload, false);
    CHECK(network->did_not_call("establish_and_store_connection", 25ms));
    CHECK(network->get_path_build_queue() ==
          std::deque<PathType>{PathType::upload, PathType::upload});
}

TEST_CASE("Network", "[network][establish_connection]") {
    auto network = TestNetwork(std::nullopt, true, true, false);
    auto test_server = network.create_test_node(2350);
    std::promise<std::pair<connection_info, std::optional<std::string>>> prom;

    network.establish_connection(
            "Test",
            test_server->node,
            3s,
            [&prom](connection_info info, std::optional<std::string> error) {
                prom.set_value({info, error});
            });

    // Wait for the result to be set
    auto result = prom.get_future().get();

    CHECK(result.first.is_valid());
    CHECK_FALSE(result.second.has_value());
}

TEST_CASE("Network", "[network][check_request_queue_timeouts]") {
    std::optional<TestNetwork> network;
    std::optional<std::shared_ptr<TestServer>> test_server;
    std::promise<Result> prom;

    // Test that it doesn't start checking for timeouts when the request doesn't have
    // a build paths timeout
    network.emplace(std::nullopt, true, true, false);
    test_server.emplace(network->create_test_node(2351));
    network->send_onion_request(
            (*test_server)->node,
            to_vector("{\"method\":\"info\",\"params\":{}}"),
            std::nullopt,
            [](bool,
               bool,
               int16_t,
               std::vector<std::pair<std::string, std::string>>,
               std::optional<std::string>) {},
            oxen::quic::DEFAULT_TIMEOUT,
            std::nullopt);
    CHECK(network->did_not_call("check_request_queue_timeouts", 300ms));

    // Test that it does start checking for timeouts when the request has a
    // paths build timeout
    network.emplace(std::nullopt, true, true, false);
    test_server.emplace(network->create_test_node(2352));
    network->ignore_calls_to("build_path");
    network->send_onion_request(
            (*test_server)->node,
            to_vector("{\"method\":\"info\",\"params\":{}}"),
            std::nullopt,
            [](bool,
               bool,
               int16_t,
               std::vector<std::pair<std::string, std::string>>,
               std::optional<std::string>) {},
            oxen::quic::DEFAULT_TIMEOUT,
            oxen::quic::DEFAULT_TIMEOUT);
    CHECK(network->called("check_request_queue_timeouts", 300ms));

    // Test that it fails the request with a timeout if it has a build path timeout
    // and the path build takes too long
    network.emplace(std::nullopt, true, true, false);
    test_server.emplace(network->create_test_node(2353));
    network->ignore_calls_to("build_path");
    network->send_onion_request(
            (*test_server)->node,
            to_vector("{\"method\":\"info\",\"params\":{}}"),
            std::nullopt,
            [&prom](bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                prom.set_value({success, timeout, status_code, headers, response});
            },
            oxen::quic::DEFAULT_TIMEOUT,
            100ms);

    // Wait for the result to be set
    auto result = prom.get_future().get();

    CHECK_FALSE(result.success);
    CHECK(result.timeout);
}

TEST_CASE("Network", "[network][send_request]") {
    auto network = TestNetwork(std::nullopt, true, true, false);
    auto test_server = network.create_test_node(2350);
    std::promise<Result> prom;

    network.establish_connection(
            "Test",
            test_server->node,
            3s,
            [&prom, &network, &test_server](
                    connection_info info, std::optional<std::string> error) {
                if (!info.is_valid())
                    return prom.set_value({false, false, -1, {}, error.value_or("Unknown Error")});

                network.send_request(
                        request_info::make(
                                test_server->node,
                                to_vector("{}"),
                                std::nullopt,
                                3s,
                                std::nullopt,
                                PathType::standard,
                                std::nullopt,
                                "info"),
                        std::move(info),
                        [&prom](bool success,
                                bool timeout,
                                int16_t status_code,
                                std::vector<std::pair<std::string, std::string>> headers,
                                std::optional<std::string> response) {
                            prom.set_value({success, timeout, status_code, headers, response});
                        });
            });

    // Wait for the result to be set
    auto result = prom.get_future().get();

    CHECK(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 200);
    REQUIRE(result.response.has_value());
    INFO("*result.response is: " << *result.response);
    REQUIRE_NOTHROW([&] { [[maybe_unused]] auto _ = nlohmann::json::parse(*result.response); });

    auto response = nlohmann::json::parse(*result.response);
    REQUIRE(response.contains("hf"));
    auto hf = response["hf"].get<std::vector<int>>();
    CHECK(hf.size() == 3);
    CHECK(hf[0] == 1);  // Called the info callback
    CHECK(response.contains("t"));
    CHECK(response.contains("version"));
}

TEST_CASE("Network", "[network][send_onion_request]") {
    auto network = TestNetwork(std::nullopt, true, true, false);
    auto test_server = network.create_test_node(2350);
    auto [test_path_servers, test_path] = network.create_test_path();
    network.handle_onion_requests_as_plaintext = true;
    network.set_paths(PathType::standard, {test_path});
    std::promise<Result> result_promise;

    network.send_onion_request(
            test_server->node,
            to_vector("{\"method\":\"info\",\"params\":{}}"),
            std::nullopt,
            [&result_promise](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result_promise.set_value({success, timeout, status_code, headers, response});
            },
            oxen::quic::DEFAULT_TIMEOUT,
            oxen::quic::DEFAULT_TIMEOUT);

    // Wait for the result to be set
    auto result = result_promise.get_future().get();

    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 200);
    REQUIRE(result.success);
    REQUIRE(result.response.has_value());
    INFO("*result.response is: " << *result.response);
    REQUIRE_NOTHROW([&] { [[maybe_unused]] auto _ = nlohmann::json::parse(*result.response); });

    auto response = nlohmann::json::parse(*result.response);
    REQUIRE(response.contains("hf"));
    auto hf = response["hf"].get<std::vector<int>>();
    CHECK(hf.size() == 3);
    CHECK(hf[0] == 2);  // Called the onion_req callback
    CHECK(response.contains("t"));
    CHECK(response.contains("version"));
}

TEST_CASE("Network", "[network][c][network_send_onion_request]") {
    auto test_network = std::make_unique<TestNetwork>(std::nullopt, true, true, false);
    auto test_server_cpp = test_network->create_test_node(2350);
    std::optional<std::pair<std::vector<std::shared_ptr<TestServer>>, onion_path>> test_path_data;
    test_path_data.emplace(test_network->create_test_path());
    test_network->handle_onion_requests_as_plaintext = true;
    test_network->set_paths(PathType::standard, {test_path_data->second});

    // Convert TestNetwork to network_object to pass to C API
    auto n_object = std::make_unique<network_object>();
    n_object->internals = test_network.release();
    network_object* network = n_object.release();

    // Convert test_server_cpp->node to network_service_node to pass to C API
    auto ip_v4 = test_server_cpp->node.to_ipv4();
    std::array<uint8_t, 4> target_ip = {
            static_cast<uint8_t>(ip_v4.addr >> 24),
            static_cast<uint8_t>((ip_v4.addr >> 16) & 0xFF),
            static_cast<uint8_t>((ip_v4.addr >> 8) & 0xFF),
            static_cast<uint8_t>(ip_v4.addr & 0xFF)};
    auto test_service_node = network_service_node{};
    test_service_node.quic_port = test_server_cpp->node.port();
    std::copy(target_ip.begin(), target_ip.end(), test_service_node.ip);
    auto test_pubkey_hex = oxenc::to_hex(test_server_cpp->node.view_remote_key());
    std::strcpy(test_service_node.ed25519_pubkey_hex, test_pubkey_hex.c_str());

    // Make the request
    auto body = to_vector("{\"method\":\"info\",\"params\":{}}");
    auto result_promise = std::make_shared<std::promise<Result>>();

    network_send_onion_request_to_snode_destination(
            network,
            test_service_node,
            body.data(),
            body.size(),
            nullptr,
            std::chrono::milliseconds{oxen::quic::DEFAULT_TIMEOUT}.count(),
            std::chrono::milliseconds{oxen::quic::DEFAULT_TIMEOUT}.count(),
            [](bool success,
               bool timeout,
               int16_t status_code,
               const char* const* headers,
               const char* const* header_values,
               size_t headers_size,
               const char* c_response,
               size_t response_size,
               void* ctx) {
                auto result_promise = static_cast<std::promise<Result>*>(ctx);
                auto response_str = std::string(c_response, response_size);
                std::vector<std::pair<std::string, std::string>> header_pairs;
                header_pairs.reserve(headers_size);

                for (size_t i = 0; i < headers_size; ++i) {
                    if (headers[i] == nullptr)
                        continue;  // Skip null entries
                    if (header_values[i] == nullptr)
                        continue;  // Skip null entries

                    header_pairs.emplace_back(headers[i], header_values[i]);
                }

                result_promise->set_value(
                        {success, timeout, status_code, header_pairs, response_str});
            },
            static_cast<void*>(result_promise.get()));

    // Wait for the result to be set
    auto result = result_promise->get_future().get();

    CHECK(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 200);
    REQUIRE(result.response.has_value());
    INFO("*result.response is: " << *result.response);
    REQUIRE_NOTHROW([&] { [[maybe_unused]] auto _ = nlohmann::json::parse(*result.response); });

    auto response = nlohmann::json::parse(*result.response);
    REQUIRE(response.contains("hf"));
    auto hf = response["hf"].get<std::vector<int>>();
    CHECK(hf.size() == 3);
    CHECK(hf[0] == 2);  // Called the onion_req callback
    CHECK(response.contains("t"));
    CHECK(response.contains("version"));
    test_path_data.reset();
    network_free(network);
}

TEST_CASE("Network", "[network][lokinet]") {
    CHECK("a" == "Start test");
    auto network = TestNetwork(std::nullopt, true, true, false);
    // fs::path ini_path = "/Users/morganpretty/Projects/Oxen/LibSession-Util/lokinet.ini";
    // auto lokinet = std::make_shared<lokinet::Lokinet>(ini_path, network.get_loop_ptr());
    auto lokinet =
            std::make_shared<lokinet::Lokinet>(lokinet::Network::TESTNET, network.get_loop_ptr());
    CHECK("a" == "Lokinet init called");
    std::this_thread::sleep_for(5000ms);
    CHECK("a" == "Sleep completed");
    std::promise<Result> prom;

    auto address = llarp::RouterID();
    uint16_t quic_port = 35400;
    address.from_hex("decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9");

    auto snode_address = address.to_network_address(true);
    auto info = lokinet->establish_udp_blocking(snode_address, quic_port);
    auto target = oxen::quic::RemoteAddress{
            "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"_hexbytes,
            "127.0.0.1",
            info.local_port};
    auto test_endpoint = oxen::quic::Endpoint::endpoint(
            network.get_loop(),
            oxen::quic::Address{"0.0.0.0", 0},
            oxen::quic::opt::alpns{"oxenstorage"},
            oxen::quic::opt::disable_mtu_discovery{});

    auto conn_key_pair = ed25519::ed25519_key_pair();
    auto creds = oxen::quic::GNUTLSCreds::make_from_ed_seckey(to_string_view(conn_key_pair.second));
    auto conn_promise = std::promise<std::shared_ptr<oxen::quic::Connection>>();
    auto conn_future = conn_promise.get_future().share();
    std::span<const std::byte> payload = to_span<std::byte>("{}");

    CHECK("a" == "Send request");
    auto c = test_endpoint->connect(
            target,
            creds,
            oxen::quic::opt::keep_alive{10s},
            [&prom, target, payload, conn_future](oxen::quic::Connection&) mutable {
                CHECK("a" == "Conn succeeded");
                auto conn = conn_future.get();
                auto stream = conn->open_stream<oxen::quic::BTRequestStream>();

                stream->command("info", payload, [&prom](oxen::quic::message resp) {
                    std::string body = std::string(resp.body());

                    if (resp.is_error() || resp.timed_out) {
                        prom.set_value({false, resp.timed_out, -1, {}, body});
                        return;
                    }
                    prom.set_value({true, false, -1, {}, body});
                });
            },
            [&prom](oxen::quic::Connection& conn, uint64_t error_code) mutable {
                CHECK("a" == "Conn failed: " + std::to_string(error_code));
                prom.set_value({false, false, -1, {}, std::nullopt});
            });

    conn_promise.set_value(c);

    // Wait for the result to be set
    auto result = prom.get_future().get();

    CHECK(result.success);
    CHECK_FALSE(result.timeout);
    if (result.response.has_value()) {
        CHECK("b" == *result.response);
    }
}