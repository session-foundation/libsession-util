#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "session/network/request_queue.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"

namespace session::network {

namespace config {
    struct OnionRequestRouterConfig {
        network::opt::retry_delay retry_delay;

        uint8_t path_length;
        uint8_t path_failure_threshold;
        uint8_t path_build_retry_limit;
        bool disable_pre_build_paths;
        bool single_path_mode;
        std::unordered_map<PathCategory, uint8_t> min_path_counts;
    };
}  // namespace config

struct OnionPath {
    std::string id;
    std::vector<service_node> nodes;

    size_t active_requests = 0;
    uint16_t failure_count = 0;

    std::string to_string() const;
};

inline PathCategory to_path_category(RequestCategory category) {
    switch (category) {
        case RequestCategory::standard: return PathCategory::standard;
        case RequestCategory::standard_small: return PathCategory::standard;
        case RequestCategory::file: return PathCategory::file;
        case RequestCategory::file_small: return PathCategory::file;
    }
    return PathCategory::standard;  // Should not be reached
}

class OnionRequestRouter : public IRouter, public std::enable_shared_from_this<OnionRequestRouter> {
  private:
    friend class TestOnionRequestRouter;

    bool _ready = false;
    bool _suspended = false;
    config::OnionRequestRouterConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::weak_ptr<SnodePool> _snode_pool;
    std::weak_ptr<ITransport> _transport;

    std::unordered_map<PathCategory, std::vector<OnionPath>> _paths;
    std::unordered_map<PathCategory, std::vector<OnionPath>> _paths_pending_drop;
    std::unordered_map<PathCategory, std::shared_ptr<detail::RequestQueue>> _request_queues;

    std::unordered_map<PathCategory, int> _in_progress_path_builds;
    std::unordered_map<std::string, int> _path_build_retries;
    std::unordered_map<std::string, std::vector<service_node>> _pending_paths;

  public:
    OnionRequestRouter(
            config::OnionRequestRouterConfig config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::weak_ptr<SnodePool> snode_pool,
            std::weak_ptr<ITransport> transport);
    ~OnionRequestRouter() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override;
    void clear_cache() override {}

    ConnectionStatus get_status() const override { return _status.load(); };
    std::vector<PathInfo> get_active_paths() override;
    std::vector<service_node> get_all_used_nodes() override;
    void send_request(Request request, network_response_callback_t callback) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};

    // All of the below functions should only be called from within `_loop`
    void _finish_setup();
    void _pre_build_paths_if_needed();
    void _close_connections();
    void _update_status();
    void _send_request_internal(Request request, network_response_callback_t callback);

    void _build_path(
            PathCategory category,
            std::optional<std::string> initiating_req_id,
            const std::vector<service_node>& nodes_to_exclude,
            std::optional<std::string> original_path_id = std::nullopt);
    void _on_edge_connectivity_response(
            const std::string& path_id,
            PathCategory category,
            std::optional<std::string> initiating_req_id,
            bool success);

    OnionPath* _find_valid_path(const Request& request);

    void _send_on_path(OnionPath& path, Request request, network_response_callback_t callback);
    void _handle_transport_response(
            std::string path_id,
            Request original_request,
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> decrypted_body,
            network_response_callback_t callback);

    void _decrement_and_cleanup_path(const std::string& path_id, PathCategory category);
    void _handle_path_failure(
            const std::string& path_id,
            const PathCategory& category,
            const std::optional<std::string>& error_body);
};

}  // namespace session::network
