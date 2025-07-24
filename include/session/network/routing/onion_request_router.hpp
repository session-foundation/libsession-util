#pragma once

#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "session/network/network_router.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/snode_pool.hpp"

namespace session::network {

namespace config {
    struct OnionRequestRouterConfig {
        uint8_t path_length;
        uint8_t path_failure_threshold;
        uint8_t path_build_retry_limit;
        bool disable_pre_build_paths;
        bool single_path_mode;
        std::unordered_map<RequestCategory, uint8_t> min_path_counts;
    };
}

struct OnionPath {
    std::string id;
    std::vector<service_node> nodes;
    
    size_t pending_requests = 0;
    uint16_t failure_count = 0;

    std::string OnionPath::to_string() const;
};

class OnionRequestRouter : public IRouter {
private:
    config::OnionRequestRouterConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    SnodePool& _snode_pool;
    std::shared_ptr<ITransport> _transport;

    std::unordered_map<RequestCategory, std::vector<OnionPath>> _paths;
    std::unordered_map<RequestCategory, std::vector<OnionPath>> _paths_pending_drop;
    std::unordered_map<RequestCategory, detail::RequestQueue> _request_queues;
    
    std::unordered_map<RequestCategory, int> _in_progress_path_builds;
    std::unordered_map<std::string, std::vector<service_node>> _pending_paths;

public:
    OnionRequestRouter(
            config::OnionRequestRouterConfig config,
            SnodePool& snode_pool,
            std::shared_ptr<ITransport> transport);

    ~OnionRequestRouter() override;

    void send_request(Request request, network_response_callback_t callback) override;

private:
    // All of the below functions should only be called from within `_loop`
    
    void _send_request_internal(Request request, network_response_callback_t callback);

    void _build_path(RequestCategory category, std::optional<std::string> initiating_req_id, const std::vector<service_node>& nodes_to_exclude);
    void _on_guard_connection_established(const std::string& path_id, RequestCategory category, std::optional<std::string> initiating_req_id, bool success);

    OnionPath* _find_valid_path(const Request& request);

    void _send_on_path(OnionPath& path, Request request, network_response_callback_t callback);
    void _decrement_and_cleanup_path(const std::string& path_id, RequestCategory category);
    void _handle_request_failure(
        const std::string& path_id,
        const Request& request,
        int16_t status_code,
        const std::string& error_body);
};

} // namespace session::network
