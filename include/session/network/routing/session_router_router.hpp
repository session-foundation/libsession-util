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

namespace session::router {
class SessionRouter;
struct tunnel_info;
};  // namespace session::router

namespace session::network {

namespace config {
    struct SessionRouterConfig {
        opt::netid::Target netid;
        fs::path cache_directory;
        std::chrono::milliseconds request_timeout_check_frequency;

        uint8_t path_length;
        uint8_t max_streams;
    };
}  // namespace config

class SessionRouter : public IRouter, public std::enable_shared_from_this<SessionRouter> {
  private:
    bool _ready = false;
    bool _suspended = false;
    config::SessionRouterConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<session::router::SessionRouter> srouter;
    std::weak_ptr<SnodePool> _snode_pool;
    std::weak_ptr<ITransport> _transport;

    std::unordered_map<std::string, session::router::tunnel_info> _active_tunnels;
    std::unordered_map<std::string, std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;

  public:
    SessionRouter(
            config::SessionRouterConfig config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::weak_ptr<SnodePool> snode_pool,
            std::weak_ptr<ITransport> transport);
    ~SessionRouter() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override;
    void clear_cache() override;

    ConnectionStatus get_status() const override { return _status.load(); };
    std::vector<PathInfo> get_active_paths() override;
    void send_request(Request request, network_response_callback_t callback) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};

    // All of the below functions should only be called from within `_loop`
    void _finish_setup();
    void _close_connections();
    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _send_direct_request(Request request, network_response_callback_t callback);
    void _send_proxy_request(Request request, network_response_callback_t callback);
    void _establish_tunnel(
            std::span<const unsigned char>& remote_pubkey, const uint16_t remote_port, const std::string& initiating_req_id);
    void _send_via_tunnel(
            session::router::tunnel_info tunnel, Request request, network_response_callback_t callback);
};

}  // namespace session::network
