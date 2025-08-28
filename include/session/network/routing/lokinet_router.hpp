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

namespace lokinet {
class Lokinet;
struct tunnel_info;
};  // namespace lokinet

namespace session::network {

namespace config {
    struct LokinetRouterConfig {
        opt::netid::Target netid;
        fs::path cache_directory;
        std::chrono::milliseconds request_timeout_check_frequency;

        uint8_t path_length;
    };
}  // namespace config

class LokinetRouter : public IRouter {
  private:
    bool _ready = false;
    bool _suspended = false;
    config::LokinetRouterConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<lokinet::Lokinet> lokinet;
    std::weak_ptr<SnodePool> _snode_pool;
    std::weak_ptr<ITransport> _transport;

    std::unordered_map<std::string, lokinet::tunnel_info> _active_tunnels;
    std::unordered_map<std::string, std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;

  public:
    LokinetRouter(
            config::LokinetRouterConfig config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::weak_ptr<SnodePool> snode_pool,
            std::weak_ptr<ITransport> transport);
    ~LokinetRouter() override;

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
    void _establish_tunnel(
            const oxen::quic::RemoteAddress& address, const std::string& initiating_req_id);
    void _send_via_tunnel(
            lokinet::tunnel_info tunnel, Request request, network_response_callback_t callback);
};

}  // namespace session::network
