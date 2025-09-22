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

class DirectRouter : public IRouter, public std::enable_shared_from_this<DirectRouter> {
  private:
    bool _suspended = false;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::weak_ptr<ITransport> _transport;

  public:
    DirectRouter(std::shared_ptr<oxen::quic::Loop> loop, std::weak_ptr<ITransport> transport);
    ~DirectRouter() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override {};
    void clear_cache() override {};

    ConnectionStatus get_status() const override { return _status.load(); };
    void send_request(Request request, network_response_callback_t callback) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};
    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _handle_transport_response(
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response_body,
            network_response_callback_t callback);
};

}  // namespace session::network
