#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "session/network/backends/session_file_server.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"

namespace session::network {

namespace config {
    struct DirectRouter {
        FileServer file_server_config;
    };
}  // namespace config

class DirectRouter : public IRouter, public std::enable_shared_from_this<DirectRouter> {
  private:
    bool _suspended = false;
    config::DirectRouter _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::weak_ptr<ITransport> _transport;
    std::unordered_map<std::string, std::pair<UploadRequest, std::thread>> _active_uploads;
    std::unordered_map<std::string, DownloadRequest> _active_downloads;

  public:
    DirectRouter(
            config::DirectRouter config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::weak_ptr<ITransport> transport);
    ~DirectRouter() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override;
    void clear_cache() override {};

    ConnectionStatus get_status() const override { return _status.load(); };
    void send_request(Request request, network_response_callback_t callback) override;
    void upload(UploadRequest request) override;
    void download(DownloadRequest request) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};
    void _close_connections();
    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _upload_internal(UploadRequest request);
    void _download_internal(DownloadRequest request);
    void _handle_transport_response(
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response_body,
            network_response_callback_t callback);
};

}  // namespace session::network
