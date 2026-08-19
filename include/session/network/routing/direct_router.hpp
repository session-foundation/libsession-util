#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "session/network/backends/quic_file_client.hpp"
#include "session/network/backends/session_file_server.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"

namespace session::network {

namespace config {
    struct DirectRouter {
        FileServer file_server_config;
        opt::netid::Target netid;

        // When set, DirectRouter uses the QUIC file server protocol for uploads/downloads
        // instead of the legacy HTTP path.  All three must be set for the QUIC path to activate.
        std::optional<std::string> quic_file_server_address;
        std::optional<std::string> quic_file_server_ed_pubkey;
        uint16_t quic_file_server_port = file_server::QUIC_DEFAULT_PORT;
    };
}  // namespace config

class DirectRouter : public IRouter, public std::enable_shared_from_this<DirectRouter> {
  private:
    bool _suspended = false;
    config::DirectRouter _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::weak_ptr<ITransport> _transport;
    std::unordered_map<ed25519_pubkey, std::unique_ptr<QuicFileClient>> _file_clients;
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
    void upload(UploadRequest request) override;  // deprecated: use upload_file()
    void upload_file(FileUploadRequest request, std::span<const std::byte> seed) override;
    void download(DownloadRequest request) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};
    void _close_connections();
    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _upload_internal(UploadRequest request);
    void _upload_internal_legacy(UploadRequest request, std::string upload_id);
    void _download_internal(DownloadRequest request);
    void _download_internal_legacy(DownloadRequest request, std::string download_id);
    void _cleanup_upload(const std::string& upload_id);
    QuicFileClient& _get_file_client(
            const ed25519_pubkey& pubkey, std::string_view address, uint16_t port);
    void _handle_transport_response(
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> response_body,
            network_response_callback_t callback);
};

}  // namespace session::network
