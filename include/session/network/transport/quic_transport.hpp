#pragma once

#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/network_config.hpp"
#include "session/network/transport/network_transport.hpp"

namespace oxen::quic {
class Loop;
class Endpoint;
struct ConnectionID;
}  // namespace oxen::quic

namespace session::network {

namespace config {
    struct QuicTransportConfig {
        std::chrono::milliseconds handshake_timeout;
        std::chrono::seconds keep_alive;

        bool disable_mtu_discovery;
    };
}  // namespace config

class QuicTransport : public ITransport {
  private:
    config::QuicTransportConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<oxen::quic::Endpoint> _endpoint;

    std::unordered_set<oxen::quic::ConnectionID> _ephemeral_connection_ids;
    std::unordered_map<std::string, oxen::quic::ConnectionID> _active_connection_ids;
    std::unordered_map<oxen::quic::ConnectionID, int64_t> _active_stream_ids;
    std::unordered_map<std::string, std::vector<std::function<void(bool)>>>
            _pending_verification_callbacks;
    std::unordered_map<std::string, std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;

  public:
    explicit QuicTransport(
            config::QuicTransportConfig config, std::shared_ptr<oxen::quic::Loop> loop);
    ~QuicTransport() override;

    ConnectionStatus get_status() const override { return _status.load(); };
    void set_node_failure_reporter(node_failure_reporter_t reporter) override;
    void verify_connectivity(
            service_node node,
            std::chrono::milliseconds timeout,
            const std::string& request_id,
            std::function<void(bool success)> callback) override;
    void send_request(Request request, network_response_callback_t callback) override;

  private:
    // The current connection status of this transport layer
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};

    // Callback which will be called when failing to connect to a node
    std::optional<node_failure_reporter_t> _report_node_failure;

    // True if we have already transitioned to "connecting" since the last time we were fully
    // disconnected
    bool _has_attempted_reconnect = false;

    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _establish_connection(
            const oxen::quic::RemoteAddress& address, const std::string& initiating_req_id);
    void _send_on_connection(
            oxen::quic::ConnectionID conn_id,
            Request request,
            network_response_callback_t callback);
};

}  // namespace session::network