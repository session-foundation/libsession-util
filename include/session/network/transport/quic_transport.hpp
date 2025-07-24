#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/network_config.hpp"
#include "session/network/network_transport.hpp"

namespace oxen::quic {
    class Loop;
    class Endpoint;
    struct ConnectionID;
}

namespace session::network {

namespace config {
    struct QuicTransportConfig {
        std::chrono::milliseconds handshake_timeout;
        std::chrono::seconds keep_alive;

        bool disable_mtu_discovery;
    };
}

class QuicTransport: public ITransport {
private:
    config::QuicTransportConfig _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<oxen::quic::Endpoint> _endpoint;

    std::unordered_map<std::string, oxen::quic::ConnectionID> _active_connection_ids;
    std::unordered_map<oxen::quic::ConnectionID, int64_t> _active_stream_ids;
    std::unordered_map<
            std::string,
            std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;

public:
    explicit QuicTransport(config::QuicTransportConfig config, std::shared_ptr<oxen::quic::Loop> loop);
    ~QuicTransport() override;

    void verify_connectivity(
        service_node node,
        std::chrono::milliseconds timeout,
        const std::string& request_id,
        std::function<void(bool success)> callback) override;
    void send_request(Request request, network_response_callback_t callback) override;

private:
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _establish_connection(const service_node& target_node, const std::string& initiating_req_id);
    void _send_on_connection(oxen::quic::ConnectionID conn_id, Request request, network_response_callback_t callback);
};

} // namespace session::network