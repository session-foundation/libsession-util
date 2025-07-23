#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/network_config.hpp"

namespace session::network {

const std::pair<std::string, std::string> content_type_plain_text = {
        "Content-Type", "text/plain; charset=UTF-8"};
const std::pair<std::string, std::string> content_type_json = {
        "Content-Type", "application/json"};

struct ServerDestination {
    std::string protocol;
    std::string host;
    std::string endpoint;
    session::network::x25519_pubkey x25519_pubkey;
    std::optional<uint16_t> port;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers;
    std::string method;

    ServerDestination(
            std::string protocol,
            std::string host,
            std::string endpoint,
            session::network::x25519_pubkey x25519_pubkey,
            std::optional<uint16_t> port = std::nullopt,
            std::optional<std::vector<std::pair<std::string, std::string>>> headers = std::nullopt,
            std::string method = "GET") :
            protocol{std::move(protocol)},
            host{std::move(host)},
            endpoint{std::move(endpoint)},
            x25519_pubkey{std::move(x25519_pubkey)},
            port{std::move(port)},
            headers{std::move(headers)},
            method{std::move(method)} {}
};

using network_destination = std::variant<session::network::service_node, ServerDestination>;

struct Request {
    std::string request_id;
    network_destination destination;
    std::string endpoint;
    std::optional<std::vector<unsigned char>> body;
    std::chrono::milliseconds request_timeout;

    // Router-specific values
    std::optional<session::network::x25519_pubkey> swarm_pubkey;
    std::optional<std::chrono::milliseconds> request_and_path_build_timeout;
    std::chrono::system_clock::time_point creation_time = std::chrono::system_clock::now();

    std::chrono::milliseconds time_remaining() const {
        if (!request_and_path_build_timeout)
            return request_timeout;
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - creation_time);
        return *request_and_path_build_timeout - elapsed;
    }
};

using network_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> response)>;

class ITransport {
public:
    virtual ~ITransport() = default;

    virtual void send_request(Request request, network_response_callback_t callback) = 0;
};

} // namespace session::network