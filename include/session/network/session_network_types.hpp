#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/service_node.hpp"

namespace session::network {

constexpr int16_t ERROR_BUILD_TIMEOUT = -10003;

const std::pair<std::string, std::string> content_type_plain_text = {
        "Content-Type", "text/plain; charset=UTF-8"};
const std::pair<std::string, std::string> content_type_json = {
        "Content-Type", "application/json"};

enum class RequestCategory {
    standard,
    upload,
    download,
};

inline std::string to_string(RequestCategory category) {
    switch (category) {
        case RequestCategory::standard: return "standard";
        case RequestCategory::upload:   return "upload";
        case RequestCategory::download: return "download";
    }
    return "unknown"; // Should not be reached
}

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

using network_destination = std::variant<service_node, ServerDestination>;

struct Request {
    std::string request_id;
    network_destination destination;
    std::string endpoint;
    std::optional<std::vector<unsigned char>> body;
    RequestCategory category;
    
    /// Timeout for an in-flight request after it has been sent via the transport mechanism.
    std::chrono::milliseconds request_timeout;

    /// An optional, overall timeout for the entire operation, starting from the moment the request is created. This includes time spent in queues waiting for a path to be built or a connection to be established. If this timeout is exceeded while the request is still in a queue, it will be timed out.
    std::optional<std::chrono::milliseconds> overall_timeout;

    /// The time the request was created, this is used primarily for determining whether the `overall_timeout` has been exceeded.
    std::chrono::system_clock::time_point creation_time = std::chrono::system_clock::now();

    // Router-specific values
    std::optional<session::network::x25519_pubkey> swarm_pubkey;

    Request(
            std::string request_id,
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<unsigned char>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt) :
            request_id{std::move(request_id)},
            destination{std::move(destination)},
            endpoint{std::move(endpoint)},
            body{std::move(body)},
            category{std::move(category)},
            request_timeout{std::move(request_timeout)},
            overall_timeout{std::move(overall_timeout)} {}

    std::chrono::milliseconds time_remaining() const {
        if (!overall_timeout)
            return request_timeout;
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - creation_time);
        auto remaining = *overall_timeout - elapsed;

        return (remaining > std::chrono::milliseconds::zero() ? remaining : std::chrono::milliseconds::zero());
    }
};

using network_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> response)>;

}  // namespace session::network
