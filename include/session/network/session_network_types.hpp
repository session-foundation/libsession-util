#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/session_network_types.h"
#include "session/network/service_node.hpp"

namespace session::network {

constexpr int16_t ERROR_BUILD_TIMEOUT = -10003;

const std::pair<std::string, std::string> content_type_plain_text = {
        "Content-Type", "text/plain; charset=UTF-8"};
const std::pair<std::string, std::string> content_type_json = {
        "Content-Type", "application/json"};

class status_code_exception : public std::runtime_error {
    public:
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;

    status_code_exception(
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::string message) :
            std::runtime_error(message), status_code{status_code}, headers{headers} {}
};

enum class RequestCategory {
    standard = SESSION_NETWORK_CATEGORY_STANDARD,
    upload = SESSION_NETWORK_CATEGORY_UPLOAD,
    download = SESSION_NETWORK_CATEGORY_DOWNLOAD,
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
    session::network::x25519_pubkey x25519_pubkey;
    std::optional<uint16_t> port;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers;
    std::string method;

    ServerDestination(
            std::string protocol,
            std::string host,
            session::network::x25519_pubkey x25519_pubkey,
            std::optional<uint16_t> port = std::nullopt,
            std::optional<std::vector<std::pair<std::string, std::string>>> headers = std::nullopt,
            std::string method = "GET") :
            protocol{std::move(protocol)},
            host{std::move(host)},
            x25519_pubkey{std::move(x25519_pubkey)},
            port{std::move(port)},
            headers{std::move(headers)},
            method{std::move(method)} {}
};

using network_destination = std::variant<service_node, ServerDestination, oxen::quic::RemoteAddress>;

struct UploadInfo {
    std::optional<std::string> file_name;
};

using RequestDetails = std::variant<std::monostate, UploadInfo>;

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

    /// Any extra request details which may modify the structure of the request.
    RequestDetails details;

    /// The time the request was created, this is used primarily for determining whether the `overall_timeout` has been exceeded.
    std::chrono::system_clock::time_point creation_time = std::chrono::system_clock::now();

    // If true, the transport should not cache/pool the connection used for this request, this is for one-shot requests like bootstrapping.
    bool ephemeral_connection;

    int retry_count = 0;

    Request(
            std::string request_id,
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<unsigned char>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt,
            RequestDetails details = std::monostate{},
            bool ephemeral_connection = false);
    
    Request(
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<unsigned char>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt,
            std::optional<std::string> request_id = std::nullopt,
            RequestDetails details = std::monostate{},
            bool ephemeral_connection = false);

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

struct Response {
    static std::optional<std::pair<int16_t, bool>> parse_text_error(const std::string& body);
    static std::optional<int16_t> find_uniform_batch_error(const std::string& body);
};

}  // namespace session::network
