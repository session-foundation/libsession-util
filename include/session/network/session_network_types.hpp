#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/service_node.hpp"
#include "session/network/session_network_types.h"

namespace session::network {

constexpr int16_t ERROR_BAD_REQUEST = 400;
constexpr int16_t ERROR_PAYLOAD_TOO_LARGE = 413;
constexpr int16_t ERROR_INTERNAL_SERVER_ERROR = 500;
constexpr int16_t ERROR_NETWORK_SUSPENDED = -10001;
constexpr int16_t ERROR_NO_TRANSPORT_LAYER = -10002;
constexpr int16_t ERROR_NO_ROUTING_LAYER = -10003;
constexpr int16_t ERROR_CONNECTION_CLOSED = -10004;
constexpr int16_t ERROR_INVALID_DOWNLOAD_URL = -10005;
constexpr int16_t ERROR_BUILD_TIMEOUT = -10100;
constexpr int16_t ERROR_REQUEST_CANCELLED = -10200;

const std::pair<std::string, std::string> content_type_plain_text = {
        "Content-Type", "text/plain; charset=UTF-8"};
const std::pair<std::string, std::string> content_type_json = {"Content-Type", "application/json"};

class cancellation_exception : public std::runtime_error {
  public:
    cancellation_exception(std::string message) : std::runtime_error(message) {}
};

class invalid_url_exception : public std::runtime_error {
  public:
    invalid_url_exception(std::string message) : std::runtime_error(message) {}
};

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

enum class ConnectionStatus {
    unknown = CONNECTION_STATUS_UNKNOWN,
    connecting = CONNECTION_STATUS_CONNECTING,
    connected = CONNECTION_STATUS_CONNECTED,
    disconnected = CONNECTION_STATUS_DISCONNECTED,
};

enum class RequestCategory {
    standard = SESSION_NETWORK_REQUEST_CATEGORY_STANDARD,
    standard_small = SESSION_NETWORK_REQUEST_CATEGORY_STANDARD_SMALL,
    file = SESSION_NETWORK_REQUEST_CATEGORY_FILE,
    file_small = SESSION_NETWORK_REQUEST_CATEGORY_FILE_SMALL,
};

enum class PathCategory {
    standard = SESSION_NETWORK_PATH_CATEGORY_STANDARD,
    file = SESSION_NETWORK_PATH_CATEGORY_FILE,
};

inline std::string to_string(RequestCategory category) {
    switch (category) {
        case RequestCategory::standard: return "standard";
        case RequestCategory::standard_small: return "standard_small";
        case RequestCategory::file: return "file";
        case RequestCategory::file_small: return "file_small";
    }
    return "unknown";  // Should not be reached
}

inline std::string to_string(PathCategory category) {
    switch (category) {
        case PathCategory::standard: return "standard";
        case PathCategory::file: return "file";
    }
    return "unknown";  // Should not be reached
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

using network_destination =
        std::variant<service_node, ServerDestination, oxen::quic::RemoteAddress>;

struct CancellationToken {
    std::atomic<bool> cancelled{false};

    void cancel() { cancelled.store(true); }
    bool is_cancelled() const { return cancelled.load(); }
};

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

    /// An optional, overall timeout for the entire operation, starting from the moment the request
    /// is created. This includes time spent in queues waiting for a path to be built or a
    /// connection to be established. If this timeout is exceeded while the request is still in a
    /// queue, it will be timed out.
    std::optional<std::chrono::milliseconds> overall_timeout;

    /// Any extra request details which may modify the structure of the request.
    RequestDetails details;

    /// The time the request was created, this is used primarily for determining whether the
    /// `overall_timeout` has been exceeded.
    std::chrono::steady_clock::time_point creation_time = std::chrono::steady_clock::now();

    // If true, the transport should not cache/pool the connection used for this request, this is
    // for one-shot requests like bootstrapping.
    bool ephemeral_connection;

    int retry_count = 0;

    Request(std::string request_id,
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<unsigned char>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt,
            RequestDetails details = std::monostate{},
            bool ephemeral_connection = false);

    Request(network_destination destination,
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

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - creation_time);
        auto remaining = *overall_timeout - elapsed;

        return (remaining > std::chrono::milliseconds::zero() ? remaining
                                                              : std::chrono::milliseconds::zero());
    }
};

struct file_metadata {
    std::string id;
    int64_t size;
    std::chrono::system_clock::time_point uploaded;
    std::chrono::system_clock::time_point expiry;
};

struct UploadRequest {
    std::function<std::vector<unsigned char>()> next_data;
    std::optional<std::string> file_name;
    std::chrono::milliseconds stall_timeout;
    std::chrono::milliseconds request_timeout;
    std::optional<std::chrono::milliseconds> overall_timeout;
    std::shared_ptr<CancellationToken> cancellation_token;

    // Called when upload completes (success) or fails (error code)
    std::function<void(std::variant<file_metadata, int16_t> result, bool timeout)> on_complete;

    bool is_cancelled() const { return cancellation_token && cancellation_token->is_cancelled(); }
};

struct DownloadRequest {
    std::string download_url;
    std::chrono::milliseconds stall_timeout;
    std::chrono::milliseconds request_timeout;
    std::optional<std::chrono::milliseconds> overall_timeout;
    std::shared_ptr<CancellationToken> cancellation_token;

    // Called as data arrives (can be called multiple times)
    std::function<void(const file_metadata& info, std::vector<unsigned char> data)> on_data;

    // Called when download completes (success) or fails (error code)
    std::function<void(std::variant<file_metadata, int16_t> result, bool timeout)> on_complete;

    // Minimum interval between on_data calls (to control callback overhead vs memory usage)
    std::chrono::milliseconds partial_min_interval = 250ms;

    bool is_cancelled() const { return cancellation_token && cancellation_token->is_cancelled(); }
};

using node_failure_reporter_t = std::function<void(const ed25519_pubkey&, bool)>;
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

struct OnionPathMetadata {
    PathCategory category;
};
struct SessionRouterTunnelMetadata {
    std::string destination_pubkey;
    std::string destination_snode_address;
};

using PathMetadata = std::variant<OnionPathMetadata, SessionRouterTunnelMetadata>;

struct PathInfo {
    std::vector<service_node> nodes;
    PathMetadata metadata;
};

}  // namespace session::network
