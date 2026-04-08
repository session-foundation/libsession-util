#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/session_network_types.hpp"

namespace oxen::quic {
class Loop;
class Endpoint;
class Connection;
class BTRequestStream;
class Stream;
class GNUTLSCreds;
class Ticker;
class Address;
struct RemoteAddress;
}  // namespace oxen::quic

namespace session::network {

/// ALPN used by the QUIC file server protocol.
constexpr auto QUIC_FILES_ALPN = "quic-files";

/// QUIC stream error code sent when the client aborts a download (e.g. due to a decryption error
/// in the on_data callback).
constexpr uint64_t QUIC_FILES_CLIENT_ABORT = 499;

/// A self-contained QUIC client that speaks the "quic-files" protocol for streaming file
/// uploads and downloads to a single file server.  Manages its own endpoint, connection lifecycle
/// (with idle timeout), and optional 0-RTT session resumption.
///
/// The caller is responsible for determining the connection address (which may be a direct address
/// or a session-router tunnel proxy port) and the Ed25519 pubkey of the file server.
class QuicFileClient {
    friend void streaming_file_upload(
            std::shared_ptr<oxen::quic::Loop>,
            attachment::Encryptor,
            FileUploadRequest,
            std::function<QuicFileClient*(void)>);

  public:
    using ticket_store_cb = std::function<void(
            std::string remote_key_hex,
            std::vector<unsigned char> ticket_data,
            std::chrono::sys_seconds expiry)>;
    using ticket_extract_cb = std::function<std::optional<std::vector<unsigned char>>(
            std::string_view remote_key_hex)>;

    /// Construct a QuicFileClient for the given file server.
    /// \param loop     The event loop to use.
    /// \param ed_pubkey  Ed25519 pubkey of the file server (for TLS verification).
    /// \param address    Host/IP to connect to (e.g. "::1" for session-router proxy, or direct IP).
    /// \param port       Port to connect to.
    QuicFileClient(
            std::shared_ptr<oxen::quic::Loop> loop,
            ed25519_pubkey ed_pubkey,
            std::string address,
            uint16_t port,
            std::optional<size_t> max_udp_payload = std::nullopt,
            ticket_store_cb ticket_store = nullptr,
            ticket_extract_cb ticket_extract = nullptr);

    ~QuicFileClient();

    /// Update the connection target (e.g. when a session-router tunnel port changes).
    /// Closes the current connection if the target changed.
    void set_target(ed25519_pubkey ed_pubkey, std::string address, uint16_t port);

    /// Upload pre-accumulated encrypted data to the file server.  The on_complete callback
    /// receives either file_metadata on success or an int16_t error code on failure.
    void upload(
            std::vector<std::byte> data,
            std::optional<std::chrono::seconds> ttl,
            std::function<void(std::variant<file_metadata, int16_t> result)> on_complete);

    /// Download a file by ID from the file server.  on_data is called as data chunks arrive
    /// with a non-owning view of the data; on_complete signals completion or failure.
    void download(
            std::string file_id,
            std::function<void(const file_metadata& info, std::span<const std::byte> data)> on_data,
            std::function<void(std::variant<file_metadata, int16_t> result)> on_complete);

    /// Close the current connection (if any).
    void close();

  private:
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<oxen::quic::Endpoint> _ep;
    std::shared_ptr<oxen::quic::Connection> _conn;
    std::shared_ptr<oxen::quic::GNUTLSCreds> _creds;

    // Stream 0: opened as BTRequestStream on each connection and held for the connection
    // lifetime.  TODO: use this for metadata requests (file info, extend TTL, etc.)
    std::shared_ptr<oxen::quic::BTRequestStream> _bt_stream;

    ed25519_pubkey _ed_pubkey;
    std::string _address;
    uint16_t _port;
    std::optional<size_t> _max_udp_payload;

    // 0RTT ticket callbacks (optional; if not provided, 0RTT is not used)
    ticket_store_cb _ticket_store;
    ticket_extract_cb _ticket_extract;

    // Idle timeout: close the connection after this much inactivity
    static constexpr auto IDLE_TIMEOUT = std::chrono::seconds{30};
    static constexpr auto IDLE_CHECK_INTERVAL = std::chrono::seconds{5};
    std::shared_ptr<oxen::quic::Ticker> _idle_timer;
    std::chrono::steady_clock::time_point _last_activity;

    // Returns the active connection, establishing one if needed.
    std::shared_ptr<oxen::quic::Connection> _ensure_connection();
    void _start_idle_timer();
    void _touch();
};

/// Performs a complete streaming file upload from a background thread.  This function blocks
/// until the upload completes or fails.  It:
/// 1. Reads the file to derive the encryption key (Encryptor phase 1)
/// 2. Opens a QUIC stream on the loop thread and sends the PUT command
/// 3. Pulls encrypted chunks from the Encryptor and pushes them to the stream,
///    using watermarks for backpressure
/// 4. Waits for the server response
///
/// Must be called from a background thread (not the loop thread).  The `on_complete` callback
/// fires on the loop thread when done.
///
/// `get_client` is called on the loop thread to obtain the QuicFileClient to use; this allows
/// the caller to do any router-specific setup (e.g. tunnel establishment) before the upload.
void streaming_file_upload(
        std::shared_ptr<oxen::quic::Loop> loop,
        attachment::Encryptor enc,
        FileUploadRequest request,
        std::function<QuicFileClient*(void)> get_client);

}  // namespace session::network
