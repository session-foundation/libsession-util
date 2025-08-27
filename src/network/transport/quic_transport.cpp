#include "session/network/transport/quic_transport.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

#include "session/ed25519.hpp"
#include "session/network/session_network_types.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    inline auto cat = log::Cat("network");
}

// TODO: Should the `ALPN` be changed to an argument passed into the `connect` function?
constexpr auto ALPN = "oxenstorage";

QuicTransport::QuicTransport(
        config::QuicTransportConfig config, std::shared_ptr<oxen::quic::Loop> loop) :
        _config{std::move(config)}, _loop{loop} {
    log::trace(cat, "[QuicTransport] Initializing.");
    _endpoint = quic::Endpoint::endpoint(
            *_loop,
            quic::Address{"0.0.0.0", 0},
            quic::opt::alpns{ALPN},
            (config.disable_mtu_discovery ? std::optional<quic::opt::disable_mtu_discovery>{}
                                          : std::nullopt));
}

QuicTransport::~QuicTransport() {
    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this] { _close_connections(); });
    log::debug(cat, "[QuicTransport] Destroyed.");
}

// MARK: ITransport

void QuicTransport::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;
        _close_connections();
        log::info(cat, "[QuicTransport] Suspended.");
    });
}

void QuicTransport::resume() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = false;
        log::info(cat, "[QuicTransport] Resumed.");
    });
}

void QuicTransport::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
}

void QuicTransport::set_node_failure_reporter(node_failure_reporter_t reporter) {
    _loop->call([this, r = std::move(reporter)] { _report_node_failure.emplace(std::move(r)); });
}

void QuicTransport::verify_connectivity(
        service_node node,
        std::chrono::milliseconds timeout,
        const std::string& context_id,
        std::function<void(bool success)> callback) {
    // For Quic, a successful connection IS a successful ping so we can just check for an existing
    // connection and, if one doesn't exist, try to establish one
    _loop->call([this, node = std::move(node), cb = std::move(callback), context_id]() {
        const auto pubkey_hex = oxenc::to_hex(node.view_remote_key());

        // If we already have a connection we can stop here
        if (_active_connection_ids.count(pubkey_hex) || _pending_requests.count(pubkey_hex))
            return cb(true);

        _pending_verification_callbacks[pubkey_hex].push_back(std::move(cb));

        // Only try to establish a connection if we are the first to ask for one
        if (_pending_requests.count(pubkey_hex) == 0 &&
            _pending_verification_callbacks.at(pubkey_hex).size() == 1)
            _establish_connection({node.view_remote_key(), node.host(), node.omq_port}, context_id);
    });
}

void QuicTransport::add_failure_listener(const ed25519_pubkey& pubkey, std::function<void()> listener) {
    _loop->call([this, pk_hex = pubkey.hex(), l = std::move(listener)]() mutable {
        _failure_listeners[pk_hex].push_back(std::move(l));
    });
}

void QuicTransport::remove_failure_listeners(const ed25519_pubkey& pubkey) {
    _loop->call([this, pk_hex = pubkey.hex()] {
        _failure_listeners.erase(pk_hex);
    });
}

void QuicTransport::send_request(Request request, network_response_callback_t callback) {
    log::trace(cat, "[QuicTransport] Dispatching request {} to loop.", request.request_id);
    _loop->call([this, req = std::move(request), cb = std::move(callback)] {
        _send_request_internal(std::move(req), std::move(cb));
    });
}

// MARK: Internal Logic

void QuicTransport::_close_connections() {
    // Explicitly close all connections then reset the endpoint
    if (_endpoint)
        _endpoint->close_conns();
    _endpoint.reset();

    // Cancel any pending verifications (they can't succeed once the connection is closed)
    for (const auto& [pubkey, callbacks] : _pending_verification_callbacks)
        for (const auto& callback : callbacks)
            callback(false);

    // Cancel any pending requests (they can't succeed once the connection is closed)
    for (const auto& [pubkey, pupkey_requests] : _pending_requests)
        for (const auto& [info, callback] : pupkey_requests)
            callback(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "QuickTransport is suspended.");

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch
    _ephemeral_connection_ids.clear();
    _active_connection_ids.clear();
    _active_stream_ids.clear();
    _pending_verification_callbacks.clear();
    _pending_requests.clear();

    _update_status(ConnectionStatus::disconnected);
    log::info(cat, "[QuicTransport] Closed all connections.");
}

void QuicTransport::_update_status(ConnectionStatus new_status) {
    ConnectionStatus old_status = _status.load();
    if (old_status == new_status)
        return;

    // Prevent swapping from "connected" back to "connecting" if a background connection is being
    // established while we are already connected
    if (old_status == ConnectionStatus::connected && new_status == ConnectionStatus::connecting)
        return;

    // If we already tried to reconnect but failed, then we want to prevent swapping between
    // "disconnected" and "connecting"
    if (old_status == ConnectionStatus::disconnected &&
        new_status == ConnectionStatus::connecting && _has_attempted_reconnect)
        return;

    _status.store(new_status);

    if (old_status == ConnectionStatus::disconnected && new_status == ConnectionStatus::connecting)
        _has_attempted_reconnect = true;

    if (new_status == ConnectionStatus::connected)
        _has_attempted_reconnect = false;

    if (on_status_changed)
        on_status_changed();
}

void QuicTransport::_send_request_internal(Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "QuickTransport is suspended.");

    std::optional<oxen::quic::RemoteAddress> remote;

    std::visit(
            [&remote, request_id = request.request_id](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;

                if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                    log::trace(
                            cat,
                            "[QuicTransport Request {}]: Using pre-resolved RemoteAddress.",
                            request_id);
                    remote = arg;
                } else if constexpr (std::is_same_v<T, service_node>) {
                    log::trace(
                            cat,
                            "[QuicTransport Request {}]: Resolving service_node to RemoteAddress.",
                            request_id);
                    remote.emplace(arg.view_remote_key(), arg.host(), arg.omq_port);
                }
            },
            request.destination);

    if (!remote) {
        log::critical(
                cat, "[QuicTransport Request {}] Invalid destination type!", request.request_id);
        return callback(
                false,
                false,
                -1,
                {content_type_plain_text},
                "Internal error: invalid destination for QuicTransport");
    }

    const auto remote_pubkey_hex = oxenc::to_hex(remote->view_remote_key());

    // If an active connection exists then we can send the request over that
    if (auto it = _active_connection_ids.find(remote_pubkey_hex);
        it != _active_connection_ids.end()) {
        log::trace(
                cat, "[QuicTransport Request {}] Found active connection ID.", request.request_id);
        _send_on_connection(it->second, std::move(request), std::move(callback));
        return;
    }

    // If we should already be establishing a connection then we can just add this as a pending
    // request and it'll be picked up once the connection is made
    if (_pending_requests.count(remote_pubkey_hex)) {
        log::debug(
                cat,
                "[QuicTransport Request {}] Connection to {} is pending, queueing request.",
                request.request_id,
                remote_pubkey_hex);
        _pending_requests[remote_pubkey_hex].emplace_back(std::move(request), std::move(callback));
        return;
    }

    // No connection exists so we need to start a new one and queue the request
    log::info(
            cat,
            "[QuicTransport Request {}] No connection to {}, initiating new connection.",
            request.request_id,
            remote_pubkey_hex);
    std::string initiating_req_id = request.request_id;
    _pending_requests[remote_pubkey_hex].emplace_back(std::move(request), std::move(callback));
    _establish_connection(*remote, initiating_req_id);
}

void QuicTransport::_establish_connection(
        const oxen::quic::RemoteAddress& address, const std::string& initiating_req_id) {
    const auto address_pubkey_hex = oxenc::to_hex(address.view_remote_key());
    auto conn_key_pair = ed25519::ed25519_key_pair();
    auto creds = quic::GNUTLSCreds::make_from_ed_seckey(to_string_view(conn_key_pair.second));

    // If we are starting a connection attempt then transition to the "connecting" state
    if (_status.load() == ConnectionStatus::unknown ||
        _status.load() == ConnectionStatus::disconnected)
        _update_status(ConnectionStatus::connecting);

    log::debug(
            cat,
            "[QuicTransport Request {}] Establishing new connection to {}.",
            initiating_req_id,
            address_pubkey_hex);
    _endpoint->connect(
            address,
            creds,
            oxen::quic::opt::handshake_timeout{_config.handshake_timeout},
            oxen::quic::opt::keep_alive{_config.keep_alive},
            [this, address_pubkey_hex, initiating_req_id](oxen::quic::Connection& conn) {
                log::info(
                        cat,
                        "[QuicTransport Request {}] Successfully established connection to {}.",
                        initiating_req_id,
                        address_pubkey_hex);

                auto stream = conn.open_stream<oxen::quic::BTRequestStream>();
                auto conn_id = conn.reference_id();
                auto stream_id = stream->stream_id();
                auto verification_callbacks =
                        std::move(_pending_verification_callbacks[address_pubkey_hex]);
                _pending_verification_callbacks.erase(address_pubkey_hex);

                auto requests_to_process = std::move(_pending_requests[address_pubkey_hex]);
                _pending_requests.erase(address_pubkey_hex);

                // Only persistent requests verify connectivity so if there is a verification
                // callback then it should be persistent, otherwise if ANY of the requests require
                // persistence then we should store the connection (if we don't store it then the
                // connection will timeout and be closed)
                bool is_persistent = !verification_callbacks.empty();
                if (!is_persistent)
                    is_persistent = std::any_of(
                            requests_to_process.begin(),
                            requests_to_process.end(),
                            [](const auto& req_pair) {
                                return !req_pair.first.ephemeral_connection;
                            });

                if (is_persistent) {
                    _ephemeral_connection_ids.erase(conn_id);  // Just in case
                    _active_connection_ids.insert_or_assign(address_pubkey_hex, conn_id);
                } else
                    _ephemeral_connection_ids.insert(conn_id);

                _active_stream_ids.insert_or_assign(conn_id, stream_id);

                // We had a successful connection so update the status to connected
                _update_status(ConnectionStatus::connected);

                for (const auto& pending_cb : verification_callbacks)
                    pending_cb(true);

                if (!requests_to_process.empty()) {
                    log::debug(
                            cat,
                            "[QuicTransport] Processing {} pending requests on new stream {} with "
                            "conn {}.",
                            requests_to_process.size(),
                            stream_id,
                            conn_id.to_string());

                    for (auto&& [req, cb] : std::move(requests_to_process))
                        _send_on_connection(conn_id, std::move(req), std::move(cb));
                }
            },
            [this, address_pubkey_hex, initiating_req_id](
                    oxen::quic::Connection& conn, uint64_t error_code) {
                auto conn_id = conn.reference_id();

                if (error_code == NGTCP2_NO_ERROR)
                    log::info(
                            cat,
                            "[QuicTransport Request {}] Connection to {} closed gracefully.",
                            initiating_req_id,
                            address_pubkey_hex);
                else if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT)) {
                    log::warning(
                            cat,
                            "[QuicTransport Request {}] Handshake timeout when connecting to {}. "
                            "The node is likely unreachable.",
                            initiating_req_id,
                            address_pubkey_hex);

                    // If the connection failed with a handshake timeout then the node is
                    // unreachable, either due to a device network issue or because the node is down
                    // so permanently fail the node so it won't be used for subsequent requests
                    // (until the next cache refresh)
                    if (_report_node_failure)
                        (*_report_node_failure)(ed25519_pubkey::from_hex(address_pubkey_hex), true);
                } else
                    log::warning(
                            cat,
                            "[QuicTransport Request {}] Connection to {} failed or was closed with "
                            "error code: {}",
                            initiating_req_id,
                            address_pubkey_hex,
                            error_code);

                _ephemeral_connection_ids.erase(conn_id);
                _active_connection_ids.erase(address_pubkey_hex);
                _active_stream_ids.erase(conn_id);

                // Process any waiting verification requests
                if (auto it = _pending_verification_callbacks.find(address_pubkey_hex);
                    it != _pending_verification_callbacks.end()) {
                    for (const auto& pending_cb : it->second)
                        pending_cb(false);
                    _pending_verification_callbacks.erase(it);
                }

                // Fail all the pending requests for this connection
                if (auto it = _pending_requests.find(address_pubkey_hex);
                    it != _pending_requests.end()) {
                    auto to_fail = std::move(it->second);
                    _pending_requests.erase(it);

                    std::string failure_reason = "Failed to establish connection to service node";
                    if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
                        failure_reason += " (handshake timeout)";

                    log::error(
                            cat,
                            "[QuicTransport] Failing {} pending requests due to connection "
                            "failure.",
                            to_fail.size());

                    for (auto& [req, cb] : to_fail)
                        cb(false, false, -1, {content_type_plain_text}, failure_reason);
                }

                // Notify any failure listeners that the connection has been closed
                if (auto it = _failure_listeners.find(address_pubkey_hex); it != _failure_listeners.end()) {
                    auto to_fail = std::move(it->second);
                    _failure_listeners.erase(it);

                    for (const auto& listener : it->second)
                        listener();
                }

                // If we have no longer have any active connections then we are disconnected
                if (_active_connection_ids.empty())
                    _update_status(ConnectionStatus::disconnected);
            });
}

void QuicTransport::_send_on_connection(
        oxen::quic::ConnectionID conn_id, Request request, network_response_callback_t callback) {
    // Try to retrieve the active connection first
    auto conn = _endpoint->get_conn(conn_id);
    if (!conn) {
        log::warning(
                cat,
                "[QuicTransport Request {}] Attempted to send on a connection (ID {}) that no "
                "longer exists.",
                request.request_id,
                conn_id.to_string());

        // Since the connection is dead we should remove it from our active list and fail the
        // request (the client can retry if they want)
        for (auto it = _active_connection_ids.begin(); it != _active_connection_ids.end(); ++it) {
            if (it->second == conn_id) {
                _active_connection_ids.erase(it);
                break;
            }
        }
        _active_stream_ids.erase(conn_id);

        return callback(
                false,
                false,
                -1,
                {content_type_plain_text},
                "Connection died before request could be sent");
    }

    // Then try to get an active stream for this connection
    auto stream_it = _active_stream_ids.find(conn_id);
    if (stream_it == _active_stream_ids.end()) {
        // Something has gone horribly wrong, lets close the connection and the client can retry
        log::critical(
                cat,
                "[QuicTransport Request {}] No stream ID found for active connection {}, closing "
                "connection.",
                request.request_id,
                conn_id.to_string());
        conn->close_connection();
        return callback(
                false,
                false,
                -1,
                {content_type_plain_text},
                "Internal error: Stream state missing for active connection");
    }

    auto stream_id = stream_it->second;
    auto stream = conn->get_stream<oxen::quic::BTRequestStream>(stream_id);
    if (!stream) {
        // Similar to the above, if the stream is gone then the connection ir probably in a bad
        // state so we should just close it
        log::warning(
                cat,
                "[QuicTransport Request {}] Stream {} on connection {} has died, closing "
                "connection.",
                request.request_id,
                stream_id,
                conn_id.to_string());
        conn->close_connection();
        return callback(
                false, false, -1, {content_type_plain_text}, "Connection stream was closed");
    }

    // If the request has already timedout at this point then just fail it immediately
    auto timeout = request.time_remaining();
    if (timeout <= std::chrono::milliseconds::zero())
        return callback(false, true, 408, {content_type_plain_text}, "Request already timed out");

    // We have a valid connection and stream so we can send the request
    log::debug(
            cat,
            "[QuicTransport Request {}] Sending on stream {} with conn {}",
            request.request_id,
            stream_id,
            conn_id.to_string());

    std::span<const std::byte> payload{};

    if (request.body)
        payload = to_span<std::byte>(*request.body);

    stream->command(
            request.endpoint,
            payload,
            timeout,
            [this, cb = std::move(callback), conn_id, stream_id, req_id = request.request_id](
                    quic::message resp) {
                log::trace(cat, "[QuicTransport Request {}] Received response.", req_id);

                // If this connection was an ephemeral connection then we should close it (don't
                // want to keep it alive longer than needed)
                if (_ephemeral_connection_ids.count(conn_id)) {
                    _ephemeral_connection_ids.erase(conn_id);
                    _active_stream_ids.erase(conn_id);

                    if (auto conn = _endpoint->get_conn(conn_id))
                        conn->close_connection();
                }

                // Trigger the callback based on the response we got
                if (resp.timed_out) {
                    log::debug(cat, "[QuicTransport Request {}] Timed out.", req_id);
                    return cb(false, true, 408, {content_type_plain_text}, "Request timed out");
                }

                if (resp.is_error()) {
                    auto final_timeout = resp.timed_out;
                    auto final_status_code = -1;
                    std::string err_body =
                            (resp.body().empty() ? "Unknown QUIC layer error"
                                                 : std::string{resp.body()});

                    // The response doesn't provide a status code but the body can include it, in
                    // which case we should try to extract it from the body so we can perform any
                    // status code related logic
                    if (auto result = Response::parse_text_error(err_body)) {
                        final_status_code = result->first;
                        final_timeout = result->second;
                    }

                    log::debug(
                            cat,
                            "[QuicTransport Request {}] Failed with QUIC error: {}.",
                            req_id,
                            err_body);
                    return cb(
                            false,
                            final_timeout,
                            final_status_code,
                            {content_type_plain_text},
                            err_body);
                }

                log::debug(
                        cat, "[QuicTransport Request {}] Received raw success response.", req_id);
                cb(true, false, 200, {}, std::string{resp.body()});
            });
}

}  // namespace session::network
