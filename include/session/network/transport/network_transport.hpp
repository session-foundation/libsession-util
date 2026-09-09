#pragma once

#include "session/network/session_network_types.hpp"

namespace session::network {

class ITransport {
  public:
    std::function<void()> on_status_changed;

    /// Called when the far end sends us something we did not ask for, on a connection we are
    /// already holding.  A swarm subscription is delivered this way: having subscribed, the
    /// storage server pushes each matching message as a request of its own rather than as a
    /// response to anything.
    ///
    /// `node` is the far end's ed25519 pubkey, which is the key the connection is addressed by
    /// whether it reached the node directly or through a tunnel, so it names the swarm member
    /// either way.  `endpoint` and `body` are the pushed request's, unparsed: the transport does
    /// not know what any of them mean.
    ///
    /// No reply is sent.  Nothing that pushes to us expects one, and answering a request the far
    /// end is not tracking would only be discarded.
    ///
    /// Runs on the network loop and must not throw.
    std::function<void(
            const ed25519_pubkey& node,
            std::string_view endpoint,
            std::span<const std::byte> body)>
            on_server_push;

    /// Called once a connection to `node` is up and requests can be sent on it, including when it
    /// comes back after having been lost.  The counterpart to `add_failure_listener`, and the
    /// point at which per-connection state the far end holds -- a subscription, say -- has to be
    /// established again, since the far end keys that state on the connection and the old one is
    /// gone.
    ///
    /// Runs on the network loop and must not throw.
    std::function<void(const ed25519_pubkey& node)> on_connection_established;

    /// Called when a connection to `node` is gone, for any reason: closed, failed, or timed out.
    /// Whatever the far end was holding for that connection is gone with it.
    ///
    /// Unlike `add_failure_listener` this is not one-shot and not per-node: it reports every
    /// connection this transport loses, and stays registered.
    ///
    /// Runs on the network loop and must not throw.
    std::function<void(const ed25519_pubkey& node)> on_connection_lost;

    virtual ~ITransport() = default;

    virtual void suspend() = 0;
    virtual void resume(bool automatically_reconnect = true) = 0;
    virtual void close_connections() = 0;

    virtual ConnectionStatus get_status() const = 0;
    virtual void set_node_failure_reporter(node_failure_reporter_t) {}
    virtual void verify_connectivity(
            service_node node,
            std::chrono::milliseconds timeout,
            const std::string& request_id,
            const RequestCategory category,
            std::function<void(bool success, std::optional<uint64_t> error_code)> callback) = 0;
    virtual void add_failure_listener(
            const ed25519_pubkey& pubkey, std::function<void()> listener) = 0;
    virtual void remove_failure_listeners(const ed25519_pubkey& pubkey) = 0;

    virtual void send_request(Request request, network_response_callback_t callback) = 0;
};

}  // namespace session::network
