#pragma once

#include <filesystem>
#include <limits>
#include <lokinet.hpp>
#include <oxen/quic.hpp>

#include "session/network/network_config.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"
#include "session/network/transport/network_transport.hpp"
#include "session/platform.hpp"
#include "session/types.hpp"

namespace session::network {

namespace fs = std::filesystem;

class Network {
  private:
    const config::Config config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<SnodePool> _snode_pool;
    std::shared_ptr<ITransport> _transport;
    std::shared_ptr<IRouter> _router;
    bool _suspended = false;

  public:
    // Hook to be notified whenever the network connection status changes.
    std::function<void(ConnectionStatus status)> on_status_changed;
    std::function<void(std::chrono::milliseconds network_time_offset, int hardfork, int softfork)> on_network_info_changed;

    template <typename... Opt>
        requires(!std::is_same_v<
                 std::decay_t<std::tuple_element_t<0, std::tuple<Opt...>>>,
                 config::Config>)
    Network(Opt&&... opts) : Network(Config(std::forward<Opt>(opts)...)){};
    explicit Network(config::Config config);
    virtual ~Network();

    std::chrono::milliseconds network_time_offset() const { return _network_time_offset; };
    fork_versions fork() const { return _fork_versions.load(); };
    uint16_t hardfork() const { return _fork_versions.load().hardfork; };
    uint16_t softfork() const { return _fork_versions.load().softfork; };

    void suspend();
    void resume(bool automatically_reconnect = true);
    void close_connections();
    void clear_cache();

    ConnectionStatus get_status();
    std::vector<PathInfo> get_active_paths();

    /// API: network/get_swarm
    ///
    /// Retrieves the swarm for the given pubkey.  If there is already an entry in the cache for the
    /// swarm then that will be returned, otherwise a network request will be made to retrieve the
    /// swarm and save it to the cache.
    ///
    /// Inputs:
    /// - 'swarm_pubkey' - [in] public key for the swarm.
    /// - 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
    /// the callback will be called with an empty list).
    void get_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback);

    /// API: network/get_random_nodes
    ///
    /// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
    /// new pool will be populated and the nodes will be retrieved from that.
    ///
    /// Inputs:
    /// - 'count' - [in] the number of nodes to retrieve.
    /// - 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
    /// the callback will be called with an empty list).
    void get_random_nodes(
            uint16_t count, std::function<void(std::vector<service_node> nodes)> callback);

    void send_request(Request request, network_response_callback_t callback);

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};
    std::atomic<std::chrono::milliseconds> _network_time_offset{0ms};
    std::atomic<fork_versions> _fork_versions{{0, 0}};

    void configure();

    void _close_connections();
    void _recalculate_status();
    void _update_status(ConnectionStatus new_status);
    void _update_network_state(const std::string& body);
    void _handle_421_retry(Request original_request, network_response_callback_t final_callback);
    Request _preprocess_request(Request request);
};

}  // namespace session::network
