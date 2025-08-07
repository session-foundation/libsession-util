#pragma once

#include <filesystem>
#include <limits>
#include <lokinet.hpp>
#include <oxen/quic.hpp>

#include "session/network/network_config.hpp"
#include "session/network/snode_pool.hpp"
#include "session/network/network_transport.hpp"
#include "session/network/network_router.hpp"
#include "session/types.hpp"

namespace session::network {

namespace fs = std::filesystem;

class Network_v2 {
  private:
    const config::Config config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<SnodePool> _snode_pool;
    std::shared_ptr<ITransport> _transport;
    std::shared_ptr<IRouter> _router;

  public:
    template <typename... Opt>
        requires(!std::is_same_v<std::decay_t<std::tuple_element_t<0, std::tuple<Opt...>>>, config::Config>)
    Network_v2(Opt&&... opts) : Network_v2(Config(std::forward<Opt>(opts)...)){};
    explicit Network_v2(config::Config config);

    virtual ~Network_v2();

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

    void send_request(Request request, network_response_callback_t callback);

  private:
    void configure();
};

}  // namespace session::network
