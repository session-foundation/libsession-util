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
    std::unique_ptr<SnodePool> _snode_pool;
    std::unique_ptr<ITransport> _transport;
    std::unique_ptr<IRouter> _router;

  public:
    template <typename... Opt>
        requires(!std::is_same_v<std::decay_t<std::tuple_element_t<0, std::tuple<Opt...>>>, config::Config>)
    Network_v2(Opt&&... opts) : Network_v2(Config(std::forward<Opt>(opts)...)){};
    explicit Network_v2(config::Config config);

    virtual ~Network_v2();

    void send_request(Request request, network_response_callback_t callback);

  private:
    void configure();
};

}  // namespace session::network
