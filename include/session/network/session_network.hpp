#pragma once

#include <filesystem>
#include <limits>
#include <lokinet.hpp>
#include <oxen/quic.hpp>

#include "session/network/session_network_config.hpp"
#include "session/network/session_network_opt.hpp"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/key_types.hpp"
#include "session/platform.hpp"
#include "session/random.hpp"
#include "session/types.hpp"

namespace session::network {

namespace fs = std::filesystem;

using swarm_id_t = uint64_t;
constexpr swarm_id_t INVALID_SWARM_ID = std::numeric_limits<uint64_t>::max();

class Network_v2 {
  private:
    const Config config;
    std::shared_ptr<oxen::quic::Loop> loop;

  public:
    template <typename... Opt>
        requires(!std::is_same_v<std::decay_t<std::tuple_element_t<0, std::tuple<Opt...>>>, session::network::Config>)
    Network_v2(Opt&&... opts) : Network_v2(Config(std::forward<Opt>(opts)...)){};
    explicit Network_v2(session::network::Config config);

    virtual ~Network_v2();

  private:
    void configure();
};

}  // namespace session::network
