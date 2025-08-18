#pragma once

#include "session/network/transport/network_transport.hpp"

namespace session::network {

class IRouter {
  public:
    virtual ~IRouter() = default;

    virtual std::vector<service_node> get_all_used_nodes() { return {}; };
    virtual void send_request(Request request, network_response_callback_t callback) = 0;
};

}  // namespace session::network