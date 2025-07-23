#pragma once

#include "session/network/network_transport.hpp" 

namespace session::network {

class IRouter {
public:
    virtual ~IRouter() = default;

    virtual void send_request(Request request, network_response_callback_t callback) = 0;
};

} // namespace session::network