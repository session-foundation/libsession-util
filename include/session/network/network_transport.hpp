#pragma once

#include "session/network/session_network_types.hpp"

namespace session::network {

class ITransport {
public:
    virtual ~ITransport() = default;

    virtual void verify_connectivity(
        service_node node,
        std::chrono::milliseconds timeout,
        const std::string& request_id,
        std::function<void(bool success)> callback) = 0;

    virtual void send_request(Request request, network_response_callback_t callback) = 0;
};

} // namespace session::network