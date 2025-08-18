#pragma once

#include <deque>
#include <chrono>
#include <memory>

#include "session/network/transport/network_transport.hpp"
#include "session/network/session_network_types.hpp"
#include <oxen/quic/loop.hpp>

namespace session::network::detail {

class RequestQueue {
private:
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::chrono::milliseconds _check_frequency;
    
    std::deque<std::pair<Request, network_response_callback_t>> _queue;
    bool _checker_active = false;
    
public:
    RequestQueue(std::shared_ptr<oxen::quic::Loop> loop, std::chrono::milliseconds check_frequency) : _loop{loop}, _check_frequency{check_frequency} {};
    ~RequestQueue();
    
    bool is_empty() const { return _queue.empty(); };

    void add(Request request, network_response_callback_t callback);
    void add_front(std::pair<Request, network_response_callback_t> req_pair);
    
    std::deque<std::pair<Request, network_response_callback_t>> pop_all();
    

private:
    void check_timeouts();
};

} // namespace session::network::detail
