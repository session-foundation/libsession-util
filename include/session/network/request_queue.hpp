#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <oxen/quic/loop.hpp>

#include "session/network/session_network_types.hpp"
#include "session/network/transport/network_transport.hpp"

namespace session::network::detail {

class RequestQueue : public std::enable_shared_from_this<RequestQueue> {
  private:
    friend class TestRequestQueue;

    std::shared_ptr<oxen::quic::Loop> _loop;
    std::chrono::milliseconds _check_frequency;

    std::deque<std::pair<Request, network_response_callback_t>> _queue;
    bool _checker_active = false;

  public:
    RequestQueue(
            std::shared_ptr<oxen::quic::Loop> loop, std::chrono::milliseconds check_frequency) :
            _loop{std::move(loop)}, _check_frequency{check_frequency} {};
    ~RequestQueue();

    bool is_empty() const { return _queue.empty(); };

    virtual void add(Request request, network_response_callback_t callback);
    virtual void add_front(std::pair<Request, network_response_callback_t> req_pair);

    virtual std::deque<std::pair<Request, network_response_callback_t>> pop_all();

  private:
    virtual void check_timeouts();
};

}  // namespace session::network::detail
