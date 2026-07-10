#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <oxen/quic/loop.hpp>
#include <oxen/quic/utils.hpp>

#include "session/network/session_network_types.hpp"
#include "session/network/transport/network_transport.hpp"

namespace session::network::detail {

class RequestQueue : public std::enable_shared_from_this<RequestQueue> {
  private:
    friend class TestRequestQueue;

    std::shared_ptr<oxen::quic::Loop> _loop;
    oxen::quic::event_ptr _timeout;

    std::deque<std::string> _queue;
    std::unordered_map<std::string, std::pair<Request, network_response_callback_t>> _requests;
    std::multimap<std::chrono::steady_clock::time_point, std::string> _req_expiries;

    RequestQueue(std::shared_ptr<oxen::quic::Loop> loop) : _loop{std::move(loop)} {};

  public:
    static std::shared_ptr<RequestQueue> make(std::shared_ptr<oxen::quic::Loop> loop) {
        return std::shared_ptr<RequestQueue>{new RequestQueue{std::move(loop)}};
    }

    virtual ~RequestQueue();

    bool is_empty() const { return _requests.empty(); };

    virtual void add(Request request, network_response_callback_t callback);
    virtual void add_front(std::pair<Request, network_response_callback_t> req_pair);

    virtual std::deque<std::pair<Request, network_response_callback_t>> pop_all();

  private:
    virtual void check_timeouts(std::optional<std::chrono::steady_clock::time_point> now);
    virtual void update_timeout();
};

}  // namespace session::network::detail
