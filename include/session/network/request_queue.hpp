#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <oxen/quic/loop.hpp>
#include <oxen/quic/utils.hpp>

#include "session/network/session_network_types.hpp"
#include "session/network/transport/network_transport.hpp"

namespace session::network::detail {

/// Runs on a loop it does not own: the loop's owner outlives every queue on it, which is what lets
/// the jobs below capture `this` rather than a reference to this object.  See _jq.
class RequestQueue {
  private:
    friend class TestRequestQueue;

    oxen::quic::Loop& _loop;
    oxen::quic::event_ptr _timeout;

    std::deque<std::string> _queue;
    std::unordered_map<std::string, std::pair<Request, network_response_callback_t>> _requests;
    std::multimap<std::chrono::steady_clock::time_point, std::string> _req_expiries;

    /// This queue's own jobs, rather than the loop's shared one, so that ~RequestQueue can take
    /// them away from the loop: `stop()` waits out whatever is running and cancels the rest, and
    /// only then does anything else get torn down.  That is what makes capturing `this` in a job
    /// safe -- and it has to be a job of *this* queue for that to hold.
    ///
    /// Declared last so that it is also the first member destroyed, for the case where something
    /// destroys this object without the destructor below having run to completion.
    oxen::quic::JobQueue _jq{_loop};

  public:
    RequestQueue(oxen::quic::Loop& loop) : _loop{loop} {};

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
