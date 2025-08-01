#include "session/network/request_queue.hpp"

#include <fmt/ranges.h>

#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network::detail {

RequestQueue::~RequestQueue() {
    _loop->call_get([this] {
        for (auto& [category, callback] : _queue) {
            try {
                callback(false, false, -1, {content_type_plain_text}, "Request cancelled: networking system is shutting down");
            } catch (...) { /* Ignore exceptions during shutdown */ }
        }
    });
}

void RequestQueue::add(Request request, network_response_callback_t callback) {
    _loop->call([this, req = std::move(request), cb = std::move(callback)]() {
        _queue.emplace_back(std::move(req), std::move(cb));

        if (!_checker_active){
            _checker_active = true;
            _loop->call_later(_check_frequency, [this] { check_timeouts(); });
        }
    });
}

void RequestQueue::add_front(std::pair<Request, network_response_callback_t> req_pair) {
    _loop->call([this, pair = std::move(req_pair)] {
        _queue.emplace_front(std::move(pair));
        
        if (!_checker_active && pair.first.overall_timeout) {
            _checker_active = true;
            _loop->call_later(_check_frequency, [this] { check_timeouts(); });
        }
    });
}

std::deque<std::pair<Request, network_response_callback_t>> RequestQueue::pop_all() {
    return _loop->call_get([this] {
        std::deque<std::pair<Request, network_response_callback_t>> popped_items;
        std::swap(_queue, popped_items);
        
        return popped_items;
    });
}

void RequestQueue::check_timeouts() {
    auto time_now = std::chrono::system_clock::now();
    bool has_remaining_timeout_requests = false;

    std::erase_if(_queue, [&has_remaining_timeout_requests, &time_now](const auto& request) {
        // If the request doesn't have a path build timeout then ignore it
        if (!request.first.overall_timeout)
            return false;

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                time_now - request.first.creation_time);

        if (duration > *request.first.overall_timeout) {
            request.second(
                    false,
                    true,
                    ERROR_BUILD_TIMEOUT,
                    {content_type_plain_text},
                    "Timed out while in build queue.");
            return true;
        }

        has_remaining_timeout_requests = true;
        return false;
    });

    // If there are no more timeout requests then stop looping here
    if (!has_remaining_timeout_requests) {
        _checker_active = false;
        return;
    }

    // Otherwise schedule the next check
    _loop->call_later(_check_frequency, [this] { check_timeouts(); });
}

}  // namespace session::network::detail
