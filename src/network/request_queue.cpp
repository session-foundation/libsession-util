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
                callback(
                        false,
                        false,
                        -1,
                        {content_type_plain_text},
                        "Request cancelled: networking system is shutting down");
            } catch (...) { /* Ignore exceptions during shutdown */
            }
        }
    });
}

void RequestQueue::add(Request request, network_response_callback_t callback) {
    _loop->call([self = shared_from_this(), req = std::move(request), cb = std::move(callback)]() {
        auto has_timeout = req.overall_timeout.has_value();
        self->_queue.emplace_back(std::move(req), std::move(cb));

        if (has_timeout && !self->_checker_active) {
            self->_checker_active = true;

            auto weak_self = std::weak_ptr<RequestQueue>(self);
            self->_loop->call_later(self->_check_frequency, [weak_self] {
                if (auto self = weak_self.lock())
                    self->check_timeouts();
            });
        }
    });
}

void RequestQueue::add_front(std::pair<Request, network_response_callback_t> req_pair) {
    _loop->call([self = shared_from_this(), pair = std::move(req_pair)] {
        auto has_timeout = pair.first.overall_timeout.has_value();
        self->_queue.emplace_front(std::move(pair));

        if (has_timeout && !self->_checker_active) {
            self->_checker_active = true;

            auto weak_self = std::weak_ptr<RequestQueue>(self);
            self->_loop->call_later(self->_check_frequency, [weak_self] {
                if (auto self = weak_self.lock())
                    self->check_timeouts();
            });
        }
    });
}

std::deque<std::pair<Request, network_response_callback_t>> RequestQueue::pop_all() {
    return _loop->call_get([self = shared_from_this()] {
        std::deque<std::pair<Request, network_response_callback_t>> popped_items;
        std::swap(self->_queue, popped_items);

        return popped_items;
    });
}

void RequestQueue::check_timeouts() {
    auto time_now = std::chrono::system_clock::now();
    bool has_remaining_timeout_requests = false;

    std::erase_if(_queue, [&has_remaining_timeout_requests, &time_now](const auto& request) {
        // If the request doesn't have an overall timeout then ignore it
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
    auto weak_self = std::weak_ptr<RequestQueue>(shared_from_this());
    _loop->call_later(_check_frequency, [weak_self] {
        if (auto self = weak_self.lock())
            self->check_timeouts();
    });
}

}  // namespace session::network::detail
