#include "session/network/routing/direct_router.hpp"

#include <fmt/ranges.h>
#include <fmt/std.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "session/network/network_opt.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    auto cat = oxen::log::Cat("network");
}  // namespace

DirectRouter::DirectRouter(
        std::shared_ptr<oxen::quic::Loop> loop, std::weak_ptr<ITransport> transport) :
        _loop{std::move(loop)}, _transport{transport} {
    log::trace(cat, "[DirectRouter] Initializing.");
    _update_status(ConnectionStatus::connected);
}

DirectRouter::~DirectRouter() {
    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this] { _update_status(ConnectionStatus::disconnected); });
    log::debug(cat, "[DirectRouter] Destroyed.");
}

// MARK: IRouter

void DirectRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;
        log::info(cat, "[DirectRouter] Suspended.");
    });
}

void DirectRouter::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        if (!_suspended)
            return;

        _suspended = false;
        log::info(cat, "[DirectRouter] Resumed.");
    });
}

void DirectRouter::send_request(Request request, network_response_callback_t callback) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request), cb = std::move(callback)] {
        if (auto self = weak_self.lock())
            self->_send_request_internal(std::move(req), std::move(cb));
    });
}

// MARK: Internal Logic

void DirectRouter::_update_status(ConnectionStatus new_status) {
    ConnectionStatus old_status = _status.load();
    if (old_status == new_status)
        return;

    _status.store(new_status);

    if (on_status_changed)
        on_status_changed();
}

void DirectRouter::_send_request_internal(Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "DirectRouter is suspended.");

    auto transport = _transport.lock();
    if (!transport) {
        log::critical(cat, "[DirectRouter] Transport was destroyed, cannot send request.");
        return;
    }

    transport->send_request(
            std::move(request),
            [weak_self = weak_from_this(), cb = std::move(callback)](
                    bool success, bool timeout, int16_t status_code, auto headers, auto response) {
                if (auto self = weak_self.lock())
                    self->_handle_transport_response(
                            success,
                            timeout,
                            status_code,
                            std::move(headers),
                            std::move(response),
                            std::move(cb));
            });
}

void DirectRouter::_handle_transport_response(
        bool success,
        bool timeout,
        int16_t status_code_,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> response_body,
        network_response_callback_t callback) {
    // If we weren't given a body then just return the data directly
    if (!response_body)
        return callback(success, timeout, status_code_, headers, response_body);

    // If the response isn't JSON then just return it directly
    if (!nlohmann::json::accept(*response_body))
        return callback(success, timeout, status_code_, headers, *response_body);

    // Otherwise the response will be a json array of [{status_code}, {body}]
    try {
        nlohmann::json response_json = nlohmann::json::parse(*response_body);

        if (!response_json.is_array() || response_json.size() != 2)
            throw std::runtime_error{"Unexpected JSON response structure."};

        uint16_t status_code = response_json[0].get<uint16_t>();
        std::string data = response_json[1].dump();
        return callback(success, timeout, status_code, headers, data);
    } catch (const std::exception& e) {
        return callback(false, timeout, status_code_, {content_type_plain_text}, e.what());
    }
}

}  // namespace session::network
