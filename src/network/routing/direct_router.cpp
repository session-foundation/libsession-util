#include "session/network/routing/direct_router.hpp"

#include <fmt/ranges.h>
#include <fmt/std.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "session/network/network_opt.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    auto cat = oxen::log::Cat("direct-router");
}  // namespace

DirectRouter::DirectRouter(
        config::DirectRouter config,
        std::shared_ptr<oxen::quic::Loop> loop,
        std::weak_ptr<ITransport> transport) :
        _config{config}, _loop{loop}, _transport{transport} {
    log::trace(cat, "Initializing.");
    _update_status(ConnectionStatus::connected);
}

DirectRouter::~DirectRouter() {
    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this] { _update_status(ConnectionStatus::disconnected); });
    log::debug(cat, "Destroyed.");
}

// MARK: IRouter

void DirectRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;
        log::info(cat, "Suspended.");
    });
}

void DirectRouter::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        if (!_suspended)
            return;

        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void DirectRouter::send_request(Request request, network_response_callback_t callback) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request), cb = std::move(callback)] {
        if (auto self = weak_self.lock())
            self->_send_request_internal(std::move(req), std::move(cb));
    });
}

void DirectRouter::upload(UploadRequest request) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request)] {
        if (auto self = weak_self.lock())
            self->_upload_internal(std::move(req));
    });
}

void DirectRouter::download(DownloadRequest request) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request)] {
        if (auto self = weak_self.lock())
            self->_download_internal(std::move(req));
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
        log::critical(cat, "Transport was destroyed, cannot send request.");
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

void DirectRouter::_upload_internal(UploadRequest request) {
    const auto upload_id = "UP-" + random::random_base32(4);
    log::info(cat, "[Upload {}]: Starting upload.", upload_id);
    _active_uploads[upload_id] = request;

    // Accumulate data on a background thread as we don't know whether `next_data` is doing file I/O
    // or just reading from memory (it's a bit of a waste if it's in-memory data but loading from
    // disk should be prioritised)
    std::thread([weak_self = weak_from_this(),
                 this,
                 upload_request = request,
                 upload_id,
                 file_server_config = _config.file_server_config] {
        auto self = weak_self.lock();
        if (!self)
            return;

        // Onion requests don't support streaming data so we need to load all the data from the
        // streaming source into memory
        try {
            Request request =
                    file_server::to_request(upload_id, file_server_config, upload_request);

            _loop->call([weak_self, this, upload_request, req = std::move(request), upload_id] {
                auto self = weak_self.lock();
                if (!self)
                    return;

                if (upload_request.is_cancelled() || !req.body) {
                    log::debug(cat, "[Upload {}]: Cancelled before sending request.", upload_id);
                    upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                    self->_active_uploads.erase(upload_id);
                    return;
                }

                const auto upload_size = req.body->size();
                log::debug(
                        cat,
                        "[Upload {}]: Accumulated {} bytes, building request.",
                        upload_id,
                        upload_size);

                _send_request_internal(
                        std::move(req),
                        [weak_self, this, upload_id, upload_request, upload_size](
                                bool success,
                                bool timeout,
                                int16_t status_code,
                                std::vector<std::pair<std::string, std::string>> headers,
                                std::optional<std::string> body) {
                            auto self = weak_self.lock();
                            if (!self)
                                return;

                            _active_uploads.erase(upload_id);

                            try {
                                if (upload_request.is_cancelled())
                                    throw cancellation_exception{"Cancelled during request."};

                                if (!success || timeout)
                                    throw status_code_exception{
                                            status_code,
                                            headers,
                                            fmt::format(
                                                    "Request failed with status {}, timeout={}.",
                                                    status_code,
                                                    timeout)};

                                if (!body)
                                    throw std::runtime_error{"No response body."};

                                auto metadata =
                                        file_server::parse_upload_response(*body, upload_size);
                                log::info(
                                        cat,
                                        "[Upload {}]: Successfully uploaded {} bytes as file ID: "
                                        "{}",
                                        upload_id,
                                        metadata.size,
                                        metadata.id);

                                upload_request.on_complete(std::move(metadata), false);
                            } catch (const status_code_exception& e) {
                                log::error(
                                        cat,
                                        "[Upload {}]: Failure with error: {}",
                                        upload_id,
                                        e.what());
                                upload_request.on_complete(e.status_code, false);
                            } catch (const std::exception& e) {
                                log::error(
                                        cat,
                                        "[Upload {}]: Failure with error: {}",
                                        upload_id,
                                        e.what());
                                upload_request.on_complete(ERROR_INTERNAL_SERVER_ERROR, false);
                            }
                        });
            });
        } catch (const std::exception& e) {
            _loop->call([weak_self, this, upload_request, upload_id, err = e.what()] {
                auto self = weak_self.lock();
                if (!self)
                    return;

                log::error(cat, "[Upload {}]: Exception during upload: {}", upload_id, err);
                upload_request.on_complete(ERROR_INTERNAL_SERVER_ERROR, false);
                _active_uploads.erase(upload_id);
            });
        }
    }).detach();
}

void DirectRouter::_download_internal(DownloadRequest request) {
    const auto download_id = "DL-" + random::random_base32(4);
    log::info(cat, "[Download {}]: Starting download.", download_id);
    _active_downloads[download_id] = request;

    try {
        Request req = file_server::to_request(download_id, _config.file_server_config, request);

        send_request(
                std::move(req),
                [weak_self = weak_from_this(), this, download_id, request](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> body) {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    _active_downloads.erase(download_id);

                    try {
                        if (request.is_cancelled())
                            throw cancellation_exception{"Cancelled during request."};

                        if (!success || timeout)
                            throw status_code_exception{
                                    status_code,
                                    headers,
                                    fmt::format(
                                            "Request failed with status {}, timeout={}.",
                                            status_code,
                                            timeout)};

                        if (!body)
                            throw std::runtime_error{"No response body."};

                        auto [metadata, data] = file_server::parse_download_response(
                                request.download_url, headers, *body);
                        log::info(
                                cat,
                                "[Download {}]: Successfully downloaded {} bytes for file ID: {}",
                                download_id,
                                data.size(),
                                metadata.id);

                        if (request.on_data)
                            request.on_data(metadata, std::move(data));

                        request.on_complete(std::move(metadata), false);
                    } catch (const status_code_exception& e) {
                        log::error(
                                cat,
                                "[Download {}]: Failure with error: {}",
                                download_id,
                                e.what());
                        request.on_complete(e.status_code, false);
                    } catch (const std::exception& e) {
                        log::error(
                                cat,
                                "[Download {}]: Failure with error: {}",
                                download_id,
                                e.what());
                        request.on_complete(ERROR_INTERNAL_SERVER_ERROR, false);
                    }
                });
    } catch (const invalid_url_exception& e) {
        log::error(cat, "[Download {}]: Exception during download: {}", download_id, e.what());
        request.on_complete(ERROR_INVALID_DOWNLOAD_URL, false);
        _active_downloads.erase(download_id);
    } catch (const std::exception& e) {
        log::error(cat, "[Download {}]: Exception during download: {}", download_id, e.what());
        request.on_complete(ERROR_INTERNAL_SERVER_ERROR, false);
        _active_downloads.erase(download_id);
    }
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
