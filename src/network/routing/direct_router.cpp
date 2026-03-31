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
    std::vector<std::thread> threads_to_join;

    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this, &threads_to_join] {
            for (auto& [_, upload] : _active_uploads)
                if (upload.second.joinable())
                    threads_to_join.push_back(std::move(upload.second));

            _close_connections();
        });

    // Block until upload threads have finished
    for (auto& t : threads_to_join)
        if (t.joinable())
            t.join();

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

void DirectRouter::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
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

void DirectRouter::_close_connections() {
    // Cancel any uploads and downloads
    for (auto& [id, request_and_thread] : _active_uploads) {
        request_and_thread.first.cancel();

        if (request_and_thread.first.on_complete)
            request_and_thread.first.on_complete(ERROR_CONNECTION_CLOSED, false);
    }

    for (auto& [id, request] : _active_downloads) {
        request.cancel();

        if (request.on_complete)
            request.on_complete(ERROR_CONNECTION_CLOSED, false);
    }

    _active_uploads.clear();
    _active_downloads.clear();

    _update_status(ConnectionStatus::disconnected);
}

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

void DirectRouter::_cleanup_upload(const std::string& upload_id) {
    auto node = _active_uploads.extract(upload_id);
    if (!node.empty()) {
        auto& thread = node.mapped().second;
        if (thread.joinable())
            thread.join();
    }
}

QuicFileClient& DirectRouter::_get_file_client(
        const ed25519_pubkey& pubkey, std::string_view address, uint16_t port) {
    auto [it, inserted] = _file_clients.try_emplace(pubkey, nullptr);
    if (inserted)
        it->second = std::make_unique<QuicFileClient>(
                _loop, pubkey, std::string{address}, port);
    else
        it->second->set_target(pubkey, std::string{address}, port);
    return *it->second;
}

void DirectRouter::_upload_internal(UploadRequest request) {
    const std::string upload_id = random::unique_id("UP");
    log::info(cat, "[Upload {}]: Starting upload.", upload_id);

    request.on_complete = make_callback_atomic(std::move(request.on_complete));

    // Use the QUIC file server path if configured, otherwise fall back to the legacy HTTP path
    if (!_config.quic_file_server_address || !_config.quic_file_server_ed_pubkey) {
        _upload_internal_legacy(std::move(request), std::move(upload_id));
        return;
    }

    auto& upload_thread =
            _active_uploads.emplace(upload_id, std::make_pair(request, std::thread{}))
                    .first->second.second;

    auto address = *_config.quic_file_server_address;
    auto pubkey_hex = *_config.quic_file_server_ed_pubkey;
    auto port = _config.quic_file_server_port;

    upload_thread = std::thread([weak_self = weak_from_this(),
                                 this,
                                 upload_request = request,
                                 upload_id,
                                 address,
                                 pubkey_hex,
                                 port] {
        auto self = weak_self.lock();
        if (!self)
            return;

        try {
            std::vector<std::byte> all_data;
            while (true) {
                if (upload_request.is_cancelled())
                    throw cancellation_exception{"Cancelled during data accumulation."};
                auto chunk = upload_request.next_data();
                if (chunk.empty())
                    break;
                auto* p = reinterpret_cast<const std::byte*>(chunk.data());
                all_data.insert(all_data.end(), p, p + chunk.size());
            }

            if (all_data.empty())
                throw std::runtime_error{"No data to upload"};

            log::debug(
                    cat,
                    "[Upload {}]: Accumulated {} bytes, uploading to {}:{}.",
                    upload_id,
                    all_data.size(),
                    address,
                    port);

            _loop->call([weak_self,
                         this,
                         upload_request,
                         upload_id,
                         address,
                         pubkey_hex,
                         port,
                         data = std::move(all_data)]() mutable {
                auto self = weak_self.lock();
                if (!self)
                    return;

                if (upload_request.is_cancelled()) {
                    upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                    _cleanup_upload(upload_id);
                    return;
                }

                auto pubkey = ed25519_pubkey::from_hex(pubkey_hex);
                auto& client = _get_file_client(pubkey, address, port);

                client.upload(
                        std::move(data),
                        upload_request.ttl,
                        [weak_self, this, upload_request, upload_id](
                                std::variant<file_metadata, int16_t> result) {
                            auto self = weak_self.lock();
                            if (!self)
                                return;

                            if (auto* meta = std::get_if<file_metadata>(&result))
                                log::info(
                                        cat,
                                        "[Upload {}]: Success, file ID: {}",
                                        upload_id,
                                        meta->id);
                            else
                                log::error(
                                        cat,
                                        "[Upload {}]: Failed with error {}",
                                        upload_id,
                                        std::get<int16_t>(result));

                            upload_request.on_complete(std::move(result), false);
                            _cleanup_upload(upload_id);
                        });
            });
        } catch (const cancellation_exception&) {
            _loop->call([weak_self = weak_from_this(), this, upload_request, upload_id] {
                if (auto self = weak_self.lock()) {
                    upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                    _cleanup_upload(upload_id);
                }
            });
        } catch (const std::exception& e) {
            log::error(cat, "[Upload {}]: Exception: {}", upload_id, e.what());
            _loop->call([weak_self = weak_from_this(), this, upload_request, upload_id] {
                if (auto self = weak_self.lock()) {
                    upload_request.on_complete(ERROR_UNKNOWN, false);
                    _cleanup_upload(upload_id);
                }
            });
        }
    });
}

void DirectRouter::_upload_internal_legacy(UploadRequest request, std::string upload_id) {
    auto& upload_thread =
            _active_uploads.emplace(upload_id, std::make_pair(request, std::thread{}))
                    .first->second.second;

    upload_thread = std::thread([weak_self = weak_from_this(),
                                 this,
                                 upload_request = request,
                                 upload_id,
                                 file_server_config = _config.file_server_config] {
        auto self = weak_self.lock();
        if (!self)
            return;

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
                    _cleanup_upload(upload_id);
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

                            _cleanup_upload(upload_id);

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
                            } catch (const cancellation_exception&) {
                                log::error(cat, "[Upload {}]: Cancelled", upload_id);
                                upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
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
                                upload_request.on_complete(ERROR_UNKNOWN, false);
                            }
                        });
            });
        } catch (const std::exception& e) {
            log::error(cat, "[Upload {}]: Exception during upload: {}", upload_id, e.what());

            _loop->call([weak_self, this, upload_request, upload_id] {
                auto self = weak_self.lock();
                if (!self)
                    return;
                _cleanup_upload(upload_id);
                upload_request.on_complete(ERROR_UNKNOWN, false);
            });
        }
    });
}

void DirectRouter::_download_internal(DownloadRequest request) {
    const std::string download_id = random::unique_id("DL");
    log::info(cat, "[Download {}]: Starting download.", download_id);

    request.on_complete = make_callback_atomic(std::move(request.on_complete));

    if (!_config.quic_file_server_address || !_config.quic_file_server_ed_pubkey) {
        _download_internal_legacy(std::move(request), std::move(download_id));
        return;
    }

    // QUIC download: parse file_id from URL, connect directly to configured file server
    auto download_info = file_server::parse_download_url(request.download_url);
    if (!download_info) {
        log::error(
                cat, "[Download {}]: Invalid download URL: {}", download_id, request.download_url);
        request.on_complete(ERROR_INVALID_DOWNLOAD_URL, false);
        return;
    }

    _active_downloads[download_id] = request;
    auto file_id = download_info->file_id;
    auto address = *_config.quic_file_server_address;
    auto pubkey = ed25519_pubkey::from_hex(*_config.quic_file_server_ed_pubkey);
    auto port = _config.quic_file_server_port;

    auto& client = _get_file_client(pubkey, address, port);

    log::debug(cat, "[Download {}]: Downloading {} from {}:{}.", download_id, file_id, address, port);

    client.download(
            std::move(file_id),
            request.on_data,
            [weak_self = weak_from_this(), this, request, download_id](
                    std::variant<file_metadata, int16_t> result) {
                auto self = weak_self.lock();
                if (!self)
                    return;

                _active_downloads.erase(download_id);

                if (auto* meta = std::get_if<file_metadata>(&result))
                    log::info(
                            cat,
                            "[Download {}]: Success, file ID: {} ({} bytes)",
                            download_id,
                            meta->id,
                            meta->size);
                else
                    log::error(
                            cat,
                            "[Download {}]: Failed with error {}",
                            download_id,
                            std::get<int16_t>(result));

                request.on_complete(std::move(result), false);
            });
}

void DirectRouter::_download_internal_legacy(DownloadRequest request, std::string download_id) {
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
                            request.on_data(metadata, to_span<const std::byte>(data));

                        request.on_complete(std::move(metadata), false);
                    } catch (const cancellation_exception&) {
                        log::error(cat, "[Download {}]: Cancelled", download_id);
                        request.on_complete(ERROR_REQUEST_CANCELLED, false);
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
                        request.on_complete(ERROR_UNKNOWN, false);
                    }
                });
    } catch (const invalid_url_exception& e) {
        log::error(cat, "[Download {}]: Exception during download: {}", download_id, e.what());
        request.on_complete(ERROR_INVALID_DOWNLOAD_URL, false);
        _active_downloads.erase(download_id);
    } catch (const std::exception& e) {
        log::error(cat, "[Download {}]: Exception during download: {}", download_id, e.what());
        request.on_complete(ERROR_UNKNOWN, false);
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
