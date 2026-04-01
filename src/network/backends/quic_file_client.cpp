#include "session/network/backends/quic_file_client.hpp"

#include <fmt/chrono.h>
#include <fmt/format.h>
#include <oxenc/base32z.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include <fstream>
#include <mutex>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

#include "session/clock.hpp"
#include "session/ed25519.hpp"

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    auto cat = log::Cat("quic-file-client");
}

// -- QuicFileClient --

QuicFileClient::QuicFileClient(
        std::shared_ptr<quic::Loop> loop,
        ed25519_pubkey ed_pubkey,
        std::string address,
        uint16_t port,
        ticket_store_cb ticket_store,
        ticket_extract_cb ticket_extract) :
        _loop{std::move(loop)},
        _ed_pubkey{std::move(ed_pubkey)},
        _address{std::move(address)},
        _port{port},
        _ticket_store{std::move(ticket_store)},
        _ticket_extract{std::move(ticket_extract)},
        _last_activity{std::chrono::steady_clock::now()} {

    // Create a dedicated endpoint for file server connections
    _ep = quic::Endpoint::endpoint(*_loop, quic::Address{});

    // Set up TLS credentials
    auto key_pair = ed25519::ed25519_key_pair();
    _creds = quic::GNUTLSCreds::make_from_ed_seckey(std::string_view{
            reinterpret_cast<const char*>(key_pair.second.data()), key_pair.second.size()});

    // Enable 0RTT if callbacks are provided
    if (_ticket_store && _ticket_extract) {
        _creds->enable_outbound_0rtt(
                [store = _ticket_store](
                        quic::RemoteAddress remote,
                        std::vector<unsigned char> data,
                        std::chrono::sys_seconds expiry) {
                    store(oxenc::to_hex(remote.view_remote_key()), std::move(data), expiry);
                },
                [extract = _ticket_extract](const quic::RemoteAddress& remote)
                        -> std::optional<std::vector<unsigned char>> {
                    return extract(oxenc::to_hex(remote.view_remote_key()));
                });
    }

    log::debug(cat, "QuicFileClient created for target {}:{}", _address, _port);
}

QuicFileClient::~QuicFileClient() {
    close();
}

void QuicFileClient::set_target(ed25519_pubkey ed_pubkey, std::string address, uint16_t port) {
    if (_address != address || _port != port || _ed_pubkey != ed_pubkey) {
        close();
        _ed_pubkey = std::move(ed_pubkey);
        _address = std::move(address);
        _port = port;
        log::debug(cat, "Target updated to {}:{}", _address, _port);
    }
}

void QuicFileClient::close() {
    _idle_timer.reset();
    _bt_stream.reset();
    if (_conn) {
        _conn->close_connection();
        _conn.reset();
    }
}

void QuicFileClient::_touch() {
    _last_activity = std::chrono::steady_clock::now();
}

void QuicFileClient::_start_idle_timer() {
    if (_idle_timer)
        return;

    _idle_timer = _loop->call_every(IDLE_CHECK_INTERVAL, [this] {
        if (!_conn)
            return;
        auto idle_duration = std::chrono::steady_clock::now() - _last_activity;
        if (idle_duration >= IDLE_TIMEOUT) {
            log::debug(cat, "Connection idle for {}s, closing.", idle_duration / 1s);
            close();
        }
    });
}

std::shared_ptr<quic::Connection> QuicFileClient::_ensure_connection() {
    if (_conn)
        return _conn;

    auto remote = quic::RemoteAddress{oxenc::from_hex(_ed_pubkey.hex()), _address, _port};

    log::info(cat, "Connecting to QUIC file server at {}:{}", _address, _port);

    _conn = _ep->connect(
            remote,
            _creds,
            quic::opt::outbound_alpn(QUIC_FILES_ALPN),
            quic::opt::handshake_timeout{10s},
            quic::opt::keep_alive{10s},
            [this](quic::Connection&) { log::info(cat, "Connected to QUIC file server."); },
            [this](quic::Connection&, uint64_t ec) {
                if (ec)
                    log::warning(cat, "Connection to QUIC file server failed (error {}).", ec);
                else
                    log::debug(cat, "Connection to QUIC file server closed.");
                _conn.reset();
                _bt_stream.reset();
            });

    // Open stream 0 as BTRequestStream (required by file server protocol — subsequent file
    // transfer streams get IDs 4, 8, etc.).
    // TODO: use this stream for metadata requests (file info, extend TTL, etc.)
    _bt_stream = _conn->open_stream<quic::BTRequestStream>();

    _touch();
    _start_idle_timer();

    return _conn;
}

void QuicFileClient::upload(
        std::vector<std::byte> data,
        std::optional<std::chrono::seconds> ttl,
        std::function<void(std::variant<file_metadata, int16_t> result)> on_complete) {
    _loop->call([this,
                 data = std::make_shared<std::vector<std::byte>>(std::move(data)),
                 ttl,
                 on_complete = std::move(on_complete)]() mutable {
        try {
            auto conn = _ensure_connection();
            if (!conn) {
                on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
                return;
            }

            // State shared between the stream callbacks
            struct upload_state {
                int64_t upload_size;
                std::string response_data;
                std::function<void(std::variant<file_metadata, int16_t>)> on_complete;
            };
            auto state = std::make_shared<upload_state>();
            state->upload_size = static_cast<int64_t>(data->size());
            state->on_complete = std::move(on_complete);

            auto on_data = [state](quic::Stream&, std::span<const std::byte> incoming) {
                state->response_data += std::string_view{
                        reinterpret_cast<const char*>(incoming.data()), incoming.size()};
            };

            auto on_close = [this, state](quic::Stream&, uint64_t error_code) {
                _touch();

                if (error_code != 0) {
                    log::warning(cat, "Upload stream closed with error {}.", error_code);
                    state->on_complete(static_cast<int16_t>(error_code));
                    return;
                }

                if (state->response_data.empty()) {
                    log::warning(cat, "Upload stream closed with no response data.");
                    state->on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
                    return;
                }

                try {
                    // The upload response is a raw bt-dict, not size-prefixed.
                    log::trace(
                            cat,
                            "Upload response ({} bytes): {}",
                            state->response_data.size(),
                            state->response_data);

                    oxenc::bt_dict_consumer resp{state->response_data};
                    file_metadata metadata{};
                    metadata.id = resp.require<std::string>("#");
                    metadata.size = state->upload_size;
                    metadata.uploaded = std::chrono::sys_seconds{
                            std::chrono::seconds{resp.require<int64_t>("u")}};
                    metadata.expiry = std::chrono::sys_seconds{
                            std::chrono::seconds{resp.require<int64_t>("x")}};

                    log::info(
                            cat,
                            "Upload complete: file ID={}, expiry={}",
                            metadata.id,
                            metadata.expiry);
                    state->on_complete(std::move(metadata));
                } catch (const std::exception& e) {
                    log::error(cat, "Failed to parse upload response: {}", e.what());
                    state->on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
                }
            };

            auto str = conn->open_stream(on_data, on_close);

            // Build and send the PUT command
            oxenc::bt_dict_producer cmd;
            cmd.append("!", "PUT");
            cmd.append("s", static_cast<int64_t>(data->size()));
            if (ttl)
                cmd.append("t", static_cast<int64_t>(ttl->count()));

            auto cmd_view = cmd.view();
            str->send(fmt::format("{}:{}", cmd_view.size(), cmd_view));

            // Send the file data, keeping the shared_ptr alive until the send completes
            str->send(*data, data);
            str->send_fin();

            _touch();
            log::debug(cat, "Upload started: {} bytes.", data->size());

        } catch (const std::exception& e) {
            log::error(cat, "Upload failed: {}", e.what());
            on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
        }
    });
}

void QuicFileClient::download(
        std::string file_id,
        std::function<void(const file_metadata& info, std::span<const std::byte> data)> on_data,
        std::function<void(std::variant<file_metadata, int16_t> result)> on_complete) {
    _loop->call([this,
                 file_id = std::move(file_id),
                 on_data = std::move(on_data),
                 on_complete = std::move(on_complete)]() mutable {
        try {
            auto conn = _ensure_connection();
            if (!conn) {
                on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
                return;
            }

            // State shared between the stream callbacks
            struct download_state {
                std::string file_id;
                file_metadata metadata{};
                bool metadata_parsed = false;
                int meta_size = -1;
                std::string partial;
                std::vector<std::byte> meta_buf;
                int64_t received = 0;
                std::function<void(const file_metadata&, std::span<const std::byte>)> on_data;
                std::function<void(std::variant<file_metadata, int16_t>)> on_complete;
            };
            auto state = std::make_shared<download_state>();
            state->file_id = file_id;
            state->on_data = std::move(on_data);
            state->on_complete = std::move(on_complete);

            auto data_cb = [this, state](quic::Stream& s, std::span<const std::byte> data) {
                _touch();

                // Phase 1: parse the size prefix of the metadata block
                if (state->meta_size < 0) {
                    try {
                        auto size = quic::prefix_accumulator(state->partial, data);
                        if (!size)
                            return;
                        if (*size == 0)
                            throw std::runtime_error{"Invalid 0-byte metadata block"};
                        state->meta_size = static_cast<int>(*size);
                    } catch (const std::exception& e) {
                        log::error(cat, "Download metadata prefix error: {}", e.what());
                        s.close(400);
                        return;
                    }
                    state->meta_buf.reserve(state->meta_size);
                }

                // Phase 2: accumulate metadata bytes
                if (!state->metadata_parsed) {
                    try {
                        if (!quic::data_accumulator(state->meta_buf, data, state->meta_size))
                            return;
                    } catch (const std::exception& e) {
                        log::error(cat, "Download metadata accumulation error: {}", e.what());
                        s.close(400);
                        return;
                    }

                    // Parse metadata dict
                    try {
                        oxenc::bt_dict_consumer d{state->meta_buf};
                        auto file_size = d.require<int64_t>("s");
                        if (file_size <= 0)
                            throw std::runtime_error{
                                    fmt::format("Invalid file size {}", file_size)};
                        state->metadata.id = state->file_id;
                        state->metadata.size = file_size;
                        state->metadata.uploaded = std::chrono::sys_seconds{
                                std::chrono::seconds{d.require<int64_t>("u")}};
                        state->metadata.expiry = std::chrono::sys_seconds{
                                std::chrono::seconds{d.require<int64_t>("x")}};
                        d.finish();
                        state->metadata_parsed = true;

                        log::debug(
                                cat,
                                "Download metadata: {} bytes, expiry={}",
                                state->metadata.size,
                                state->metadata.expiry);
                    } catch (const std::exception& e) {
                        log::error(cat, "Download metadata parse error: {}", e.what());
                        s.close(444);
                        return;
                    }
                }

                // Phase 3: deliver file data
                if (!data.empty()) {
                    state->received += data.size();
                    if (state->on_data) {
                        try {
                            state->on_data(state->metadata, data);
                        } catch (const std::exception& e) {
                            log::warning(cat, "Download aborted by on_data callback: {}", e.what());
                            s.close(QUIC_FILES_CLIENT_ABORT);
                            return;
                        }
                    }
                }
            };

            auto close_cb = [this, state](quic::Stream&, uint64_t error_code) {
                _touch();

                if (error_code != 0) {
                    log::warning(
                            cat,
                            "Download stream for {} closed with error {}.",
                            state->file_id,
                            error_code);
                    state->on_complete(static_cast<int16_t>(error_code));
                    return;
                }

                if (!state->metadata_parsed) {
                    log::warning(cat, "Download stream closed before metadata received.");
                    state->on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
                    return;
                }

                if (state->received < state->metadata.size) {
                    log::warning(
                            cat,
                            "Download incomplete: received {}/{} bytes.",
                            state->received,
                            state->metadata.size);
                    state->on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
                    return;
                }

                log::info(
                        cat, "Download complete: {} ({} bytes).", state->file_id, state->received);
                state->on_complete(state->metadata);
            };

            auto str = conn->open_stream(data_cb, close_cb);

            // Build and send the GET command
            oxenc::bt_dict_producer cmd;
            cmd.append("!", "GET");
            cmd.append("#", file_id);

            auto cmd_view = cmd.view();
            str->send(fmt::format("{}:{}", cmd_view.size(), cmd_view));
            str->send_fin();

            _touch();
            log::debug(cat, "Download started for file {}.", file_id);

        } catch (const std::exception& e) {
            log::error(cat, "Download failed: {}", e.what());
            on_complete(static_cast<int16_t>(ERROR_UNKNOWN));
        }
    });
}

void streaming_file_upload(
        std::shared_ptr<quic::Loop> loop,
        attachment::Encryptor enc,
        FileUploadRequest request,
        std::function<QuicFileClient*(void)> get_client) {

    struct upload_state {
        std::mutex mutex;
        std::condition_variable cv;
        bool paused = false;
        bool done = false;
        QuicFileClient* client = nullptr;
        std::shared_ptr<quic::Stream> stream;
        std::string response_data;
        std::optional<std::variant<file_metadata, int16_t>> result;
    };
    auto state = std::make_shared<upload_state>();

    auto fail = [&](int16_t err) {
        if (request.on_complete)
            loop->call([request, err] { request.on_complete(err, false); });
    };

    loop->call([state, get_client = std::move(get_client)] {
        auto* client = get_client();
        std::lock_guard lock{state->mutex};
        if (client)
            state->client = client;
        else
            state->done = true;
        state->cv.notify_one();
    });

    auto key = enc.load_key_from_file(request.file, request.allow_large);
    auto upload_size = attachment::encrypted_size(enc.data_size());
    auto enc_ptr = std::make_shared<attachment::Encryptor>(std::move(enc));

    {
        std::unique_lock lock{state->mutex};
        state->cv.wait(
                lock, [&] { return state->client || state->done || request.is_cancelled(); });
        if (request.is_cancelled())
            return fail(ERROR_REQUEST_CANCELLED);
        if (state->done)
            return fail(ERROR_FILE_SERVER_UNAVAILABLE);
    }

    loop->call_get([&] {
        auto conn = state->client->_ensure_connection();
        if (!conn) {
            std::lock_guard lock{state->mutex};
            state->done = true;
            return;
        }

        auto str = conn->open_stream(
                [state](quic::Stream&, std::span<const std::byte> incoming) {
                    state->response_data += std::string_view{
                            reinterpret_cast<const char*>(incoming.data()), incoming.size()};
                },
                [state, upload_size](quic::Stream&, uint64_t error_code) {
                    std::lock_guard lock{state->mutex};
                    if (error_code != 0) {
                        state->result = static_cast<int16_t>(error_code);
                    } else if (state->response_data.empty()) {
                        state->result = static_cast<int16_t>(ERROR_UNKNOWN);
                    } else {
                        try {
                            oxenc::bt_dict_consumer resp{state->response_data};
                            file_metadata meta{};
                            meta.id = resp.require<std::string>("#");
                            meta.size = upload_size;
                            meta.uploaded = from_epoch_s(resp.require<int64_t>("u"));
                            meta.expiry = from_epoch_s(resp.require<int64_t>("x"));
                            resp.finish();
                            state->result = std::move(meta);
                        } catch (const std::exception& e) {
                            log::warning(
                                    cat, "Failed to parse streaming upload response: {}", e.what());
                            state->result = static_cast<int16_t>(ERROR_UNKNOWN);
                        }
                    }
                    state->done = true;
                    state->cv.notify_one();
                });

        constexpr size_t WATERMARK_ALARM = 512 * 1024;
        constexpr size_t WATERMARK_CLEAR = 128 * 1024;
        str->enable_watermarks(
                WATERMARK_ALARM,
                [state](quic::Stream&) {
                    std::lock_guard lock{state->mutex};
                    state->paused = true;
                },
                WATERMARK_CLEAR,
                [state](quic::Stream&) {
                    {
                        std::lock_guard lock{state->mutex};
                        state->paused = false;
                    }
                    state->cv.notify_one();
                });

        oxenc::bt_dict_producer cmd;
        cmd.append("!", "PUT");
        cmd.append("s", static_cast<int64_t>(upload_size));
        if (request.ttl)
            cmd.append("t", static_cast<int64_t>(request.ttl->count()));
        auto cmd_view = cmd.view();
        str->send(fmt::format("{}:{}", cmd_view.size(), cmd_view));

        state->stream = std::move(str);
    });

    {
        std::lock_guard lock{state->mutex};
        if (state->done)
            return fail(ERROR_FILE_SERVER_UNAVAILABLE);
    }

    auto check_cancelled = [&]() -> bool {
        if (!request.is_cancelled())
            return false;
        log::debug(cat, "Streaming file upload cancelled");
        loop->call([state, request] {
            if (state->stream)
                state->stream->close(QUIC_FILES_CLIENT_ABORT);
            if (request.on_complete)
                request.on_complete(ERROR_REQUEST_CANCELLED, false);
        });
        return true;
    };

    for (auto chunk = enc_ptr->next(); !chunk.empty(); chunk = enc_ptr->next()) {
        if (check_cancelled())
            return;

        {
            std::unique_lock lock{state->mutex};
            state->cv.wait(
                    lock, [&] { return !state->paused || state->done || request.is_cancelled(); });
            if (check_cancelled())
                return;
            if (state->done)
                break;
        }

        auto data = std::make_shared<std::vector<std::byte>>(chunk.begin(), chunk.end());
        loop->call([state, data] {
            if (state->stream)
                state->stream->send(*data, data);
        });
    }

    loop->call([state] {
        if (state->stream)
            state->stream->send_fin();
    });

    {
        std::unique_lock lock{state->mutex};
        state->cv.wait(lock, [&] { return state->done; });
    }

    if (request.on_complete && state->result) {
        loop->call([request, result = std::move(*state->result), key] {
            if (auto* meta = std::get_if<file_metadata>(&result))
                request.on_complete(std::make_pair(std::move(*meta), key), false);
            else
                request.on_complete(std::get<int16_t>(result), false);
        });
    }
}
}  // namespace session::network
