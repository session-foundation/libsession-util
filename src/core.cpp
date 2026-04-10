#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <mlkem_native.h>
#include <oxenc/base64.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/core.h>

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/loop.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/schema/schema_registry.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/network/session_network.hpp>
#include <session/network/session_network_types.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>
#include <session/util.hpp>
#include <session/xed25519.hpp>
#include <unordered_set>

#include "session/config/namespaces.hpp"
#include "session/core/component.hpp"

namespace session::core {

namespace log = oxen::log;
using namespace session::sqlite;
using namespace oxen::log::literals;
static auto cat = log::Cat("core");

// Returns true if the given namespace requires a signed retrieve request.  A namespace does NOT
// require auth if and only if it satisfies: ns_val < 0 && (-ns_val) % 20 == 1 (i.e. -1, -21, ...).
static constexpr bool ns_requires_auth(int16_t ns_val) {
    return !(ns_val < 0 && (-ns_val) % 20 == 1);
}

static cleared_b32 seed_from_words(
        std::span<const std::string_view> words, const mnemonics::Mnemonics& lang) {
    auto n = words.size();
    if (n != 12 && n != 13 && n != 24 && n != 25)
        throw std::invalid_argument{
                "Seed phrase must be 12, 13, 24, or 25 words (got {})"_format(n)};

    cleared_b32 result;
    if (n <= 13) {
        // 12 or 13 words → 16-byte seed in the lower half; upper 16 bytes are zeroed
        mnemonics::words_to_bytes(words, lang, std::span<std::byte>(result.data(), 16));
        std::memset(result.data() + 16, 0, 16);
    } else {
        // 24 or 25 words → full 32-byte seed
        mnemonics::words_to_bytes(words, lang, std::span<std::byte>(result.data(), 32));
    }
    return result;
}

predefined_seed::predefined_seed(
        std::span<const std::string_view> words, const mnemonics::Mnemonics& lang) :
        predefined_seed{seed_from_words(words, lang)} {}

predefined_seed::predefined_seed(
        std::span<const std::string_view> words, std::string_view lang_name) :
        predefined_seed{words, mnemonics::get_language(lang_name)} {}

void Core::LoopDeleter::operator()(quic::Loop* p) const {
    delete p;
}

void Core::init() {
    if (sodium_init() < 0)
        throw std::runtime_error{"libsodium initialization failed!"};

    _loop.reset(new quic::Loop());

    apply_migrations();

    for (auto* component : _comp_init)
        component->init();

    _comp_init.clear();

    _update_polling();
}

void Core::register_comp_init(detail::CoreComponent* c) {
    _comp_init.push_back(c);
}

void Core::set_network(std::shared_ptr<network::Network> network) {
    _network = std::move(network);
    _update_polling();
}

void Core::_update_polling() {
    if (_network && !_poll_ticker) {
        _poll_ticker = _loop->call_every(_poll_interval, [this] { _poll(); });
    } else if (!_network && _poll_ticker) {
        _poll_ticker->stop();
        _poll_ticker.reset();
    }
}

void Core::set_poll_interval(std::chrono::milliseconds interval) {
    _poll_interval = interval;
    if (_poll_ticker) {
        _poll_ticker->stop();
        _poll_ticker.reset();
    }
    if (_network)
        _poll_ticker = _loop->call_every(_poll_interval, [this] { _poll(); });
}

void Core::_poll() {
    auto net = _network;
    if (!net)
        return;

    constexpr std::array namespaces = {
            config::Namespace::Default,
            config::Namespace::Devices,
            config::Namespace::AccountPubkeys};

    auto now_ms = epoch_ms(clock_now_ms());
    auto ed25519_hex = globals.pubkey_ed25519().hex();

    // Build per-namespace signatures for namespaces that require authentication; index-aligned with
    // `namespaces`.  Empty string means no auth needed for that namespace.
    std::vector<std::string> ns_sig(namespaces.size());
    {
        auto seed = globals.account_seed();
        for (size_t i = 0; i < namespaces.size(); ++i) {
            auto ns_val = static_cast<int16_t>(namespaces[i]);
            if (!ns_requires_auth(ns_val))
                continue;
            std::string to_sign = "retrieve{}{}"_format(ns_val, now_ms);
            auto sig = ed25519::sign(seed.ed25519_secret(), to_span(to_sign));
            ns_sig[i] = "{:b}"_format(sig);
        }
    }

    net->get_swarm(
            globals.pubkey_x25519(),
            false,
            [this, net, namespaces, ed25519_hex, now_ms, ns_sig = std::move(ns_sig)](
                    auto, auto swarm) {
                if (swarm.empty())
                    return;

                auto& node = swarm.front();

                // Build one batch subrequest per namespace.
                nlohmann::json requests = nlohmann::json::array();
                {
                    auto conn = db.conn();
                    for (size_t i = 0; i < namespaces.size(); ++i) {
                        auto ns = namespaces[i];
                        auto ns_val = static_cast<int16_t>(ns);
                        nlohmann::json params = {
                                {"pubkey", globals.session_id_hex()},
                                {"namespace", ns_val},
                        };

                        if (!ns_sig[i].empty()) {
                            params["pubkey_ed25519"] = ed25519_hex;
                            params["timestamp"] = now_ms;
                            params["signature"] = ns_sig[i];
                        }

                        auto last_hash = conn.prepared_maybe_get<std::string>(
                                "SELECT last_hash FROM namespace_sync"
                                " WHERE namespace = ? AND sn_pubkey = ?",
                                ns_val,
                                node.remote_pubkey);
                        if (last_hash)
                            params["last_hash"] = *last_hash;

                        requests.push_back({{"method", "retrieve"}, {"params", std::move(params)}});
                    }
                }

                auto body_str = nlohmann::json{{"requests", std::move(requests)}}.dump();
                net->send_request(
                        network::Request{
                                node,
                                "batch",
                                to_vector(body_str),
                                network::RequestCategory::standard_small,
                                20s},
                        [this, sn_pubkey = node.remote_pubkey, namespaces](
                                bool success,
                                bool timeout,
                                int16_t /*status_code*/,
                                std::vector<std::pair<std::string, std::string>> /*headers*/,
                                std::optional<std::string> body) {
                            if (!success || !body) {
                                log::warning(
                                        cat,
                                        "Swarm poll request failed: {}",
                                        timeout ? "timed out"
                                        : body  ? *body
                                                : "request failed");
                                return;
                            }

                            _handle_poll_response(sn_pubkey, namespaces, std::move(*body));
                        });
            });
}

void Core::_handle_poll_response(
        const network::ed25519_pubkey& sn_pubkey,
        std::span<const config::Namespace> namespaces,
        std::string body) {
    try {
        auto json = nlohmann::json::parse(body);
        auto it = json.find("results");
        if (it == json.end() || !it->is_array())
            return;

        auto& results = *it;
        auto conn = db.conn();
        for (size_t i = 0; i < namespaces.size() && i < results.size(); ++i) {
            const auto& res = results[i];
            auto code_it = res.find("code");
            if (code_it == res.end() || code_it->get<int>() != 200)
                continue;
            auto body_it = res.find("body");
            if (body_it == res.end())
                continue;
            auto msgs_it = body_it->find("messages");
            if (msgs_it == body_it->end() || !msgs_it->is_array())
                continue;

            auto ns = namespaces[i];
            auto ns_val = static_cast<int16_t>(ns);

            // Decode each message; keep the decoded bytes alive until after
            // receive_messages() returns, since SwarmMessage::data spans
            // into them.
            std::vector<std::vector<std::byte>> messages_data;
            std::vector<SwarmMessage> swarm_messages;
            std::string newest_hash;

            for (const auto& msg : *msgs_it) {
                auto data_it = msg.find("data");
                if (data_it == msg.end() || !data_it->is_string())
                    continue;
                auto& decoded = messages_data.emplace_back();
                auto b64 = data_it->get<std::string_view>();
                decoded.reserve(oxenc::from_base64_size(b64.size()));
                oxenc::from_base64(b64.begin(), b64.end(), std::back_inserter(decoded));

                SwarmMessage swarm_msg;
                swarm_msg.data = {decoded.data(), decoded.size()};

                if (auto h = msg.find("hash"); h != msg.end() && h->is_string()) {
                    swarm_msg.hash = h->get<std::string>();
                    newest_hash = swarm_msg.hash;
                }

                if (auto t = msg.find("timestamp"); t != msg.end() && t->is_number_integer())
                    swarm_msg.timestamp = from_epoch_ms(t->get<int64_t>());

                if (auto e = msg.find("expiry"); e != msg.end() && e->is_number_integer())
                    swarm_msg.expiry = from_epoch_ms(e->get<int64_t>());

                swarm_messages.push_back(std::move(swarm_msg));
            }

            if (!swarm_messages.empty()) {
                if (!newest_hash.empty())
                    conn.prepared_exec(
                            R"(
INSERT INTO namespace_sync (namespace, sn_pubkey, last_hash) VALUES (?, ?, ?)
ON CONFLICT(namespace, sn_pubkey) DO UPDATE SET last_hash = excluded.last_hash
)",
                            ns_val,
                            sn_pubkey,
                            newest_hash);
                receive_messages(swarm_messages, ns, true);
            }
        }
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to parse poll response: {}", e.what());
    }
}

PfsKeyStatus Core::prefetch_pfs_keys(std::span<const std::byte, 33> session_id) {
    auto net = _network;
    if (!net)
        throw std::logic_error{"prefetch_pfs_keys called without a network object"};

    // One copy of session_id for async use; subsequently moved into lambdas.
    b33 sid;
    std::ranges::copy(session_id, sid.begin());

    // Skip the fetch if the cached entry is still fresh, or a recent NAK suppresses retrying.
    // Otherwise determine whether we have a stale (but usable) key or no key at all.
    auto status = PfsKeyStatus::fetching;
    {
        auto conn = db.conn();
        if (auto row = conn.prepared_maybe_get<std::optional<int64_t>, std::optional<int64_t>>(
                    "SELECT fetched_at, nak_at FROM pfs_key_cache WHERE session_id = ?", sid)) {
            auto [fetched_at, nak_at] = *row;
            if (fetched_at) {
                auto age = clock_now_s() - from_epoch_s(*fetched_at);
                if (age < PFS_KEY_FRESH_DURATION) {
                    log::debug(
                            cat,
                            "prefetch_pfs_keys: cached key for {} is still fresh ({} old), "
                            "skipping",
                            session_id,
                            age);
                    return PfsKeyStatus::fresh;
                }
                log::debug(
                        cat,
                        "prefetch_pfs_keys: cached key for {} is stale ({} old), re-fetching",
                        session_id,
                        age);
                status = PfsKeyStatus::stale;
            } else if (nak_at) {
                auto age = clock_now_s() - from_epoch_s(*nak_at);
                if (age < PFS_KEY_NAK_DURATION) {
                    log::debug(
                            cat,
                            "prefetch_pfs_keys: recent NAK for {} ({} old), skipping",
                            session_id,
                            age);
                    return PfsKeyStatus::nak;
                }
                log::debug(
                        cat,
                        "prefetch_pfs_keys: expired NAK for {} ({} old), re-fetching",
                        session_id,
                        age);
            }
        } else {
            log::debug(cat, "prefetch_pfs_keys: no cached key for {}, fetching", session_id);
        }
    }

    // The swarm is indexed by the x25519 pubkey — the session_id without its 0x05 prefix.
    network::x25519_pubkey x25519_pub;
    std::ranges::copy(session_id.subspan<1>(), x25519_pub.begin());

    auto now_ms = epoch_ms(clock_now_ms());

    // AccountPubkeys (-21) allows unauthenticated retrieve: no signature needed.
    nlohmann::json params = {
            {"pubkey", oxenc::to_hex(session_id)},
            {"namespace", static_cast<int16_t>(config::Namespace::AccountPubkeys)},
    };

    net->get_swarm(x25519_pub, false, [this, net, sid = std::move(sid), params](auto, auto swarm) {
        if (swarm.empty()) {
            log::debug(cat, "prefetch_pfs_keys: get_swarm returned empty swarm");
            if (callbacks.pfs_keys_fetched)
                callbacks.pfs_keys_fetched(sid, PfsKeyFetch::failed);
            return;
        }

        auto body_str = params.dump();
        net->send_request(
                network::Request{
                        swarm.front(),
                        "retrieve",
                        to_vector(body_str),
                        network::RequestCategory::standard_small,
                        20s},
                [this, sid = std::move(sid)](
                        bool success,
                        bool timeout,
                        int16_t /*status_code*/,
                        std::vector<std::pair<std::string, std::string>> /*headers*/,
                        std::optional<std::string> body) {
                    if (!success || !body) {
                        log::warning(
                                cat,
                                "Failed to fetch PFS keys for {}: {}",
                                sid,
                                timeout ? "timed out"
                                : body  ? *body
                                        : "request failed");
                        if (callbacks.pfs_keys_fetched)
                            callbacks.pfs_keys_fetched(sid, PfsKeyFetch::failed);
                        return;
                    }

                    return _handle_pfs_response(sid, std::move(*body));
                });
    });
    return status;
}

bool Core::_store_pfs_keys(
        std::span<const std::byte, 33> session_id,
        std::span<const std::byte, 32> x25519_pub,
        std::span<const std::byte, 1184> mlkem768_pub) {
    auto now_s = epoch_seconds(clock_now_s());
    auto conn = db.conn();
    SQLite::Transaction tx{conn.sql};

    bool is_unchanged = conn.prepared_maybe_get<int>(
                                    R"(
SELECT 1 FROM pfs_key_cache
WHERE session_id = ? AND pubkey_x25519 = ? AND pubkey_mlkem768 = ?
)",
                                    session_id,
                                    x25519_pub,
                                    mlkem768_pub)
                                .has_value();

    conn.prepared_exec(
            R"(
INSERT INTO pfs_key_cache (session_id, fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768)
VALUES (?, ?, NULL, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
    fetched_at = excluded.fetched_at,
    pubkey_x25519 = excluded.pubkey_x25519,
    pubkey_mlkem768 = excluded.pubkey_mlkem768
)",
            session_id,
            now_s,
            x25519_pub,
            mlkem768_pub);
    tx.commit();
    return !is_unchanged;
}

void Core::_store_pfs_nak(std::span<const std::byte, 33> session_id) {
    auto now_s = epoch_seconds(clock_now_s());
    db.conn().prepared_exec(
            R"(
INSERT INTO pfs_key_cache (session_id, fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768)
VALUES (?, NULL, ?, NULL, NULL)
ON CONFLICT(session_id) DO UPDATE SET nak_at = excluded.nak_at
)",
            session_id,
            now_s);
}

void Core::_handle_pfs_response(std::span<const std::byte, 33> sid, std::string body) {
    try {
        auto json = nlohmann::json::parse(body);
        auto msgs_it = json.find("messages");
        if (msgs_it == json.end() || !msgs_it->is_array()) {
            log::warning(
                    cat,
                    "prefetch_pfs_keys: response missing or invalid "
                    "'messages' array");
            return;
        }

        // Strip the 0x05 prefix to get the x25519 pubkey for
        // signature verification.
        auto x25519_pub = sid.subspan<1>();

        // Track the most recently valid pubkeys seen across all messages.
        std::optional<std::array<std::byte, 32>> pk_x25519;
        std::optional<std::array<std::byte, MLKEM768_PUBLICKEYBYTES>> pk_mlkem768;

        for (const auto& msg : *msgs_it) {
            auto data_it = msg.find("data");
            if (data_it == msg.end() || !data_it->is_string()) {
                log::warning(
                        cat,
                        "prefetch_pfs_keys: message missing or "
                        "non-string 'data' field");
                continue;
            }
            auto b64 = data_it->get<std::string_view>();
            std::vector<std::byte> decoded;
            decoded.reserve(oxenc::from_base64_size(b64.size()));
            oxenc::from_base64(b64.begin(), b64.end(), std::back_inserter(decoded));
            try {
                oxenc::bt_dict_consumer in{decoded};
                auto M = in.require_span<std::byte, MLKEM768_PUBLICKEYBYTES>("M");
                auto X = in.require_span<std::byte, 32>("X");
                in.require_signature(
                        "~",
                        [&x25519_pub](
                                std::span<const std::byte> b, std::span<const std::byte> sig) {
                            if (sig.size() != 64 ||
                                !xed25519::verify(sig.first<64>(), x25519_pub, b))
                                throw std::runtime_error{"signature verification failed"};
                        });
                std::ranges::copy(X, pk_x25519.emplace().begin());
                std::ranges::copy(M, pk_mlkem768.emplace().begin());
            } catch (const std::exception& e) {
                log::warning(
                        cat,
                        "Ignoring malformed remote account pubkey "
                        "message: {}",
                        e.what());
            }
        }

        if (!pk_x25519 || !pk_mlkem768) {
            log::debug(
                    cat,
                    "prefetch_pfs_keys: no valid account pubkey message "
                    "found in response");
            _store_pfs_nak(sid);
            if (callbacks.pfs_keys_fetched)
                callbacks.pfs_keys_fetched(sid, PfsKeyFetch::not_found);
            return;
        }

        bool changed = _store_pfs_keys(sid, *pk_x25519, *pk_mlkem768);
        if (callbacks.pfs_keys_fetched)
            callbacks.pfs_keys_fetched(
                    sid, changed ? PfsKeyFetch::new_key : PfsKeyFetch::unchanged);
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to process PFS key fetch response: {}", e.what());
    }
}

void Core::_send_to_swarm(
        std::span<const std::byte, 33> dest_pubkey,
        config::Namespace ns,
        std::vector<std::byte> payload,
        std::chrono::milliseconds ttl,
        std::function<void(bool success)> on_complete) {
    if (callbacks.send_to_swarm) {
        callbacks.send_to_swarm(dest_pubkey, ns, std::move(payload), ttl, std::move(on_complete));
        return;
    }

    auto net = _network;
    if (!net)
        throw std::logic_error{"_send_to_swarm: no send_to_swarm callback and no network object"};

    // Build signed store request.
    auto ed25519_hex = globals.pubkey_ed25519().hex();
    auto ns_val = static_cast<int16_t>(ns);
    auto now_ms = epoch_ms(clock_now_ms());

    std::string to_sign = "store{}{}"_format(ns_val, now_ms);
    b64 sig;
    {
        auto seed = globals.account_seed();
        auto to_sign_bytes = std::as_bytes(std::span{to_sign});
        ed25519::sign(sig, seed.ed25519_secret(), to_sign_bytes);
    }

    nlohmann::json params = {
            {"pubkey", globals.session_id_hex()},
            {"pubkey_ed25519", ed25519_hex},
            {"namespace", ns_val},
            {"data", "{:b}"_format(payload)},
            {"timestamp", now_ms},
            {"sig_timestamp", now_ms},
            {"signature", "{:b}"_format(sig)},
            {"ttl", ttl.count()},
    };

    auto body = to_vector<std::byte>(params.dump());

    // Resolve the recipient's swarm and send.
    network::x25519_pubkey x25519_pub;
    std::memcpy(x25519_pub.data(), dest_pubkey.data() + 1, 32);

    net->get_swarm(
            x25519_pub,
            false,
            [net, body = std::move(body), on_complete = std::move(on_complete)](
                    auto, auto swarm) mutable {
                if (swarm.empty()) {
                    if (on_complete)
                        on_complete(false);
                    return;
                }
                net->send_request(
                        network::Request{
                                swarm.front(),
                                "store",
                                std::move(body),
                                network::RequestCategory::standard_small,
                                20s},
                        [on_complete = std::move(on_complete)](
                                bool success, bool, int16_t, auto, auto) {
                            if (on_complete)
                                on_complete(success);
                        });
            });
}

void Core::_do_send_dm(
        int64_t message_id,
        std::span<const std::byte, 33> recipient,
        std::span<const std::byte> content,
        sys_ms sent_timestamp,
        const ed25519::OptionalPrivKeySpan& pro_privkey,
        std::chrono::milliseconds ttl,
        bool force_v2) {
    auto fire_status = [&](MessageSendStatus status) {
        if (callbacks.message_send_status) {
            try {
                callbacks.message_send_status(message_id, status);
            } catch (const std::exception& e) {
                log::warning(cat, "message_send_status callback threw: {}", e.what());
            }
        }
    };

    // Look up cached PFS keys for the recipient.
    using X = sqlite::blob_guts<b32>;
    using M = sqlite::blob_guts<std::array<std::byte, 1184>>;
    auto row = db.conn()
                       .prepared_maybe_get<
                               std::optional<int64_t>,
                               std::optional<int64_t>,
                               std::optional<X>,
                               std::optional<M>>(
                               "SELECT fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768"
                               " FROM pfs_key_cache WHERE session_id = ?",
                               recipient);

    const b32* pfs_x25519 = nullptr;
    const std::array<std::byte, 1184>* pfs_mlkem768 = nullptr;
    if (row) {
        auto& [fetched_at, nak_at, pk_x, pk_m] = *row;
        if (fetched_at && pk_x && pk_m) {
            pfs_x25519 = &static_cast<const b32&>(*pk_x);
            pfs_mlkem768 = &static_cast<const std::array<std::byte, 1184>&>(*pk_m);
        }
    }

    // Encrypt the message.  v2 (PFS or nopfs) produces the complete wire format directly
    // (0x00 0x02 | ki | E | mlkem_ct | encrypted_inner) — no protobuf wrapping.  v1 uses
    // encode_dm_v1 which wraps in Envelope + WebSocketMessage protobufs.
    std::vector<std::byte> payload;
    try {
        auto seed = globals.account_seed();
        auto ed_sec = seed.ed25519_secret();

        if (pfs_x25519)
            payload = encrypt_for_recipient_v2(
                    ed_sec, recipient, *pfs_x25519, *pfs_mlkem768, content, pro_privkey);
        else if (force_v2)
            payload = encrypt_for_recipient_v2_nopfs(ed_sec, recipient, content, pro_privkey);
        else
            payload = encode_dm_v1(content, ed_sec, sent_timestamp, recipient, pro_privkey);
    } catch (const std::exception& e) {
        log::warning(cat, "send_dm: encryption failed for message {}: {}", message_id, e.what());
        fire_status(MessageSendStatus::encrypt_failed);
        return;
    }

    // Dispatch to swarm.
    fire_status(MessageSendStatus::sending);
    try {
        _send_to_swarm(
                recipient,
                config::Namespace::Default,
                std::move(payload),
                ttl,
                [this, message_id](bool success) {
                    if (callbacks.message_send_status) {
                        try {
                            callbacks.message_send_status(
                                    message_id,
                                    success ? MessageSendStatus::success
                                            : MessageSendStatus::network_error);
                        } catch (const std::exception& e) {
                            log::warning(cat, "message_send_status callback threw: {}", e.what());
                        }
                    }
                });
    } catch (const std::logic_error&) {
        fire_status(MessageSendStatus::no_network);
    }
}

void Core::_flush_pending_sends(std::span<const std::byte, 33> session_id) {
    auto it = _pending_sends.begin();
    while (it != _pending_sends.end()) {
        if (std::ranges::equal(it->recipient, session_id)) {
            auto pending = std::move(*it);
            it = _pending_sends.erase(it);
            _do_send_dm(
                    pending.id,
                    pending.recipient,
                    pending.content,
                    pending.sent_timestamp,
                    pending.pro_privkey ? ed25519::OptionalPrivKeySpan{*pending.pro_privkey}
                                        : ed25519::OptionalPrivKeySpan{},
                    pending.ttl,
                    pending.force_v2);
        } else {
            ++it;
        }
    }
}

int64_t Core::send_dm(
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte> content,
        sys_ms sent_timestamp,
        const ed25519::OptionalPrivKeySpan& pro_privkey,
        std::chrono::milliseconds ttl,
        bool force_v2) {
    auto id = _next_message_id++;

    // Check cache state to decide whether we can send immediately or must queue.
    auto conn = db.conn();
    auto row = conn.prepared_maybe_get<std::optional<int64_t>, std::optional<int64_t>>(
            "SELECT fetched_at, nak_at FROM pfs_key_cache WHERE session_id = ?",
            recipient_session_id);

    bool have_cached_key = false;
    bool is_nak = false;

    if (row) {
        auto& [fetched_at, nak_at] = *row;
        if (fetched_at)
            have_cached_key = true;
        else if (nak_at)
            is_nak = true;
    }

    if (have_cached_key || is_nak) {
        // Can send immediately: either we have keys (use v2 PFS) or it's a NAK (use v1 or v2
        // nopfs).
        _do_send_dm(id, recipient_session_id, content, sent_timestamp, pro_privkey, ttl, force_v2);
    } else if (_network) {
        // No cache entry at all: need to fetch keys first.  Queue the send and initiate a
        // prefetch.  The pfs_keys_fetched callback will flush it.
        PendingSend pending;
        pending.id = id;
        std::ranges::copy(recipient_session_id, pending.recipient.begin());
        pending.content.assign(content.begin(), content.end());
        pending.sent_timestamp = sent_timestamp;
        if (pro_privkey) {
            auto& stored = pending.pro_privkey.emplace();
            std::memcpy(stored.data(), pro_privkey->data(), 64);
        }
        pending.ttl = ttl;
        pending.force_v2 = force_v2;
        _pending_sends.push_back(std::move(pending));

        if (callbacks.message_send_status)
            callbacks.message_send_status(id, MessageSendStatus::awaiting_keys);

        // Wire up flushing: wrap the existing callback to also flush pending sends.
        auto existing_cb = callbacks.pfs_keys_fetched;
        callbacks.pfs_keys_fetched =
                [this, existing_cb](std::span<const std::byte, 33> sid, PfsKeyFetch result) {
                    if (existing_cb)
                        existing_cb(sid, result);
                    _flush_pending_sends(sid);
                };

        prefetch_pfs_keys(recipient_session_id);
    } else {
        // No cache and no network: fire immediate failure.
        if (callbacks.message_send_status)
            callbacks.message_send_status(id, MessageSendStatus::no_network);
    }

    return id;
}

void Core::_handle_direct_messages(std::span<const SwarmMessage> messages) {
    if (!callbacks.message_received && !callbacks.message_decrypt_failed)
        return;

    auto seed = globals.account_seed();
    auto session_id = globals.session_id();
    // Long-term X25519 pub/sec used for v2 key-indicator prefix decryption.
    std::span<const std::byte, 32> x25519_pub{session_id.data() + 1, 32};
    auto x25519_sec = seed.x25519_key();

    // Ed25519 secret key used for v1 envelope decryption.
    auto ed_sec = seed.ed25519_secret();

    auto fire_received = [&](ReceivedMessage out) {
        if (!callbacks.message_received)
            return;
        try {
            callbacks.message_received(std::move(out));
        } catch (const std::exception& e) {
            log::warning(cat, "message_received callback threw: {}", e.what());
        }
    };

    auto fire_fail = [&](const SwarmMessage& msg, MessageDecryptFailure reason) {
        if (!callbacks.message_decrypt_failed)
            return;
        try {
            callbacks.message_decrypt_failed(msg, reason);
        } catch (const std::exception& e) {
            log::warning(cat, "message_decrypt_failed callback threw: {}", e.what());
        }
    };

    for (const auto& msg : messages) {
        auto data = msg.data;
        if (data.empty()) {
            fire_fail(msg, MessageDecryptFailure::bad_format);
            continue;
        }

        if (data[0] == std::byte{0x00}) {
            // Version 2 (PFS+PQ) or an unrecognised future version.
            if (data.size() < 2 || data[1] != std::byte{0x02}) {
                fire_fail(msg, MessageDecryptFailure::unknown_version);
                continue;
            }

            // Extract the 2-byte ML-KEM key indicator, then look up matching account keys.
            std::array<std::byte, 2> ki;
            try {
                ki = decrypt_incoming_v2_prefix(x25519_sec, x25519_pub, data);
            } catch (const std::exception&) {
                // Ciphertext is too short or otherwise structurally malformed.
                fire_fail(msg, MessageDecryptFailure::bad_format);
                continue;
            }

            auto keys = devices.active_account_keys(ki);

            bool decrypted = false;
            for (auto& key : keys) {
                try {
                    auto result = decrypt_incoming_v2(
                            session_id, key.x25519_sec, key.x25519_pub, key.mlkem768_sec, data);
                    ReceivedMessage out;
                    out.hash = msg.hash;
                    out.timestamp = msg.timestamp;
                    out.expiry = msg.expiry;
                    out.sender_session_id = result.sender_session_id;
                    out.version = 2;
                    out.content = std::move(result.content);
                    out.pro_signature = result.pro_signature;
                    out.pfs_encrypted = true;
                    fire_received(std::move(out));
                    decrypted = true;
                    break;
                } catch (const DecryptV2Error&) {
                    // This key didn't work; try the next candidate.
                } catch (const std::exception& e) {
                    // Unrecoverable structural error in the message itself.
                    log::warning(cat, "v2 direct message format error: {}", e.what());
                    fire_fail(msg, MessageDecryptFailure::bad_format);
                    decrypted = true;  // Prevent the non-PFS fallback attempt.
                    break;
                }
            }
            if (!decrypted) {
                // No PFS key matched; try the non-PFS fallback (sender had no PFS keys).
                try {
                    auto result =
                            decrypt_incoming_v2_nopfs(session_id, x25519_sec, x25519_pub, data);
                    ReceivedMessage out;
                    out.hash = msg.hash;
                    out.timestamp = msg.timestamp;
                    out.expiry = msg.expiry;
                    out.sender_session_id = result.sender_session_id;
                    out.version = 2;
                    out.content = std::move(result.content);
                    out.pro_signature = result.pro_signature;
                    // pfs_encrypted remains false (default)
                    fire_received(std::move(out));
                } catch (const DecryptV2Error&) {
                    // Non-PFS fallback also failed: message cannot be read.
                    fire_fail(msg, MessageDecryptFailure::no_pfs_key);
                } catch (const std::exception& e) {
                    log::warning(cat, "v2 direct message format error: {}", e.what());
                    fire_fail(msg, MessageDecryptFailure::bad_format);
                }
            }

        } else {
            // Version 1: protobuf WebSocketMessage → Envelope wire format.
            try {
                auto decoded = decode_dm_envelope(ed_sec, data, pro_backend::PUBKEY);

                ReceivedMessage out;
                out.hash = msg.hash;
                out.timestamp = msg.timestamp;
                out.expiry = msg.expiry;
                out.version = 1;
                // Reconstruct the 33-byte (0x05-prefixed) session ID from the x25519 pubkey.
                out.sender_session_id[0] = std::byte{0x05};
                std::ranges::copy(decoded.sender_x25519_pubkey, out.sender_session_id.begin() + 1);
                out.content = std::move(decoded.content_plaintext);
                if (decoded.envelope.flags & SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG)
                    out.pro_signature = decoded.envelope.pro_sig;
                fire_received(std::move(out));
            } catch (const std::exception& e) {
                log::warning(cat, "v1 direct message decryption error: {}", e.what());
                fire_fail(msg, MessageDecryptFailure::decrypt_failed);
            }
        }
    }
}

void Core::receive_messages(
        std::span<const SwarmMessage> messages, config::Namespace ns, bool is_final) {
    using config::Namespace;
    switch (ns) {
        case Namespace::Default: _handle_direct_messages(messages); break;
        case Namespace::Devices: devices.parse_device_messages(messages, is_final); break;
        case Namespace::AccountPubkeys: devices.parse_account_pubkeys(messages, is_final); break;
        default:
            log::warning(
                    cat,
                    "receive_messages: ignoring unhandled namespace {}",
                    static_cast<int16_t>(ns));
    }
}

void Core::apply_migrations() {
    auto cat = log::Cat("schema");

    auto conn = db.conn();
    exec_query(conn.sql, R"(
CREATE TABLE IF NOT EXISTS migrations_applied (
    name TEXT PRIMARY KEY NOT NULL
) STRICT
)");

    std::unordered_set<std::string> applied;
    {
        SQLite::Statement st{conn.sql, "SELECT name FROM migrations_applied"};
        while (st.executeStep())
            applied.insert(get<std::string>(st));
    }

    log::debug(cat, "Checking schema migrations");
    for (const auto& [name, apply] : schema::MIGRATIONS) {
        if (applied.count(name)) {
            log::debug(cat, "Schema migration {} already applied", name);
            continue;
        }

        try {
            log::info(cat, "Applying database schema migration {}", name);

            SQLite::Transaction tx{conn.sql};

            apply(conn, *this);
            conn.prepared_exec("INSERT INTO migrations_applied (name) VALUES (?)", name);

            tx.commit();
        } catch (const std::exception& e) {
            log::critical(cat, "Database schema migration '{}' failed: {}", name, e.what());
            throw;
        }
    }
    log::debug(cat, "All schema migrations are applied");
}

}  // namespace session::core
