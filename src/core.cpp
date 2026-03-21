#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <mlkem_native.h>
#include <oxenc/base64.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <initializer_list>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/loop.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/schema/schema_registry.hpp>
#include <session/network/session_network.hpp>
#include <session/network/session_network_types.hpp>
#include <session/util.hpp>
#include <session/xed25519.hpp>
#include <unordered_set>

#include "session/core/component.hpp"

namespace session::core {

namespace log = oxen::log;
using namespace session::sqlite;
using namespace oxen::log::literals;
static auto cat = log::Cat("core");

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
        _poll_ticker = _loop->call_every(20s, [this] { _poll(); });
    } else if (!_network && _poll_ticker) {
        _poll_ticker->stop();
        _poll_ticker.reset();
    }
}

void Core::_poll() {
    auto net = _network;
    if (!net)
        return;

    constexpr std::array namespaces = {
            config::Namespace::Devices, config::Namespace::AccountPubkeys};
    nlohmann::json ns_list = nlohmann::json::array();
    for (auto ns : namespaces)
        ns_list.push_back(static_cast<int16_t>(ns));

    auto now_ms = epoch_ms(clock_now_ms());
    auto session_id = oxenc::to_hex(globals.session_id());

    std::string to_sign = fmt::format("retrieve{}{}", session_id, now_ms);
    std::array<unsigned char, 64> sig;
    auto seed = globals.account_seed();
    crypto_sign_ed25519_detached(
            sig.data(),
            nullptr,
            reinterpret_cast<const unsigned char*>(to_sign.data()),
            to_sign.size(),
            reinterpret_cast<const unsigned char*>(seed.buf.data()));

    auto sig_b64 = oxenc::to_base64(sig);

    net->get_swarm(
            globals.pubkey_x25519(),
            false,
            [this, net, namespaces, ns_list, session_id, now_ms, sig_b64](auto, auto swarm) {
                if (swarm.empty())
                    return;

                auto& node = swarm.front();

                nlohmann::json last_hashes = nlohmann::json::object();
                {
                    auto conn = db.conn();
                    for (auto ns : namespaces) {
                        auto ns_val = static_cast<int16_t>(ns);
                        auto last_hash = conn.prepared_maybe_get<std::string>(
                                "SELECT last_hash FROM namespace_sync"
                                " WHERE namespace = ? AND sn_pubkey = ?",
                                ns_val,
                                node.remote_pubkey);
                        if (last_hash)
                            last_hashes[std::to_string(ns_val)] = *last_hash;
                    }
                }

                nlohmann::json params = {
                        {"pubkey", session_id},
                        {"namespaces", ns_list},
                        {"timestamp", now_ms},
                        {"signature", sig_b64},
                };
                if (!last_hashes.empty())
                    params["last_hashes"] = last_hashes;

                nlohmann::json req_body = {
                        {"method", "retrieve"},
                        {"params", params},
                };

                auto body_str = req_body.dump();
                net->send_request(
                        network::Request{
                                node,
                                "storage_rpc",
                                to_vector<unsigned char>(body_str),
                                network::RequestCategory::standard_small,
                                20s},
                        [this, sn_pubkey = node.remote_pubkey](
                                bool success,
                                bool /*timeout*/,
                                int16_t /*status_code*/,
                                std::vector<std::pair<std::string, std::string>> /*headers*/,
                                std::optional<std::string> body) {
                            if (!success || !body)
                                return;

                            try {
                                auto json = nlohmann::json::parse(*body);
                                if (!json.contains("results") || !json["results"].is_array())
                                    return;

                                auto conn = db.conn();
                                for (const auto& res : json["results"]) {
                                    if (!res.contains("namespace") || !res.contains("messages") ||
                                        !res["messages"].is_array())
                                        continue;

                                    auto ns_val = res["namespace"].get<int16_t>();
                                    auto ns = static_cast<config::Namespace>(ns_val);

                                    std::vector<std::vector<unsigned char>> messages_data;
                                    std::string newest_hash;

                                    for (const auto& msg : res["messages"]) {
                                        if (!msg.contains("data") || !msg["data"].is_string())
                                            continue;
                                        auto b64_data = msg["data"].get<std::string_view>();
                                        auto& decoded = messages_data.emplace_back();
                                        decoded.reserve(oxenc::from_base64_size(b64_data.size()));
                                        oxenc::from_base64(
                                                b64_data.begin(),
                                                b64_data.end(),
                                                std::back_inserter(decoded));

                                        if (msg.contains("hash") && msg["hash"].is_string())
                                            newest_hash = msg["hash"].get<std::string>();
                                    }

                                    if (!messages_data.empty()) {
                                        if (!newest_hash.empty())
                                            conn.prepared_exec(
                                                    R"(
INSERT INTO namespace_sync (namespace, sn_pubkey, last_hash) VALUES (?, ?, ?)
ON CONFLICT(namespace, sn_pubkey) DO UPDATE SET last_hash = excluded.last_hash
)",
                                                    ns_val,
                                                    sn_pubkey,
                                                    newest_hash);
                                        receive_messages(to_view_vector(messages_data), ns, true);
                                    }
                                }
                            } catch (const std::exception& e) {
                                log::warning(cat, "Failed to parse poll response: {}", e.what());
                            }
                        });
            });
}

void Core::prefetch_pfs_keys(std::span<const unsigned char, 33> session_id) {
    auto net = _network;
    if (!net)
        throw std::logic_error{"prefetch_pfs_keys called without a network object"};

    // One copy of session_id for async use; subsequently moved into lambdas.
    // sid must be unsigned char because xed25519::verify requires it for the x25519 pubkey span.
    std::array<unsigned char, 33> sid;
    std::ranges::copy(session_id, sid.begin());

    // Skip the fetch if the cached entry is still fresh (< 24h old).
    {
        auto conn = db.conn();
        auto fetched_at = conn.prepared_maybe_get<int64_t>(
                "SELECT fetched_at FROM pfs_key_cache WHERE session_id = ?", sid);
        if (fetched_at) {
            auto age = clock_now_s() - from_epoch_s(*fetched_at);
            if (age < PFS_KEY_FRESH_DURATION) {
                log::debug(
                        cat,
                        "prefetch_pfs_keys: cached key for {} is still fresh ({} old), skipping",
                        oxenc::to_hex(session_id.begin(), session_id.end()),
                        age);
                return;
            }
            log::debug(
                    cat,
                    "prefetch_pfs_keys: cached key for {} is stale ({} old), re-fetching",
                    oxenc::to_hex(session_id.begin(), session_id.end()),
                    age);
        } else {
            log::debug(
                    cat,
                    "prefetch_pfs_keys: no cached key for {}, fetching",
                    oxenc::to_hex(session_id.begin(), session_id.end()));
        }
    }

    // The swarm is indexed by the x25519 pubkey — the session_id without its 0x05 prefix.
    network::x25519_pubkey x25519_pub;
    std::ranges::copy(session_id.subspan<1>(), x25519_pub.begin());

    auto session_id_hex = oxenc::to_hex(session_id.begin(), session_id.end());
    auto now_ms = epoch_ms(clock_now_ms());

    nlohmann::json req_body = {
            {"method", "retrieve"},
            {"params",
             {{"pubkey", session_id_hex},
              {"namespaces", {static_cast<int16_t>(config::Namespace::AccountPubkeys)}},
              {"timestamp", now_ms}}},
    };

    net->get_swarm(
            x25519_pub, false, [this, net, sid = std::move(sid), req_body](auto, auto swarm) {
                if (swarm.empty()) {
                    log::debug(cat, "prefetch_pfs_keys: get_swarm returned empty swarm");
                    return;
                }

                auto body_str = req_body.dump();
                net->send_request(
                        network::Request{
                                swarm.front(),
                                "storage_rpc",
                                to_vector<unsigned char>(body_str),
                                network::RequestCategory::standard_small,
                                20s},
                        [this, sid = std::move(sid)](
                                bool success,
                                bool /*timeout*/,
                                int16_t /*status_code*/,
                                std::vector<std::pair<std::string, std::string>> /*headers*/,
                                std::optional<std::string> body) {
                            if (!success || !body) {
                                log::debug(cat, "prefetch_pfs_keys: request failed");
                                return;
                            }

                            try {
                                auto json = nlohmann::json::parse(*body);
                                if (!json.contains("results") || !json["results"].is_array()) {
                                    log::warning(
                                            cat,
                                            "prefetch_pfs_keys: response missing or invalid "
                                            "'results' array");
                                    return;
                                }

                                // Strip the 0x05 prefix to get the x25519 pubkey for
                                // signature verification.
                                std::span<const unsigned char, 32> x25519_pub{sid.data() + 1, 32};

                                // Track the most recently valid pubkeys seen across all messages.
                                std::optional<std::array<std::byte, 32>> pk_x25519;
                                std::optional<std::array<std::byte, MLKEM768_PUBLICKEYBYTES>>
                                        pk_mlkem768;

                                for (const auto& res : json["results"]) {
                                    if (!res.contains("namespace")) {
                                        log::warning(
                                                cat,
                                                "prefetch_pfs_keys: result entry missing "
                                                "'namespace' field");
                                        continue;
                                    }
                                    if (res["namespace"].get<int16_t>() !=
                                        static_cast<int16_t>(config::Namespace::AccountPubkeys))
                                        continue;
                                    if (!res.contains("messages") || !res["messages"].is_array()) {
                                        log::warning(
                                                cat,
                                                "prefetch_pfs_keys: AccountPubkeys result "
                                                "missing or invalid 'messages' array");
                                        continue;
                                    }

                                    for (const auto& msg : res["messages"]) {
                                        if (!msg.contains("data") || !msg["data"].is_string()) {
                                            log::warning(
                                                    cat,
                                                    "prefetch_pfs_keys: message missing or "
                                                    "non-string 'data' field");
                                            continue;
                                        }
                                        auto b64 = msg["data"].get<std::string_view>();
                                        std::vector<std::byte> decoded;
                                        decoded.reserve(oxenc::from_base64_size(b64.size()));
                                        oxenc::from_base64(
                                                b64.begin(),
                                                b64.end(),
                                                std::back_inserter(decoded));
                                        try {
                                            oxenc::bt_dict_consumer in{decoded};
                                            auto M = in.require_span<
                                                    std::byte,
                                                    MLKEM768_PUBLICKEYBYTES>("M");
                                            auto X = in.require_span<std::byte, 32>("X");
                                            in.require_signature(
                                                    "~",
                                                    [&x25519_pub](
                                                            std::span<const unsigned char> b,
                                                            std::span<const unsigned char> sig) {
                                                        if (!xed25519::verify(sig, x25519_pub, b))
                                                            throw std::runtime_error{
                                                                    "signature verification "
                                                                    "failed"};
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
                                }

                                if (!pk_x25519 || !pk_mlkem768) {
                                    log::debug(
                                            cat,
                                            "prefetch_pfs_keys: no valid account pubkey message "
                                            "found in response");
                                    return;
                                }

                                db.conn().prepared_exec(
                                        R"(
INSERT INTO pfs_key_cache (session_id, fetched_at, pubkey_x25519, pubkey_mlkem768)
VALUES (?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
    fetched_at = excluded.fetched_at,
    pubkey_x25519 = excluded.pubkey_x25519,
    pubkey_mlkem768 = excluded.pubkey_mlkem768
)",
                                        sid,
                                        epoch_seconds(clock_now_s()),
                                        *pk_x25519,
                                        *pk_mlkem768);
                            } catch (const std::exception& e) {
                                log::warning(
                                        cat,
                                        "Failed to process PFS key fetch response: {}",
                                        e.what());
                            }
                        });
            });
}

void Core::receive_messages(
        std::span<const std::span<const unsigned char>> messages,
        config::Namespace ns,
        bool is_final) {
    using config::Namespace;
    switch (ns) {
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
