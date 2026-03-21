#include <fmt/format.h>
#include <fmt/ranges.h>
#include <oxenc/base64.h>
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

    auto namespaces = {config::Namespace::Devices, config::Namespace::AccountPubkeys};
    nlohmann::json ns_list = nlohmann::json::array();
    nlohmann::json last_hashes = nlohmann::json::object();

    auto conn = db.conn();
    for (auto ns : namespaces) {
        auto ns_val = static_cast<int16_t>(ns);
        ns_list.push_back(ns_val);
        auto last_hash = conn.prepared_maybe_get<std::string>(
                "SELECT last_hash FROM namespace_sync WHERE namespace = ?", ns_val);
        if (last_hash)
            last_hashes[std::to_string(ns_val)] = *last_hash;
    }

    auto now_ms = epoch_ms(clock_now_ms());
    auto session_id = oxenc::to_hex(globals.session_id());

    nlohmann::json params = {
            {"pubkey", session_id},
            {"namespaces", ns_list},
            {"timestamp", now_ms},
    };

    if (!last_hashes.empty())
        params["last_hashes"] = last_hashes;

    std::string to_sign = fmt::format("retrieve{}{}", session_id, now_ms);
    std::array<unsigned char, 64> sig;
    auto seed = globals.account_seed();
    crypto_sign_ed25519_detached(
            sig.data(),
            nullptr,
            reinterpret_cast<const unsigned char*>(to_sign.data()),
            to_sign.size(),
            reinterpret_cast<const unsigned char*>(seed.buf.data()));

    params["signature"] = oxenc::to_base64(sig);

    nlohmann::json req_body = {
            {"method", "retrieve"},
            {"params", params},
    };

    net->get_swarm(globals.pubkey_x25519(), false, [this, net, req_body](auto, auto swarm) {
        if (swarm.empty())
            return;

        auto body_str = req_body.dump();
        net->send_request(
                network::Request{
                        swarm.front(),
                        "storage_rpc",
                        to_vector<unsigned char>(body_str),
                        network::RequestCategory::standard_small,
                        20s},
                [this](bool success,
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
INSERT INTO namespace_sync (namespace, last_hash) VALUES (?, ?)
ON CONFLICT(namespace) DO UPDATE SET last_hash = excluded.last_hash
)",
                                            ns_val,
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
