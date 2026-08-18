#include "session/core/configs.hpp"

#include <oxen/log.hpp>

#include <session/config/base.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/local.hpp>
#include <session/config/user_groups.hpp>
#include <session/config/user_profile.hpp>
#include <session/core.hpp>
#include <string>
#include <unordered_map>
#include <utility>

namespace session::core {

static auto cat = oxen::log::Cat("configs");

namespace log = oxen::log;

Configs::Configs(Core& core) : CoreComponent{core} {}

Configs::~Configs() = default;

void Configs::_load() {
    if (_loaded)
        return;

    auto seed = core.globals.account_seed();
    auto key = seed.ed25519_secret();

    // Copied out rather than referenced: a sqlite::blob spans the statement's own memory, which is
    // reused as the iteration advances.
    std::unordered_map<std::string, std::vector<std::byte>> dumps;
    for (auto [type, data] : conn().prepared_results<std::string, sqlite::blob>(
                 "SELECT type, data FROM config_dumps WHERE pubkey = ?",
                 core.globals.session_id()))
        dumps.emplace(std::move(type), std::vector<std::byte>{data.begin(), data.end()});

    auto stored = [&dumps](std::string_view type) -> std::optional<std::span<const std::byte>> {
        if (auto it = dumps.find(std::string{type}); it != dumps.end())
            return std::span<const std::byte>{it->second};
        return std::nullopt;
    };

    _user_profile = std::make_unique<config::UserProfile>(key, stored("UserProfile"));
    _contacts = std::make_unique<config::Contacts>(key, stored("Contacts"));
    _convo_info_volatile =
            std::make_unique<config::ConvoInfoVolatile>(key, stored("ConvoInfoVolatile"));
    _user_groups = std::make_unique<config::UserGroups>(key, stored("UserGroups"));
    _local = std::make_unique<config::Local>(key, stored("Local"));

    _loaded = true;

    // The names above are literals because a dump has to be handed to the constructor, so there is
    // no object to ask for its domain until after it exists.  Anything left unclaimed is therefore
    // either a typo in one of them -- which would silently discard a config and resync it from the
    // swarm -- or a dump written by a version that knows a config this one does not.
    for (auto* conf : all())
        dumps.erase(std::string{conf->encryption_domain()});
    for (const auto& [type, _] : dumps)
        log::warning(cat, "Ignoring stored config dump of unrecognised type {}", type);

    log::debug(cat, "Loaded {} config(s)", all().size());
}

std::vector<config::ConfigBase*> Configs::all() {
    _load();
    return {_user_profile.get(),
            _contacts.get(),
            _convo_info_volatile.get(),
            _user_groups.get(),
            _local.get()};
}

config::UserProfile& Configs::user_profile() {
    _load();
    return *_user_profile;
}

config::Contacts& Configs::contacts() {
    _load();
    return *_contacts;
}

config::ConvoInfoVolatile& Configs::convo_info_volatile() {
    _load();
    return *_convo_info_volatile;
}

config::UserGroups& Configs::user_groups() {
    _load();
    return *_user_groups;
}

config::Local& Configs::local() {
    _load();
    return *_local;
}

config::ConfigBase* Configs::for_namespace(config::Namespace ns) {
    _load();
    switch (ns) {
        case config::Namespace::UserProfile: return _user_profile.get();
        case config::Namespace::Contacts: return _contacts.get();
        case config::Namespace::ConvoInfoVolatile: return _convo_info_volatile.get();
        case config::Namespace::UserGroups: return _user_groups.get();
        default: return nullptr;
    }
}

void Configs::_store(config::ConfigBase& conf) {
    if (!conf.needs_dump())
        return;

    conn().prepared_exec(
            R"(
INSERT INTO config_dumps (pubkey, type, data) VALUES (?, ?, ?)
ON CONFLICT (pubkey, type) DO UPDATE SET data = excluded.data
)",
            core.globals.session_id(),
            conf.encryption_domain(),
            conf.dump());
}

void Configs::store_dumps() {
    for (auto* conf : all())
        _store(*conf);
}

Configs::Batch::Batch(Configs& configs) : _configs{configs} {
    _configs._batch_depth++;
}

Configs::Batch::~Batch() {
    if (--_configs._batch_depth == 0 && _configs._flush_pending)
        _configs._flush();
}

void Configs::_flush() {
    if (_batch_depth > 0) {
        _flush_pending = true;
        return;
    }
    _flush_pending = false;
    store_dumps();
}

void Configs::merge(config::Namespace ns, std::span<const SwarmMessage> messages) {
    auto held = batch();

    auto* conf = for_namespace(ns);
    if (!conf) {
        log::warning(
                cat,
                "Ignoring {} config message(s) for namespace {}, which holds no config",
                messages.size(),
                static_cast<int16_t>(ns));
        return;
    }

    std::vector<std::pair<std::string, std::span<const std::byte>>> incoming;
    incoming.reserve(messages.size());
    for (const auto& m : messages)
        incoming.emplace_back(m.hash, m.data);

    auto accepted = conf->merge(incoming);

    log::debug(
            cat,
            "Merged {} of {} {} config message(s); {}, {}",
            accepted.size(),
            incoming.size(),
            conf->encryption_domain(),
            conf->needs_push() ? "needs push" : "up to date",
            conf->needs_dump() ? "changed" : "unchanged");

    _flush();
}

std::vector<config::ConfigBase*> Configs::_pushable() {
    _load();
    return {_user_profile.get(),
            _contacts.get(),
            _convo_info_volatile.get(),
            _user_groups.get()};
}

bool Configs::needs_push() {
    for (auto* conf : _pushable())
        if (conf->needs_push())
            return true;
    return false;
}

}  // namespace session::core
