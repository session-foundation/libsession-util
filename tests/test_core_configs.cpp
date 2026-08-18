#include <catch2/catch_test_macros.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/local.hpp>
#include <session/config/user_groups.hpp>
#include <session/config/user_profile.hpp>
#include <session/core.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;

namespace {

/// Reopens the same database file, which is how "does this survive a restart" is asked: the configs
/// are rebuilt from their dumps rather than from anything still in memory.
void reopen(TempCore& c) {
    c.core.reset();
    c.core = std::make_unique<core::Core>(c.path);
}

int64_t stored_dumps(TempCore& c) {
    return c->database().conn().prepared_get<int64_t>("SELECT count(*) FROM config_dumps");
}

/// A config message as it would arrive from the swarm: what another device on this account pushed.
/// Built from a second config object holding the same account key, since that is exactly what
/// another device is.
std::vector<std::vector<std::byte>> push_from_another_device(TempCore& c, std::string_view name) {
    auto seed = c->globals.account_seed();
    config::UserProfile theirs{seed.ed25519_secret(), std::nullopt};
    theirs.set_name(name);
    auto [seqno, messages, obsolete] = theirs.push();
    return messages;
}

/// Note the spans: a SwarmMessage points at its data rather than owning it, exactly as one decoded
/// from a poll response does, so whatever is passed in here has to outlive the result.
std::vector<SwarmMessage> as_swarm_messages(const std::vector<std::vector<std::byte>>& messages) {
    std::vector<SwarmMessage> out;
    for (size_t i = 0; i < messages.size(); i++) {
        SwarmMessage m;
        m.hash = fmt::format("fakehash{}", i);
        m.data = messages[i];
        out.push_back(std::move(m));
    }
    return out;
}

}  // namespace

TEST_CASE("Configs: a fresh account has empty configs", "[core][configs]") {
    TempCore c{};

    CHECK_FALSE(c->configs.user_profile().get_name());
    CHECK(c->configs.contacts().size() == 0);

    // Nothing has changed, so nothing is owed to the swarm and nothing has been written.
    CHECK_FALSE(c->configs.needs_push());
    CHECK(stored_dumps(c) == 0);
}

TEST_CASE("Configs: a namespace names exactly one config", "[core][configs]") {
    TempCore c{};

    auto base = [](auto& conf) { return static_cast<config::ConfigBase*>(&conf); };

    CHECK(c->configs.for_namespace(config::Namespace::UserProfile) ==
          base(c->configs.user_profile()));
    CHECK(c->configs.for_namespace(config::Namespace::Contacts) == base(c->configs.contacts()));
    CHECK(c->configs.for_namespace(config::Namespace::UserGroups) == base(c->configs.user_groups()));
    CHECK(c->configs.for_namespace(config::Namespace::ConvoInfoVolatile) ==
          base(c->configs.convo_info_volatile()));

    // Local reports UserProfile's namespace, having none of its own, so the lookup must not be
    // answering from storage_namespace() -- if it were, one of these two would win arbitrarily.
    CHECK(c->configs.for_namespace(config::Namespace::UserProfile) != base(c->configs.local()));

    // A namespace that holds no config at all.
    CHECK(c->configs.for_namespace(config::Namespace::Default) == nullptr);
}

TEST_CASE("Configs: a dumped config survives a restart", "[core][configs]") {
    TempCore c{};

    c->configs.user_profile().set_name("Leia");
    c->configs.local().set_setting("some_toggle", true);
    c->configs.store_dumps();

    reopen(c);

    CHECK(c->configs.user_profile().get_name() == "Leia");
    CHECK(c->configs.local().get_setting("some_toggle") == true);

    // Reloading is not a change, so it owes no new dump.
    CHECK_FALSE(c->configs.user_profile().needs_dump());
}

TEST_CASE("Configs: merging what another device pushed", "[core][configs]") {
    TempCore c{};

    auto pushed = push_from_another_device(c, "Padmé");
    auto incoming = as_swarm_messages(pushed);
    c->receive_messages(incoming, config::Namespace::UserProfile, true);

    CHECK(c->configs.user_profile().get_name() == "Padmé");

    // Adopting someone else's config outright is not a change of ours, so there is nothing to push
    // back -- but it is a change to what we hold, so it is written out.
    CHECK_FALSE(c->configs.needs_push());
    CHECK(stored_dumps(c) == 1);

    reopen(c);
    CHECK(c->configs.user_profile().get_name() == "Padmé");
}

TEST_CASE("Configs: a local change survives merging a config that predates it", "[core][configs]") {
    TempCore c{};

    // Our own unpushed change participates in the merge as though it had been pushed, so a config
    // from another device that has never heard of it does not erase it.  This is what makes "in our
    // database but not in the config" mean deleted elsewhere rather than not yet synced.
    c->configs.contacts().set(c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
    REQUIRE(c->configs.contacts().size() == 1);

    auto seed = c->globals.account_seed();
    config::Contacts theirs{seed.ed25519_secret(), std::nullopt};
    theirs.set(theirs.get_or_construct("05" + std::string(64, 'b')));
    auto [seqno, messages, obsolete] = theirs.push();

    auto incoming = as_swarm_messages(messages);
    c->receive_messages(incoming, config::Namespace::Contacts, true);

    // Both contacts are present, and the merged result is ours to push since only we hold it.
    CHECK(c->configs.contacts().size() == 2);
    CHECK(c->configs.needs_push());
}

TEST_CASE("Configs: Local is never owed to a swarm", "[core][configs]") {
    TempCore c{};

    c->configs.local().set_setting("a_toggle", true);

    // The change is real -- it is held, and dumped like any other config...
    CHECK(c->configs.local().get_setting("a_toggle") == true);
    CHECK(c->configs.local().needs_dump());

    // ...but Local has no swarm, so it can never make the account owe a push.  It declines on its
    // own account (needs_push() is overridden to false) and is also left out of the pushable set,
    // so neither alone is load-bearing.
    CHECK_FALSE(c->configs.local().needs_push());
    CHECK_FALSE(c->configs.needs_push());
}

TEST_CASE("Configs: a batch holds back the dump", "[core][configs]") {
    TempCore c{};

    auto pushed = push_from_another_device(c, "Rey");
    auto profile = as_swarm_messages(pushed);

    {
        auto held = c->configs.batch();
        c->receive_messages(profile, config::Namespace::UserProfile, true);

        // The merge landed, but writing it out is deferred: nothing reads a half-processed batch.
        CHECK(c->configs.user_profile().get_name() == "Rey");
        CHECK(stored_dumps(c) == 0);
    }

    CHECK(stored_dumps(c) == 1);
}
