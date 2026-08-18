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

/// A Core with a mock network attached, ready to have a push observed.
struct PushableCore {
    TempCore core;
    std::shared_ptr<MockNetwork> net = std::make_shared<MockNetwork>();

    PushableCore() {
        net->current_node.remote_pubkey[0] = std::byte{0x01};
        core->set_network(net);
        net->sent_requests.clear();
    }

    core::Core* operator->() { return &*core; }

    const network::Request& only_request() {
        REQUIRE(net->sent_requests.size() == 1);
        return net->sent_requests[0].request;
    }

    /// The subrequests of the one request sent, bound to a local: ranging over
    /// `parse_json(body)["requests"]` directly would iterate a reference into a dead temporary.
    nlohmann::json subrequests() { return parse_json(*only_request().body)["requests"]; }

    /// Answers the outstanding request as the storage server would, one result per subrequest.
    /// `hashes` gives the hash each store returns; a nullopt is a store that failed.
    void answer(std::vector<std::optional<std::string>> hashes, int delete_code = 200) {
        auto results = nlohmann::json::array();
        for (auto& h : hashes) {
            if (h)
                results.push_back({{"code", 200}, {"body", {{"hash", *h}}}});
            else
                results.push_back({{"code", 503}, {"body", {{"reason", "nope"}}}});
        }
        auto subs = subrequests();
        while (results.size() < subs.size())
            results.push_back({{"code", delete_code}, {"body", nlohmann::json::object()}});

        auto callback = net->sent_requests[0].callback;
        net->sent_requests.clear();
        callback(true, false, 200, {}, nlohmann::json{{"results", results}}.dump());
    }
};

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

TEST_CASE("Configs: a change goes out as one signed sequence", "[core][configs][push]") {
    PushableCore c;

    c->configs.user_profile().set_name("Leia");
    // Local changes too: it must not appear in what goes out.
    c->configs.local().set_setting("a_toggle", true);
    c->configs.push_now();

    CHECK(c.only_request().endpoint == "sequence");

    auto subs = c.subrequests();
    REQUIRE(subs.size() == 1);
    CHECK(subs[0]["method"] == "store");
    CHECK(subs[0]["params"]["namespace"] == 2);
    CHECK(subs[0]["params"]["ttl"] == std::chrono::milliseconds{30 * 24h}.count());
    // Config namespaces are owner-write, so the store carries a signature and the key to check it.
    CHECK(subs[0]["params"].contains("signature"));
    CHECK(subs[0]["params"].contains("pubkey_ed25519"));

    // Nothing is obsolete on a first push, so there is nothing to delete.
    CHECK_FALSE(subs[0].contains("delete"));
}

TEST_CASE("Configs: two dirty configs share one request", "[core][configs][push]") {
    PushableCore c;

    c->configs.user_profile().set_name("Leia");
    c->configs.contacts().set(c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
    c->configs.push_now();

    auto subs = c.subrequests();
    REQUIRE(subs.size() == 2);
    std::vector<int> namespaces{subs[0]["params"]["namespace"], subs[1]["params"]["namespace"]};
    std::ranges::sort(namespaces);
    CHECK(namespaces == std::vector<int>{2, 3});
}

TEST_CASE("Configs: a stored push stops being owed", "[core][configs][push]") {
    PushableCore c;

    c->configs.user_profile().set_name("Leia");
    c->configs.push_now();

    // Handing it to the swarm is not the same as it having arrived, so it is still owed until the
    // store is confirmed -- otherwise a failed push would be forgotten.
    CHECK(c->configs.needs_push());

    c.answer({"hash1"});
    CHECK_FALSE(c->configs.needs_push());
}

TEST_CASE("Configs: a rejected store leaves the config dirty", "[core][configs][push]") {
    PushableCore c;

    c->configs.user_profile().set_name("Leia");
    c->configs.push_now();
    c.answer({std::nullopt});

    // The change is still ours to deliver, and pushing again offers it again.
    CHECK(c->configs.needs_push());
    c->configs.push_now();
    CHECK(c.subrequests().size() == 1);
}

TEST_CASE("Configs: the next push deletes what it replaces", "[core][configs][push]") {
    PushableCore c;

    c->configs.user_profile().set_name("Leia");
    c->configs.push_now();
    c.answer({"hash1"});

    c->configs.user_profile().set_name("Padmé");
    c->configs.push_now();

    auto subs = c.subrequests();
    REQUIRE(subs.size() == 2);
    CHECK(subs[0]["method"] == "store");

    // The delete goes last: a sequence stops at its first failure, so nothing is removed before
    // what replaces it has been stored.
    CHECK(subs[1]["method"] == "delete");
    CHECK(subs[1]["params"]["messages"] == nlohmann::json::array({"hash1"}));
    CHECK(subs[1]["params"].contains("signature"));
}

TEST_CASE("Configs: a change schedules a push rather than sending one", "[core][configs][push]") {
    PushableCore c;

    {
        auto held = c->configs.batch();
        c->configs.user_profile().set_name("Leia");
    }

    // Releasing the batch is what notices the change; it schedules rather than sending, so a run of
    // changes coalesces into one request.
    CHECK(TestHelper::push_scheduled(c->configs));
    CHECK(c.net->sent_requests.empty());
}

TEST_CASE("Configs: the debounce waits for quiet, up to a limit", "[core][configs][push]") {
    PushableCore c;
    c->configs.push_debounce = 2s;
    c->configs.push_max_delay = 10s;

    {
        auto held = c->configs.batch();
        c->configs.user_profile().set_name("Leia");
    }
    REQUIRE(TestHelper::push_scheduled(c->configs));

    SECTION("changes still arriving hold it back") {
        TestHelper::backdate_push_state(c->configs, 500ms, 1s);
        TestHelper::push_if_due(c->configs);
        CHECK(c.net->sent_requests.empty());
        CHECK(TestHelper::push_scheduled(c->configs));
    }

    SECTION("quiet for long enough sends it") {
        TestHelper::backdate_push_state(c->configs, 3s, 4s);
        TestHelper::push_if_due(c->configs);
        CHECK(c.net->sent_requests.size() == 1);
        CHECK_FALSE(TestHelper::push_scheduled(c->configs));
    }

    SECTION("a steady trickle cannot defer it past the cap") {
        // Never quiet -- the last change was a moment ago -- but the burst began long enough ago
        // that waiting for quiet would mean waiting indefinitely.
        TestHelper::backdate_push_state(c->configs, 100ms, 11s);
        TestHelper::push_if_due(c->configs);
        CHECK(c.net->sent_requests.size() == 1);
    }
}

TEST_CASE("Configs: a push already in flight is not duplicated", "[core][configs][push]") {
    PushableCore c;

    c->configs.user_profile().set_name("Leia");
    c->configs.push_now();
    REQUIRE(c.net->sent_requests.size() == 1);

    // A second change while the first is out must not race it onto the wire; the completion picks
    // it up instead.
    c->configs.contacts().set(c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
    c->configs.push_now();
    CHECK(c.net->sent_requests.size() == 1);
}
