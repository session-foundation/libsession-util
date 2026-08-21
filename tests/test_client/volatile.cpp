#include "config_helpers.hpp"

// Recent, because ConvoInfoVolatile refuses to store a last-read older than PRUNE_LOW (30 days)
// and would silently keep nothing at all from the 1970 timestamps the other tests here use.
sys_ms recently(std::chrono::milliseconds ago) {
    return clock_now_ms() - ago;
}

TEST_CASE("Client: reading a conversation publishes the watermark", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    auto newest = recently(2s);
    deliver(*c, them, "one", recently(3s), "h1");
    deliver(*c, them, "two", newest, "h2");
    REQUIRE(c->conversation(id, wait)->unread() == 2);

    c->conversation(id, wait)->mark_read(wait);

    CHECK(c->conversation(id, wait)->unread() == 0);
    auto entry = c->core.configs.convo_info_volatile().get_1to1(hex);
    REQUIRE(entry);
    CHECK(entry->last_read == newest.time_since_epoch().count());
}

TEST_CASE("Client: a watermark from another device applies", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    auto older = recently(30s);
    deliver(*c, them, "one", older, "h1");
    deliver(*c, them, "two", recently(10s), "h2");
    REQUIRE(c->conversation(id, wait)->unread() == 2);

    // Read up to the first message on another device.
    auto read = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(hex);
        e.last_read = older.time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, read);

    CHECK(c->conversation(id, wait)->unread() == 1);
}

TEST_CASE("Client: a stale watermark cannot unread what we have read", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    auto older = recently(30s);
    auto newest = recently(10s);
    deliver(*c, them, "one", older, "h1");
    deliver(*c, them, "two", newest, "h2");
    c->conversation(id, wait)->mark_read(wait);
    REQUIRE(c->conversation(id, wait)->unread() == 0);

    // The config permits a value to be written backwards on purpose, and a same-seqno conflict
    // resolves by a tie-break that knows nothing about which value is newer -- so an older one
    // really can arrive, and applying it would make read messages unread again.
    auto stale = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(hex);
        e.last_read = older.time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, stale);

    CHECK(c->conversation(id, wait)->unread() == 0);

    // ...and we do not publish the stale value back out, either.
    TestHelper::sync_convo_volatile(*c.client, id);
    auto entry = c->core.configs.convo_info_volatile().get_1to1(hex);
    REQUIRE(entry);
    CHECK(entry->last_read == newest.time_since_epoch().count());
}

TEST_CASE("Client: marking unread syncs, and reading clears it", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    deliver(*c, them, "one", recently(5s), "h1");
    c->conversation(id, wait)->mark_read(wait);
    REQUIRE(c->conversation(id, wait)->unread() == 0);

    c->conversation(id, wait)->set_marked_unread(true, wait);

    // Survives having read everything, which is the whole point of it.
    CHECK(c->conversation(id, wait)->marked_unread());
    CHECK(c->conversation(id, wait)->unread() == 0);
    CHECK(c->core.configs.convo_info_volatile().get_1to1(hex)->unread);

    c->conversation(id, wait)->mark_read(wait);
    CHECK_FALSE(c->conversation(id, wait)->marked_unread());
    CHECK_FALSE(c->core.configs.convo_info_volatile().get_1to1(hex)->unread);
}

TEST_CASE("Client: read state for a conversation we do not have is ignored", "[client][volatile]") {
    TempClient c;
    auto them = "05" + std::string(64, '8');
    auto id = dm_from_hex(them);

    // An entry outlives the conversation it describes: this config is pruned by age, not by
    // anything noticing a deletion.  Creating a conversation from one would resurrect what another
    // device deleted.
    auto orphan = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(them);
        e.last_read = clock_now_ms().time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, orphan);

    CHECK_FALSE(c->conversation(id, wait));
    CHECK(c->conversations(wait).empty());
}

