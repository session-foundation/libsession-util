#include "common.hpp"

// ── ConversationId ──────────────────────────────────────────────────────────────────────────────

TEST_CASE("ConversationId: round-trips through its string form", "[client][convo_id]") {
    constexpr auto sid = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

    auto dm = ConversationId::dm(sid);
    CHECK(dm.type() == ConversationId::Type::dm);
    CHECK(dm.to_string() == oxenc::to_hex(sid));
    CHECK(ConversationId::parse(dm.to_string()) == dm);
    CHECK(std::ranges::equal(dm.session_id(), sid));

    auto group = ConversationId::group(gid);
    CHECK(group.type() == ConversationId::Type::group);
    CHECK(ConversationId::parse(group.to_string()) == group);
    CHECK(std::ranges::equal(group.group_id(), gid));

    // Same 32-byte body, different prefix: distinct conversations.
    CHECK(dm != group);

    auto com = ConversationId::community("http://example.com", "room");
    CHECK(com.type() == ConversationId::Type::community);
    CHECK(com.to_string() == "community:http://example.com/room");
    CHECK(ConversationId::parse(com.to_string()) == com);
    auto [url, room] = com.community();
    CHECK(url == "http://example.com");
    CHECK(room == "room");
}

TEST_CASE("ConversationId: normalises community URLs and rooms", "[client][convo_id]") {
    auto a = ConversationId::community("http://Example.COM/", "Room");
    auto b = ConversationId::community("http://example.com", "room");
    CHECK(a == b);

    CHECK_THROWS_AS(ConversationId::community("", "room"), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::community("http://x.com", ""), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::community("http://x.com", "a/b"), std::invalid_argument);
}

TEST_CASE("ConversationId: rejects bad input and mistyped access", "[client][convo_id]") {
    constexpr auto sid = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    constexpr auto bad_prefix =
            "07fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

    CHECK_THROWS_AS(ConversationId::dm(bad_prefix), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::group(bad_prefix), std::invalid_argument);

    CHECK_THROWS_AS(ConversationId::parse(""), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse("nonsense"), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse(oxenc::to_hex(bad_prefix)), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse("05zz"), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse("community:noroom"), std::invalid_argument);

    // Extracting the wrong kind is a programming error, not a parse error.
    auto dm = ConversationId::dm(sid);
    CHECK_THROWS_AS(dm.group_id(), std::logic_error);
    CHECK_THROWS_AS(dm.community(), std::logic_error);
}

// ── Schema ──────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: applies its migrations under the client owner", "[client][schema]") {
    TempClient c;

    // Both schemas are created from their full_schema.sql, each marking its own owner.
    CHECK(TestHelper::migration_applied(c->core, "client:@created"));
    CHECK(TestHelper::migration_applied(c->core, "@created"));

    // Not Connection::table_exists(): its query in session-sqlite is missing a closing paren and
    // throws "incomplete input" for every caller.
    auto has_table = [&](std::string_view name) {
        return c->core.database()
                .conn()
                .prepared_maybe_get<std::string>(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", name)
                .has_value();
    };
    CHECK(has_table("accounts"));
    CHECK(has_table("conversations"));
    CHECK(has_table("messages"));
    CHECK(has_table("message_raw_content"));
    // Client's tables live in Core's database, not a second file.
    CHECK(has_table("globals"));
}
