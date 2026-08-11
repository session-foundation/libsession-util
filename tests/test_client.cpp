#include <SessionProtos.pb.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <future>
#include <oxen/quic/loop.hpp>
#include <session/client.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/random.hpp>
#include <session/session_protocol.hpp>
#include <thread>

#include "schema_fingerprint.hpp"
#include "test_helper.hpp"

using namespace session;
using namespace session::client;
using namespace std::literals;
using namespace oxenc::literals;

namespace {

struct SenderKeys {
    b32 ed_pk;
    b64 ed_sk;
    b33 session_id;

    SenderKeys() {
        ed25519::keypair(ed_pk, ed_sk);
        ed25519::pk_to_session_id(session_id, ed_pk);
    }
};

/// RAII Client over a unique temporary database, mirroring TempCore.  Unlike TempCore this can
/// close and reopen the same file, which is how the restart behaviour is exercised.
struct TempClient {
    std::filesystem::path path;
    std::unique_ptr<Client> client;

    template <core::CoreOption... Opts>
    explicit TempClient(Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", random::unique_id("test_client", 7))},
            client{std::make_unique<Client>(path, std::forward<Opts>(opts)...)} {}

    template <core::CoreOption... Opts>
    explicit TempClient(callbacks cbs, Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", random::unique_id("test_client", 7))},
            client{std::make_unique<Client>(path, std::move(cbs), std::forward<Opts>(opts)...)} {}

    template <core::CoreOption... Opts>
    void reopen(Opts&&... opts) {
        client.reset();
        client = std::make_unique<Client>(path, std::forward<Opts>(opts)...);
    }

    ~TempClient() {
        client.reset();
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    Client* operator->() { return client.get(); }
    Client& operator*() { return *client; }
};

b33 own_sid(Client& c) {
    b33 out;
    std::ranges::copy(c.core.globals.session_id(), out.begin());
    return out;
}

/// `c`'s own sending keys, for building the copy of an outgoing message that Session stores on the
/// sender's own swarm.
SenderKeys self_keys(Client& c) {
    SenderKeys k;
    auto seed = c.core.globals.account_seed();
    std::ranges::copy(seed.ed25519_secret(), k.ed_sk.begin());
    std::ranges::copy(seed.ed25519_secret().last<32>(), k.ed_pk.begin());
    std::ranges::copy(c.core.globals.session_id(), k.session_id.begin());
    return k;
}

/// Builds, encrypts and delivers a v1 DM into `to` as if it had arrived from the swarm.
void deliver(
        Client& to,
        const SenderKeys& from,
        std::string_view body,
        sys_ms ts,
        std::string hash,
        std::string_view display_name = "",
        std::optional<b33> sync_target = std::nullopt) {
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    auto* data = content.mutable_datamessage();
    data->set_body(std::string{body});
    if (!display_name.empty())
        data->mutable_profile()->set_displayname(std::string{display_name});
    if (sync_target)
        data->set_synctarget(oxenc::to_hex(sync_target->begin(), sync_target->end()));

    auto plaintext = content.SerializeAsString();
    auto encoded = encode_dm_v1(
            std::as_bytes(std::span{plaintext}), from.ed_sk, ts, own_sid(to), std::nullopt);

    core::SwarmMessage sm{encoded, std::move(hash), ts, from_epoch_ms(1'000'000'000'000)};

    // Core delivers arriving messages from its event loop, so do the same here rather than writing
    // the database from the test thread: the connection pool is single-threaded by design.
    to.core.loop().call_get([&] {
        to.core.receive_messages({&sm, 1}, config::Namespace::Default, true);
        return 0;
    });
}

/// Records every callback so a test can assert on what a subscriber was told, and in what order.
struct Recorder {
    std::vector<std::string> order;
    std::vector<Conversation> added, updated;
    std::vector<ConversationId> removed;
    std::vector<std::vector<Conversation>> replaced;
    std::vector<std::pair<ConversationId, Message>> msg_added, msg_updated;

    callbacks handlers() {
        return {
                .conversation_added =
                        [this](const Conversation& c) {
                            order.push_back("added");
                            added.push_back(c);
                        },
                .conversation_updated =
                        [this](const Conversation& c) {
                            order.push_back("updated");
                            updated.push_back(c);
                        },
                .conversation_removed =
                        [this](const ConversationId& id) {
                            order.push_back("removed");
                            removed.push_back(id);
                        },
                .conversation_list_replaced =
                        [this](std::vector<Conversation> l) {
                            order.push_back("replaced");
                            replaced.push_back(std::move(l));
                        },
                .message_added =
                        [this](const ConversationId& id, const Message& m) {
                            order.push_back("message");
                            msg_added.emplace_back(id, m);
                        },
                .message_updated =
                        [this](const ConversationId& id, const Message& m) {
                            order.push_back("message_updated");
                            msg_updated.emplace_back(id, m);
                        },
        };
    }
};

/// Waits for anything Client deferred with call_soon -- the coalesced conversation_updated -- to
/// have run.  Jobs run in the order they were queued, so a job queued afterwards that we wait on
/// cannot finish first.
void sync(Client& c) {
    c.core.loop().call_get([] { return 0; });
}

}  // namespace

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

// ── Receiving ───────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: a received DM creates a conversation and a message", "[client][receive]") {
    TempClient c;
    SenderKeys sender;

    deliver(*c, sender, "hello there", from_epoch_ms(5000), "hash1", "Obi-Wan");

    auto convos = c->conversations();
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id == ConversationId::dm(sender.session_id));
    CHECK(convos[0].display_name == "Obi-Wan");
    CHECK(convos[0].last_message == "hello there");
    CHECK(convos[0].last_activity == from_epoch_ms(5000));
    CHECK(convos[0].unread == 1);

    auto msgs = c->messages(convos[0].id);
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].body == "hello there");
    CHECK_FALSE(msgs[0].outgoing);
    CHECK(msgs[0].sender == sender.session_id);
    CHECK(msgs[0].timestamp == from_epoch_ms(5000));
    CHECK(msgs[0].hash == "hash1");
    CHECK_FALSE(msgs[0].send_state.has_value());

    CHECK(c->message(msgs[0].id)->body == "hello there");
    CHECK_FALSE(c->message(msgs[0].id + 1000).has_value());
}

TEST_CASE(
        "Client: our own sent message lands in the recipient's conversation", "[client][receive]") {
    TempClient c;
    SenderKeys peer;

    // A one-to-one message is stored on both swarms, so this is what our own send looks like coming
    // back to us: sender is us, and the conversation it belongs to is only in syncTarget.
    deliver(*c,
            self_keys(*c),
            "sent from my phone",
            from_epoch_ms(5000),
            "sync1",
            "",
            peer.session_id);

    auto convos = c->conversations();
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id == ConversationId::dm(peer.session_id));
    CHECK(convos[0].unread == 0);

    auto msgs = c->messages(convos[0].id);
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].body == "sent from my phone");
    CHECK(msgs[0].outgoing);
    CHECK(msgs[0].sender == own_sid(*c));
    CHECK(msgs[0].send_state == SendState::sent);
}

TEST_CASE("Client: a message to ourselves is a conversation with ourselves", "[client][receive]") {
    TempClient c;
    auto me = own_sid(*c);

    // Note to Self is not a distinct kind of conversation, in Session or here: it is the DM whose
    // peer is our own account, which is what both spellings below resolve to.
    deliver(*c, self_keys(*c), "targeted", from_epoch_ms(5000), "self1", "", me);
    deliver(*c, self_keys(*c), "untargeted", from_epoch_ms(6000), "self2");

    auto convos = c->conversations();
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id == ConversationId::dm(me));
    CHECK(convos[0].unread == 0);
    CHECK(convos[0].note_to_self);
    CHECK(c->is_note_to_self(convos[0].id));

    auto msgs = c->messages(convos[0].id);
    REQUIRE(msgs.size() == 2);
    CHECK(msgs[0].outgoing);
    CHECK(msgs[1].outgoing);
}

TEST_CASE("Client: reads answer emptily before an account exists", "[client][convos]") {
    // An application opening the database under defer_account renders before onboarding has run, so
    // every read has to survive having no identity: "no account" and "no conversations" are the
    // same answer.  Only writes may insist on one.
    TempClient c{core::defer_account{}};
    REQUIRE_FALSE(c->core.globals.have_account());

    constexpr auto sid = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    auto convo = ConversationId::dm(sid);

    CHECK(c->conversations().empty());
    CHECK_FALSE(c->conversation(convo).has_value());
    CHECK(c->messages(convo).empty());
    CHECK_FALSE(c->message(1).has_value());
    CHECK_FALSE(c->is_note_to_self(convo));
    CHECK_NOTHROW(c->mark_read(convo));
}

TEST_CASE("Client: note to self is reported, not left to the caller", "[client][convos]") {
    TempClient c;
    SenderKeys peer;

    auto self = c->create_conversation(ConversationId::dm(own_sid(*c)));
    CHECK(self.note_to_self);
    CHECK(c->conversation(self.id)->note_to_self);
    CHECK(c->is_note_to_self(self.id));

    auto other = c->create_conversation(ConversationId::dm(peer.session_id));
    CHECK_FALSE(other.note_to_self);
    CHECK_FALSE(c->conversation(other.id)->note_to_self);
    CHECK_FALSE(c->is_note_to_self(other.id));

    // A group or community is never note-to-self, whatever its id happens to be.
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    CHECK_FALSE(c->is_note_to_self(ConversationId::group(gid)));
    CHECK_FALSE(c->is_note_to_self(ConversationId::community("http://example.com", "room")));

    // The list form agrees with the single-conversation form.
    for (const auto& convo : c->conversations())
        CHECK(convo.note_to_self == c->is_note_to_self(convo.id));
}

TEST_CASE("Client: syncTarget from another sender is ignored", "[client][receive]") {
    TempClient c;
    SenderKeys peer, elsewhere;

    deliver(*c, peer, "not yours to file", from_epoch_ms(5000), "h1", "", elsewhere.session_id);

    auto convos = c->conversations();
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id == ConversationId::dm(peer.session_id));

    auto msgs = c->messages(convos[0].id);
    REQUIRE(msgs.size() == 1);
    CHECK_FALSE(msgs[0].outgoing);
}

TEST_CASE("Client: redelivery of the same swarm hash is ignored", "[client][receive]") {
    TempClient c;
    SenderKeys sender;

    deliver(*c, sender, "only once", from_epoch_ms(5000), "dup");
    deliver(*c, sender, "only once", from_epoch_ms(5000), "dup");

    auto convo = ConversationId::dm(sender.session_id);
    CHECK(c->messages(convo).size() == 1);
    CHECK(c->conversation(convo)->unread == 1);

    // A genuinely different message from the same sender still lands.
    deliver(*c, sender, "and again", from_epoch_ms(6000), "notdup");
    CHECK(c->messages(convo).size() == 2);
}

TEST_CASE(
        "Client: identical content under a different swarm hash is deduped", "[client][receive]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    // The same message re-encrypted for a different recipient -- our own other device, say --
    // lands in a different swarm with a different hash.  The swarm hash cannot recognise that;
    // the content hash can, because it is computed above the encryption layer.
    deliver(*c, sender, "said once", from_epoch_ms(5000), "hash_from_their_swarm");
    deliver(*c, sender, "said once", from_epoch_ms(5000), "hash_from_our_swarm");

    CHECK(c->messages(convo).size() == 1);
    CHECK(c->conversation(convo)->unread == 1);

    // Same body a millisecond later is a different message, not a redelivery.
    deliver(*c, sender, "said once", from_epoch_ms(5001), "third_hash");
    CHECK(c->messages(convo).size() == 2);
}

TEST_CASE("Client: display name is unset rather than empty until known", "[client][convos]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "hi", from_epoch_ms(1000), "h1");

    // No profile has been seen, so the column holds NULL rather than an empty string.
    auto stored = c->core.database().conn().prepared_get<std::optional<std::string>>(
            "SELECT display_name FROM accounts WHERE session_id = ?", sender.session_id);
    CHECK_FALSE(stored.has_value());
    CHECK(c->conversation(convo)->display_name.empty());
}

TEST_CASE("Client: a later profile name updates the conversation", "[client][receive]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "one", from_epoch_ms(1000), "h1");
    CHECK(c->conversation(convo)->display_name.empty());
    // With no name known, name_or_id() falls back to the id rather than an empty string.
    CHECK(c->conversation(convo)->name_or_id() == convo.to_string());

    deliver(*c, sender, "two", from_epoch_ms(2000), "h2", "Padmé");
    CHECK(c->conversation(convo)->display_name == "Padmé");
    CHECK(c->conversation(convo)->name_or_id() == "Padmé");

    // A message with no profile does not erase the name we already have.
    deliver(*c, sender, "three", from_epoch_ms(3000), "h3");
    CHECK(c->conversation(convo)->display_name == "Padmé");
}

TEST_CASE("Client: non-conversation content does not create a conversation", "[client][receive]") {
    TempClient c;
    SenderKeys sender;

    auto deliver_content = [&](const SessionProtos::Content& content, std::string hash) {
        auto plaintext = content.SerializeAsString();
        auto encoded = encode_dm_v1(
                std::as_bytes(std::span{plaintext}),
                sender.ed_sk,
                from_epoch_ms(1000),
                own_sid(*c),
                std::nullopt);
        core::SwarmMessage sm{encoded, std::move(hash), from_epoch_ms(1000), from_epoch_ms(99999)};
        c->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
    };

    // A typing indicator: valid Content, but nothing that belongs in message history.
    SessionProtos::Content typing;
    typing.set_sigtimestamp(1000);
    typing.mutable_typingmessage()->set_timestamp(1000);
    typing.mutable_typingmessage()->set_action(SessionProtos::TypingMessage::STARTED);
    deliver_content(typing, "typing");

    // A DataMessage carrying only a profile update, with no body.
    SessionProtos::Content bodyless;
    bodyless.set_sigtimestamp(1000);
    bodyless.mutable_datamessage()->mutable_profile()->set_displayname("Ghost");
    deliver_content(bodyless, "bodyless");

    CHECK(c->conversations().empty());
}

// ── Ordering, unread, drafts ────────────────────────────────────────────────────────────────────

TEST_CASE("Client: conversations are ordered by most recent activity", "[client][convos]") {
    TempClient c;
    SenderKeys alice, bob;

    deliver(*c, alice, "first", from_epoch_ms(1000), "a1");
    deliver(*c, bob, "second", from_epoch_ms(2000), "b1");

    auto convos = c->conversations();
    REQUIRE(convos.size() == 2);
    CHECK(convos[0].id == ConversationId::dm(bob.session_id));
    CHECK(convos[1].id == ConversationId::dm(alice.session_id));

    // Alice speaking again moves her back to the top.
    deliver(*c, alice, "third", from_epoch_ms(3000), "a2");
    convos = c->conversations();
    CHECK(convos[0].id == ConversationId::dm(alice.session_id));
    CHECK(convos[0].last_message == "third");
}

TEST_CASE("Client: unread counting and the read watermark", "[client][unread]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "one", from_epoch_ms(1000), "h1");
    deliver(*c, sender, "two", from_epoch_ms(2000), "h2");
    deliver(*c, sender, "three", from_epoch_ms(3000), "h3");
    CHECK(c->conversation(convo)->unread == 3);

    c->mark_read(convo, from_epoch_ms(2000));
    CHECK(c->conversation(convo)->unread == 1);

    // The watermark never moves backwards.
    c->mark_read(convo, from_epoch_ms(1000));
    CHECK(c->conversation(convo)->unread == 1);

    c->mark_read(convo);
    CHECK(c->conversation(convo)->unread == 0);

    // A new arrival after a full read is unread again: "read everything" must not mean "read
    // everything that will ever arrive".
    deliver(*c, sender, "four", from_epoch_ms(4000), "h4");
    CHECK(c->conversation(convo)->unread == 1);

    // Even one that arrives late, bearing a timestamp older than what we already read to.
    c->mark_read(convo);
    deliver(*c, sender, "late", from_epoch_ms(3500), "h5");
    CHECK(c->conversation(convo)->unread == 0);  // known limitation of a timestamp watermark

    // Marking read on a conversation with nothing to read is a no-op, not an error.
    auto empty = ConversationId::dm(
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b);
    c->create_conversation(empty);
    CHECK_NOTHROW(c->mark_read(empty));
    CHECK(c->conversation(empty)->unread == 0);
}

TEST_CASE("Client: cached counts stay in step with the messages table", "[client][convos]") {
    TempClient c;
    SenderKeys alice, bob;
    auto convo = ConversationId::dm(alice.session_id);
    auto other = ConversationId::dm(bob.session_id);

    auto conn = c->core.database().conn();

    // The cached counters alongside what counting the rows actually yields.  Nothing in the public
    // API can tell a counter from a subquery, which is exactly why drift needs asserting directly.
    auto counts = [&](std::span<const std::byte, 33> sid) {
        return conn.prepared_get<int64_t, int64_t, int64_t, int64_t>(
                R"(
            SELECT c.count, c.unread_count,
                   (SELECT COUNT(*) FROM messages WHERE conversation = c.id),
                   (SELECT COUNT(*) FROM messages
                     WHERE conversation = c.id AND outgoing = 0 AND timestamp > c.last_read)
            FROM conversations c
            JOIN accounts a ON a.id = c.dm
            WHERE a.session_id = ?
        )",
                sid);
    };

    deliver(*c, alice, "one", from_epoch_ms(1000), "h1");
    deliver(*c, alice, "two", from_epoch_ms(2000), "h2");
    deliver(*c, alice, "three", from_epoch_ms(3000), "h3");
    deliver(*c, bob, "elsewhere", from_epoch_ms(1500), "h4");

    SECTION("arrivals update both") {
        auto [n, unread, actual_n, actual_unread] = counts(alice.session_id);
        CHECK(n == actual_n);
        CHECK(unread == actual_unread);
        CHECK(n == 3);
        CHECK(unread == 3);
        CHECK(c->conversation(convo)->unread == 3);
    }

    SECTION("marking read moves unread without touching the total") {
        c->mark_read(convo, from_epoch_ms(2000));
        auto [n, unread, actual_n, actual_unread] = counts(alice.session_id);
        CHECK(n == actual_n);
        CHECK(unread == actual_unread);
        CHECK(n == 3);
        CHECK(unread == 1);
    }

    SECTION("count tracks deletes made behind the application's back") {
        auto id = c->messages(convo).front().id;
        conn.prepared_exec("DELETE FROM messages WHERE id = ?", id);

        auto [n, unread, actual_n, actual_unread] = counts(alice.session_id);
        CHECK(n == actual_n);
        CHECK(n == 2);

        // unread_count is the application's to maintain, so a raw delete leaves it behind -- that
        // is the deliberate split, not a bug.  Whatever next recomputes it puts it right.
        CHECK(unread == 3);
        CHECK(actual_unread == 2);

        c->mark_read(convo, from_epoch_ms(1000));
        auto [n2, unread2, actual_n2, actual_unread2] = counts(alice.session_id);
        CHECK(unread2 == actual_unread2);
    }

    SECTION("count follows a message moved between conversations") {
        auto convo_row = conn.prepared_get<int64_t>(
                "SELECT c.id FROM conversations c JOIN accounts a ON a.id = c.dm"
                " WHERE a.session_id = ?",
                bob.session_id);
        auto id = c->messages(convo).front().id;
        conn.prepared_exec("UPDATE messages SET conversation = ? WHERE id = ?", convo_row, id);

        auto [n, unread, actual_n, actual_unread] = counts(alice.session_id);
        CHECK(n == actual_n);
        CHECK(n == 2);

        auto [n2, unread2, actual_n2, actual_unread2] = counts(bob.session_id);
        CHECK(n2 == actual_n2);
        CHECK(n2 == 2);
    }
}

TEST_CASE("Client: explicit conversation creation", "[client][convos]") {
    TempClient c;
    constexpr auto sid = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    auto convo = ConversationId::dm(sid);

    CHECK_FALSE(c->conversation(convo).has_value());

    auto created = c->create_conversation(convo);
    CHECK(created.id == convo);
    CHECK(created.unread == 0);
    CHECK(created.last_message.empty());
    CHECK(c->conversations().size() == 1);

    // Creating an existing conversation is not an error and does not duplicate it.
    c->create_conversation(convo);
    CHECK(c->conversations().size() == 1);
}

// ── Paging ──────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: message history pages backwards by cursor", "[client][messages]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    for (int i = 1; i <= 10; i++)
        deliver(*c, sender, "msg{}"_format(i), from_epoch_ms(i * 1000), "h{}"_format(i));

    auto page1 = c->messages(convo, 4);
    REQUIRE(page1.size() == 4);
    CHECK(page1[0].body == "msg10");
    CHECK(page1[3].body == "msg7");

    auto page2 = c->messages(convo, 4, page1.back().cursor());
    REQUIRE(page2.size() == 4);
    CHECK(page2[0].body == "msg6");
    CHECK(page2[3].body == "msg3");

    auto page3 = c->messages(convo, 4, page2.back().cursor());
    REQUIRE(page3.size() == 2);
    CHECK(page3[0].body == "msg2");
    CHECK(page3[1].body == "msg1");

    CHECK(c->messages(convo, 4, page3.back().cursor()).empty());
}

TEST_CASE("Client: paging is stable across equal timestamps", "[client][messages]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    // Three messages sharing one timestamp: only the id tiebreak keeps paging from repeating or
    // skipping rows.
    for (int i = 1; i <= 3; i++)
        deliver(*c, sender, "same{}"_format(i), from_epoch_ms(1000), "same_h{}"_format(i));

    std::vector<std::string> seen;
    std::optional<MessageCursor> cursor;
    while (true) {
        auto page = c->messages(convo, 1, cursor);
        if (page.empty())
            break;
        seen.push_back(page[0].body);
        cursor = page[0].cursor();
    }

    CHECK(seen == std::vector<std::string>{"same3", "same2", "same1"});
}

// ── Sending ─────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: send_message stores, dispatches and reaches sent", "[client][send]") {
    std::vector<std::byte> payload;
    core::callbacks cbs;
    cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                            config::Namespace ns,
                            std::vector<std::byte> p,
                            std::chrono::milliseconds,
                            std::function<void(bool)> on_stored) {
        CHECK(ns == config::Namespace::Default);
        payload = std::move(p);
        on_stored(true);
    };

    TempClient c{cbs};
    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    auto convo = ConversationId::dm(peer);

    // No PFS keys published for the peer, so this falls back to a v1 send without needing network.
    TestHelper::seed_pfs_nak(c->core, peer);

    auto id = c->send_message(convo, "general kenobi");
    CHECK_FALSE(payload.empty());

    auto msg = c->message(id);
    REQUIRE(msg.has_value());
    CHECK(msg->body == "general kenobi");
    CHECK(msg->outgoing);
    CHECK(msg->sender == own_sid(*c));
    CHECK(msg->send_state == SendState::sent);

    // The conversation was created by the send and shows the outgoing message as its preview.
    auto convos = c->conversations();
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].last_message == "general kenobi");
    // Our own message is never unread.
    CHECK(convos[0].unread == 0);
}

TEST_CASE("Client: a failed send is recorded as failed", "[client][send]") {
    core::callbacks cbs;
    cbs.send_to_swarm = [](std::span<const std::byte, 33>,
                           config::Namespace,
                           std::vector<std::byte>,
                           std::chrono::milliseconds,
                           std::function<void(bool)> on_stored) { on_stored(false); };

    TempClient c{cbs};
    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);

    auto id = c->send_message(ConversationId::dm(peer), "into the void");
    CHECK(c->message(id)->send_state == SendState::failed);
}

TEST_CASE("Client: sending to a non-DM conversation is rejected", "[client][send]") {
    TempClient c;
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    CHECK_THROWS_AS(c->send_message(ConversationId::group(gid), "hi"), std::invalid_argument);
}

TEST_CASE("Client: an in-flight send becomes interrupted after a restart", "[client][send]") {
    // Never completing the store leaves the message mid-flight, which is exactly the state a
    // crash would leave behind.
    core::callbacks cbs;
    cbs.send_to_swarm = [](std::span<const std::byte, 33>,
                           config::Namespace,
                           std::vector<std::byte>,
                           std::chrono::milliseconds,
                           std::function<void(bool)>) {};

    TempClient c{cbs};
    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);

    auto id = c->send_message(ConversationId::dm(peer), "did this land?");
    CHECK(c->message(id)->send_state == SendState::sending);

    c.reopen();

    // Not "failed": we genuinely do not know whether the swarm stored it.
    CHECK(c->message(id)->send_state == SendState::interrupted);
    CHECK(c->message(id)->body == "did this land?");
}

// ── Signals ─────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: the application is told what changed", "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};

    deliver(*c, sender, "ping", from_epoch_ms(1000), "h1");
    sync(*c);

    auto convo = ConversationId::dm(sender.session_id);
    CHECK(r.order == std::vector<std::string>{"added", "message", "updated"});

    // Every handler is given the state itself, not something to go and look up.
    REQUIRE(r.added.size() == 1);
    CHECK(r.added[0].id == convo);
    REQUIRE(r.msg_added.size() == 1);
    CHECK(r.msg_added[0].first == convo);
    CHECK(r.msg_added[0].second.body == "ping");
    REQUIRE(r.updated.size() == 1);
    CHECK(r.updated[0].last_message == "ping");
    CHECK(r.updated[0].unread == 1);

    // A second message on an existing conversation does not re-announce the conversation.
    r.order.clear();
    deliver(*c, sender, "pong", from_epoch_ms(2000), "h2");
    sync(*c);
    CHECK(r.order == std::vector<std::string>{"message", "updated"});
}

TEST_CASE(
        "Client: a batch reports each message but settles the conversation once",
        "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};

    // One delivery carrying several messages, as a swarm poll produces.
    std::vector<std::string> encoded;
    for (int i = 0; i < 5; i++) {
        SessionProtos::Content content;
        auto ts = from_epoch_ms(1000 + i);
        content.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(ts)));
        content.mutable_datamessage()->set_body("m{}"_format(i));
        encoded.push_back(content.SerializeAsString());
    }
    std::vector<std::vector<std::byte>> wire;
    for (int i = 0; i < 5; i++)
        wire.push_back(encode_dm_v1(
                std::as_bytes(std::span{encoded[i]}),
                sender.ed_sk,
                from_epoch_ms(1000 + i),
                own_sid(*c),
                std::nullopt));
    std::vector<core::SwarmMessage> batch;
    for (int i = 0; i < 5; i++)
        batch.push_back(
                core::SwarmMessage{
                        wire[i],
                        "b{}"_format(i),
                        from_epoch_ms(1000 + i),
                        from_epoch_ms(1'000'000'000'000)});

    c->core.loop().call_get([&] {
        c->core.receive_messages(batch, config::Namespace::Default, true);
        return 0;
    });
    sync(*c);

    // Five messages, but the conversation settles once rather than being rebuilt five times.
    CHECK(std::ranges::count(r.order, "message") == 5);
    CHECK(std::ranges::count(r.order, "updated") == 1);
    REQUIRE(r.updated.size() == 1);
    CHECK(r.updated[0].unread == 5);
    CHECK(r.updated[0].last_message == "m4");
}

TEST_CASE("Client: state is committed before the handler fires", "[client][signals]") {
    SenderKeys sender;
    std::optional<std::string> body_seen_from_handler;
    Client* self = nullptr;

    TempClient c{callbacks{.message_added = [&](const ConversationId&, const Message& m) {
        body_seen_from_handler = self->message(m.id)->body;
    }}};
    self = &*c;

    deliver(*c, sender, "readable already", from_epoch_ms(1000), "h1");
    CHECK(body_seen_from_handler == "readable already");
}

TEST_CASE("Client: a throwing handler is contained", "[client][signals]") {
    SenderKeys sender;
    TempClient c{callbacks{.message_added = [](const ConversationId&, const Message&) {
        throw std::runtime_error{"deliberate"};
    }}};

    // The exception is caught and logged rather than escaping into Core's event loop, and the
    // message is stored regardless: a broken listener must not cost us data.
    CHECK_NOTHROW(deliver(*c, sender, "still fine", from_epoch_ms(1000), "h1"));
    CHECK(c->messages(ConversationId::dm(sender.session_id)).size() == 1);
}

TEST_CASE("Client: send status changes are reported as message_updated", "[client][signals]") {
    std::function<void(bool)> finish_store;
    core::callbacks cbs;
    cbs.send_to_swarm = [&](std::span<const std::byte, 33>,
                            config::Namespace,
                            std::vector<std::byte>,
                            std::chrono::milliseconds,
                            std::function<void(bool)> on_stored) {
        finish_store = std::move(on_stored);
    };

    Recorder r;
    TempClient c{r.handlers(), cbs};
    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);

    auto id = c->send_message(ConversationId::dm(peer), "hello");
    sync(*c);
    r.order.clear();
    r.msg_updated.clear();

    REQUIRE(finish_store);
    finish_store(true);

    CHECK(r.order == std::vector<std::string>{"message_updated"});
    REQUIRE(r.msg_updated.size() == 1);
    CHECK(r.msg_updated[0].second.id == id);
    CHECK(r.msg_updated[0].second.send_state == SendState::sent);
}

TEST_CASE("Client: priority orders the list and hides", "[client][convos]") {
    TempClient c;
    SenderKeys a, b, d;

    // Three conversations, most recent first: d, b, a.
    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    deliver(*c, d, "third", from_epoch_ms(3000), "h3");
    sync(*c);

    auto ida = ConversationId::dm(a.session_id);
    auto idb = ConversationId::dm(b.session_id);
    auto idd = ConversationId::dm(d.session_id);

    auto ids = [&] {
        std::vector<ConversationId> out;
        for (const auto& convo : c->conversations())
            out.push_back(convo.id);
        return out;
    };
    CHECK(ids() == std::vector{idd, idb, ida});

    // Higher priority sorts first, regardless of recency.
    c->set_priority(ida, 1);
    CHECK(ids() == std::vector{ida, idd, idb});
    CHECK(c->conversation(ida)->priority == 1);

    // A bigger number outranks a smaller one.
    c->set_priority(idb, 5);
    CHECK(ids() == std::vector{idb, ida, idd});

    // Equal priorities form a block that sorts among itself by recency: b is pinned alongside a but
    // is the more recently active of the two, so it leads.  d stays below both, unpinned.
    c->set_priority(ida, 5);
    CHECK(ids() == std::vector{idb, ida, idd});

    // Negative is hidden: gone from the list entirely rather than sorted last.
    c->set_priority(idb, -1);
    CHECK(ids() == std::vector{ida, idd});

    // Still reachable by name, though: hidden is a statement about the list, and this is the only
    // way back to one.
    REQUIRE(c->conversation(idb).has_value());
    CHECK(c->conversation(idb)->priority == -1);

    // ...and unhiding brings it back where its priority says.
    c->set_priority(idb, 0);
    CHECK(ids() == std::vector{ida, idd, idb});
}

TEST_CASE("Client: a priority change replaces the whole list", "[client][signals]") {
    SenderKeys a, b;
    Recorder r;
    TempClient c{r.handlers()};

    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    sync(*c);
    r.order.clear();

    c->set_priority(ConversationId::dm(a.session_id), 3);

    // Reported as a replacement, not as an update to the one conversation whose priority changed:
    // what moved is the list.
    CHECK(r.order == std::vector<std::string>{"replaced"});
    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 2);
    CHECK(r.replaced[0][0].id == ConversationId::dm(a.session_id));
    CHECK(r.replaced[0][0].priority == 3);

    // Hiding removes it from the replacement list, which is how a subscriber learns it is gone.
    r.order.clear();
    r.replaced.clear();
    c->set_priority(ConversationId::dm(a.session_id), -1);
    CHECK(r.order == std::vector<std::string>{"replaced"});
    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 1);
    CHECK(r.replaced[0][0].id == ConversationId::dm(b.session_id));

    // Setting the same value again changes nothing, so it says nothing.
    r.order.clear();
    c->set_priority(ConversationId::dm(a.session_id), -1);
    CHECK(r.order.empty());
}

// ── Core interoperability ───────────────────────────────────────────────────────────────────────

TEST_CASE("Client: the application's own Core callbacks still fire", "[client][callbacks]") {
    std::vector<core::ReceivedMessage> app_received;
    std::vector<core::MessageSendStatus> app_statuses;

    core::callbacks cbs;
    cbs.message_received = [&](core::ReceivedMessage&& m) { app_received.push_back(std::move(m)); };
    cbs.message_send_status = [&](int64_t, core::MessageSendStatus s) {
        app_statuses.push_back(s);
    };
    cbs.send_to_swarm = [](std::span<const std::byte, 33>,
                           config::Namespace,
                           std::vector<std::byte>,
                           std::chrono::milliseconds,
                           std::function<void(bool)> on_stored) { on_stored(true); };

    TempClient c{cbs};
    SenderKeys sender;

    deliver(*c, sender, "seen by both", from_epoch_ms(1000), "h1");

    // Client handled it *and* passed it on intact.
    REQUIRE(app_received.size() == 1);
    CHECK(app_received[0].hash == "h1");
    CHECK(app_received[0].sender_session_id == sender.session_id);
    CHECK(c->messages(ConversationId::dm(sender.session_id)).size() == 1);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    c->send_message(ConversationId::dm(peer), "outbound");

    REQUIRE(app_statuses.size() >= 1);
    CHECK(app_statuses.back() == core::MessageSendStatus::success);
}

TEST_CASE("Client: Core is usable directly through the Client", "[client][callbacks]") {
    TempClient c;

    // The account state is Core's, and reachable without Client wrapping any of it.
    CHECK(c->core.globals.session_id()[0] == std::byte{0x05});
    CHECK_FALSE(c->core.devices.device_id().empty());

    // Globals set through Core survive a Client restart, i.e. it really is one database.
    c->core.globals.set("client_test_key", "value"sv);
    c.reopen();
    CHECK(c->core.globals.get_text("client_test_key") == "value");
}

// ── Threading ───────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: reads are safe while messages arrive on another thread", "[client][threads]") {
    // An application reads conversations and history from its UI thread while Core's poll thread
    // writes arriving messages.  Those are two connections from the shared pool against a WAL
    // database, so readers should not block behind the writer nor see SQLITE_BUSY -- but that is a
    // claim about configuration, and nothing exercised it until this.
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    constexpr int N = 300;
    std::atomic<bool> writing{true};
    std::atomic<int> reads{0};
    std::exception_ptr writer_err, reader_err;

    std::thread writer{[&] {
        try {
            for (int i = 1; i <= N; i++)
                deliver(*c, sender, "msg{}"_format(i), from_epoch_ms(i * 1000), "h{}"_format(i));
        } catch (...) {
            writer_err = std::current_exception();
        }
        writing = false;
    }};

    std::thread reader{[&] {
        try {
            while (writing) {
                for (const auto& convo_row : c->conversations())
                    c->messages(convo_row.id, 50);
                reads++;
            }
        } catch (...) {
            reader_err = std::current_exception();
        }
    }};

    writer.join();
    reader.join();

    // Rethrown on this thread: Catch2's assertion macros are not safe to use from the others.
    if (writer_err)
        std::rethrow_exception(writer_err);
    if (reader_err)
        std::rethrow_exception(reader_err);

    CHECK(reads > 0);  // the reader really did run alongside, rather than after
    CHECK(c->messages(convo, N + 10).size() == N);
}
