#include <SessionProtos.pb.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <future>
#include <oxen/quic/loop.hpp>
#include <session/attachments.hpp>
#include <session/client/sync_client.hpp>
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
    std::unique_ptr<SyncClient> client;

    template <core::CoreOption... Opts>
    explicit TempClient(Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", random::unique_id("test_client", 7))},
            client{std::make_unique<SyncClient>(path, std::forward<Opts>(opts)...)} {}

    template <core::CoreOption... Opts>
    explicit TempClient(callbacks cbs, Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", random::unique_id("test_client", 7))},
            client{std::make_unique<SyncClient>(
                    path, std::move(cbs), std::forward<Opts>(opts)...)} {}

    template <core::CoreOption... Opts>
    void reopen(Opts&&... opts) {
        client.reset();
        client = std::make_unique<SyncClient>(path, std::forward<Opts>(opts)...);
    }

    ~TempClient() {
        client.reset();
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    SyncClient* operator->() { return client.get(); }
    SyncClient& operator*() { return *client; }
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
        std::optional<b33> sync_target = std::nullopt,
        const std::function<void(SessionProtos::DataMessage&)>& decorate = nullptr,
        std::optional<int64_t> msgid = std::nullopt) {
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    if (msgid)
        content.set_msgid(*msgid);
    auto* data = content.mutable_datamessage();
    data->set_body(std::string{body});
    if (!display_name.empty())
        data->mutable_profile()->set_displayname(std::string{display_name});
    if (sync_target)
        data->set_synctarget(oxenc::to_hex(sync_target->begin(), sync_target->end()));
    if (decorate)
        decorate(*data);

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
        "Client: the same message under a different swarm hash is deduped", "[client][receive]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    // One message stored twice -- a sender who retried a store that had actually succeeded, say --
    // lands under two swarm hashes.  The swarm hash cannot recognise that; the msgid can, being the
    // one identifier every copy of a message carries.
    deliver(*c, sender, "said once", from_epoch_ms(5000), "first_hash", "", std::nullopt, nullptr, 7);
    deliver(*c, sender, "said once", from_epoch_ms(5000), "second_hash", "", std::nullopt, nullptr, 7);

    CHECK(c->messages(convo).size() == 1);
    CHECK(c->conversation(convo)->unread == 1);

    // Same millisecond, different message: the case the timestamp alone cannot tell apart, and the
    // whole reason the id exists.  Identical body, so nothing but the id distinguishes them.
    deliver(*c, sender, "said once", from_epoch_ms(5000), "third_hash", "", std::nullopt, nullptr, 8);
    CHECK(c->messages(convo).size() == 2);

    // A sender too old to set one has no identity beyond its timestamp, so two arrivals under
    // different swarm hashes cannot be told from one message stored twice.  Both land: a visible
    // duplicate is the failure we chose over silently dropping a real message.
    deliver(*c, sender, "from an old client", from_epoch_ms(6000), "old_a");
    deliver(*c, sender, "from an old client", from_epoch_ms(6000), "old_b");
    CHECK(c->messages(convo).size() == 4);
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
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    auto convo = ConversationId::dm(peer);

    // No PFS keys published for either of us, so these fall back to v1 sends: the recipient's copy
    // and the copy for our own swarm, which needs our own keys answered too.
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(convo, "general kenobi");

    // A store to the recipient's swarm and one to our own, both into the default namespace, with
    // something in them.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 2);
    for (const auto* r : sent) {
        auto body = store_body(*r);
        CHECK(body["namespace"] == static_cast<int16_t>(config::Namespace::Default));
        CHECK_FALSE(body["data"].get<std::string>().empty());
    }
    CHECK(accept_stores(*net) == 2);

    auto msg = c->message(id);
    REQUIRE(msg.has_value());
    CHECK(msg->body == "general kenobi");
    CHECK(msg->outgoing);
    CHECK(msg->sender == own_sid(*c));
    CHECK(msg->send_state == SendState::sent);

    // Of the two hashes the two stores were assigned, the one kept is our own swarm's: it is the
    // copy we can still act on, and the one a redelivery would arrive under.
    CHECK(msg->hash == store_hash_for(oxenc::to_hex(own_sid(*c))));

    // The conversation was created by the send and shows the outgoing message as its preview.
    auto convos = c->conversations();
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].last_message == "general kenobi");
    // Our own message is never unread.
    CHECK(convos[0].unread == 0);
}

TEST_CASE("Client: a failed send is recorded as failed", "[client][send]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(ConversationId::dm(peer), "into the void");

    // The swarm refusing the store is what a failure is, rather than us declining to attempt one.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 2);
    for (auto* r : sent)
        r->callback(false, false, 500, {}, "nope");

    CHECK(c->message(id)->send_state == SendState::failed);
}

TEST_CASE("Client: sending to a non-DM conversation is rejected", "[client][send]") {
    TempClient c;
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    CHECK_THROWS_AS(c->send_message(ConversationId::group(gid), "hi"), std::invalid_argument);
}

TEST_CASE("Client: an in-flight send becomes interrupted after a restart", "[client][send]") {
    // The store is captured and never answered, which leaves the message mid-flight -- exactly the
    // state a crash would leave behind.
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

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
    SyncClient* self = nullptr;

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
    Recorder r;
    TempClient c{r.handlers()};
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

    // Only the peer's keys are answered, so only the recipient's copy is dispatched: the copy for
    // our own swarm stays waiting on our keys.  That is what makes the single update below the one
    // for `send_state` rather than for the sync copy's.
    TestHelper::seed_pfs_nak(c->core, peer);

    auto id = c->send_message(ConversationId::dm(peer), "hello");
    sync(*c);
    r.order.clear();
    r.msg_updated.clear();

    REQUIRE(accept_stores(*net) == 1);

    CHECK(r.order == std::vector<std::string>{"message_updated"});
    REQUIRE(r.msg_updated.size() == 1);
    CHECK(r.msg_updated[0].second.id == id);
    CHECK(r.msg_updated[0].second.send_state == SendState::sent);

    // The only store that landed was the recipient's, and that hash belongs to their swarm: it is
    // not something we could ever look up, so it is not recorded as ours.
    CHECK_FALSE(r.msg_updated[0].second.hash.has_value());
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

TEST_CASE("Client: the two copies of a send report separately", "[client][send]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(ConversationId::dm(peer), "two ways");

    // Which swarm a store is bound for is the pubkey it names, so the two copies can be answered
    // independently and in either order.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 2);

    auto my_hex = oxenc::to_hex(own_sid(*c));
    auto is_self = [&](const MockNetwork::SentRequest* r) {
        return store_body(*r)["pubkey"].get<std::string>() == my_hex;
    };
    auto to_peer = std::ranges::find_if_not(sent, is_self);
    auto to_self = std::ranges::find_if(sent, is_self);
    REQUIRE(to_peer != sent.end());
    REQUIRE(to_self != sent.end());

    // The recipient's copy lands; our own swarm has not answered yet.
    (*to_peer)->callback(true, false, 200, {}, "{}");
    CHECK(c->message(id)->send_state == SendState::sent);
    CHECK(c->message(id)->sync_send_state == SendState::sending);

    // The sync copy fails, which says nothing about whether the message arrived.
    (*to_self)->callback(false, false, 500, {}, "nope");
    CHECK(c->message(id)->send_state == SendState::sent);
    CHECK(c->message(id)->sync_send_state == SendState::failed);
}

TEST_CASE("Client: an arriving message records the files it names", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;

    // `id` is deprecated in favour of `url` but is still `required` by the protobuf, so every
    // pointer carries one whether or not anything reads it.
    uint64_t next_id = 111;
    auto add = [&next_id](
                       SessionProtos::DataMessage& data,
                       std::string_view url,
                       size_t key_len,
                       auto&& fill) {
        auto* a = data.add_attachments();
        a->set_id(next_id++);
        a->set_url(std::string{url});
        a->set_key(std::string(key_len, 'k'));
        fill(a);
    };

    // Three attachments and no body at all: the case that used to be discarded outright, since a
    // message was only history if it had text.
    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                // Stream-encrypted, as anything we send is: 32-byte key, `d` in the url.
                add(data, "http://fs.example/file/111#d", 32, [](auto* a) {
                    a->set_size(4321);
                    a->set_contenttype("image/png");
                    a->set_filename("kitten.png");
                    a->set_width(640);
                    a->set_height(480);
                });
                // Legacy, which is what every current client actually sends: 64-byte key and a
                // digest, and no fragment on the url.
                add(data, "http://fs.example/file/222", 64, [](auto* a) {
                    a->set_digest(std::string(32, 'd'));
                    a->set_size(99);
                    a->set_contenttype("application/pdf");
                    a->set_filename("invoice.pdf");
                    a->set_caption("last month");
                    a->set_flags(1);
                });
                // A pointer with no url at all: unfetchable, but still one of three files the
                // sender said were here, so it is not silently dropped.
                add(data, "", 32, [](auto* a) { a->clear_url(); });
            });
    sync(*c);

    auto msgs = c->messages(ConversationId::dm(peer.session_id));
    REQUIRE(msgs.size() == 1);
    const auto& m = msgs[0];
    CHECK(m.body.empty());
    CHECK_FALSE(m.outgoing);
    REQUIRE(m.attachments.size() == 3);

    CHECK(m.attachments[0].index == 0);
    CHECK(m.attachments[0].content_type == "image/png");
    CHECK(m.attachments[0].filename == "kitten.png");
    CHECK(m.attachments[0].size == 4321);
    CHECK(m.attachments[0].width == 640);
    CHECK(m.attachments[0].height == 480);
    CHECK_FALSE(m.attachments[0].voice_message);
    // Always true on an incoming attachment: the file server is where it came from.
    CHECK(m.attachments[0].uploaded);

    CHECK(m.attachments[1].caption == "last month");
    CHECK(m.attachments[1].voice_message);
    CHECK(m.attachments[1].uploaded);

    // The unusable one still occupies its position, so the indices keep meaning what the sender
    // meant by them.
    CHECK(m.attachments[2].index == 2);
    CHECK_FALSE(m.attachments[2].uploaded);
}

TEST_CASE("Client: a message reports the attachments it carries", "[client][send][attachments]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_attach", 7);
    std::filesystem::create_directories(dir);
    auto write = [&](std::string_view name) {
        auto p = dir / name;
        std::ofstream{p, std::ios::binary} << "not really a file";
        return p;
    };
    // Names chosen for the ways extension parsing goes wrong: several dots, and a dotfile whose
    // leading dot must not be read as an extension.
    auto photo = write("holiday.snap.PNG");
    auto doc = write("notes.pdf");
    auto mystery = write(".hidden");

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto id = c->send_message(
            ConversationId::dm(me),
            "",
            {OutgoingAttachment{.path = photo, .caption = "on the beach"},
             OutgoingAttachment{.path = doc, .content_type = "application/x-my-own", .width = 4},
             OutgoingAttachment{.path = mystery, .voice_message = true}});

    auto msg = c->message(id);
    REQUIRE(msg.has_value());

    // An attachments-only message: nothing to show but the files, which is exactly the case that
    // used to be indistinguishable from an empty message.
    CHECK(msg->body.empty());
    REQUIRE(msg->attachments.size() == 3);

    // Ordered by position, and that position is what an upload report names.
    CHECK(msg->attachments[0].index == 0);
    CHECK(msg->attachments[1].index == 1);
    CHECK(msg->attachments[2].index == 2);

    // Inferred from the last extension, case-insensitively, when the caller named none...
    CHECK(msg->attachments[0].content_type == "image/png");
    CHECK(msg->attachments[0].filename == "holiday.snap.PNG");
    CHECK(msg->attachments[0].caption == "on the beach");
    CHECK_FALSE(msg->attachments[0].voice_message);

    // ...and never overriding one the caller did name.
    CHECK(msg->attachments[1].content_type == "application/x-my-own");
    CHECK(msg->attachments[1].width == 4);
    CHECK_FALSE(msg->attachments[1].height.has_value());

    // A dotfile has no extension -- "hidden" is the name, not the type -- so it falls back rather
    // than being given a type invented out of the filename.
    CHECK(msg->attachments[2].content_type == "application/octet-stream");
    CHECK(msg->attachments[2].filename == ".hidden");
    CHECK(msg->attachments[2].voice_message);

    // Each file reached the server, and the size recorded is the file's own -- read at upload time,
    // not the padded ciphertext's length that the server reports back.
    sync(*c);
    msg = c->message(id);
    REQUIRE(msg.has_value());
    for (const auto& a : msg->attachments) {
        CHECK(a.uploaded);
        CHECK(a.size == static_cast<int64_t>(std::string_view{"not really a file"}.size()));
    }

    // The same list reaches a paged read, not only the single-message one.
    auto page = c->messages(ConversationId::dm(me));
    REQUIRE(page.size() == 1);
    CHECK(page[0].attachments.size() == 3);
    CHECK(page[0].attachments[0].content_type == "image/png");

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: saving an attachment fetches, decrypts and reports it", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    // So the notification below goes out as a v1 send rather than queueing behind a key fetch.
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    // A real attachment: encrypted exactly as a sender would, so what the download serves is what
    // the decryptor has to cope with, chunk boundaries and padding included.
    std::vector<std::byte> plaintext(9000);
    for (size_t i = 0; i < plaintext.size(); i++)
        plaintext[i] = static_cast<std::byte>(i * 31 % 256);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);

    deliver(*c, peer, "", from_epoch_ms(1000), "h1", "", std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/1#d");
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_filename("payload.bin");
            },
            42);
    sync(*c);

    auto msgs = c->messages(ConversationId::dm(peer.session_id));
    REQUIRE(msgs.size() == 1);
    auto msg_id = msgs[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_save", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";

    std::vector<std::tuple<size_t, int64_t, int64_t, std::optional<int>>> reports;
    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg_id, 0, dest,
            [&](size_t i, int64_t d, int64_t tot, std::optional<int> r) {
                reports.emplace_back(i, d, tot, r);
            },
            [&](std::optional<std::string> err) { done.set_value(std::move(err)); });

    // Nothing is fetched until asked, and asking produces exactly one download.
    sync(*c);
    REQUIRE(net->downloads.size() == 1);
    CHECK(net->downloads[0].download_url == "http://fs.example/file/1#d");

    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    // The file is the file, byte for byte, with the padding that hid its length gone.
    REQUIRE(std::filesystem::exists(dest));
    CHECK(std::filesystem::file_size(dest) == plaintext.size());
    {
        std::ifstream in{dest, std::ios::binary};
        std::vector<std::byte> got(plaintext.size());
        in.read(reinterpret_cast<char*>(got.data()), got.size());
        CHECK(!!(got == plaintext));
    }
    // ...and nothing is left behind that could be mistaken for it.
    CHECK_FALSE(std::filesystem::exists(dest.string() + ".part"));

    // Progress reported as a send does: an opening 0/0, then exactly one terminal result.
    REQUIRE(reports.size() >= 2);
    CHECK(std::get<3>(reports.front()) == std::nullopt);
    CHECK(std::get<1>(reports.front()) == 0);
    CHECK(std::get<3>(reports.back()) == 0);

    // And the sender is told, since nothing said otherwise.
    sync(*c);
    CHECK(stores(*net).size() == 1);

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a save can be kept to ourselves, and a bad one writes nothing",
          "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    std::vector<std::byte> plaintext(500, std::byte{7});
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);

    auto add = [&](SessionProtos::DataMessage& data) {
        auto* a = data.add_attachments();
        a->set_id(1);
        a->set_url("http://fs.example/file/2#d");
        a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
        a->set_size(plaintext.size());
    };
    deliver(*c, peer, "", from_epoch_ms(2000), "h2", "", std::nullopt, add, 43);
    sync(*c);
    auto msg_id = c->messages(ConversationId::dm(peer.session_id))[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_save", 7);
    std::filesystem::create_directories(dir);

    // The promise is shared rather than captured by reference: save_attachment's callback outlives
    // this scope, and a reference to a local here would dangle by the time the download is served.
    auto save = [&](const std::filesystem::path& dest, bool notify) {
        auto done = std::make_shared<std::promise<std::optional<std::string>>>();
        auto waiter = done->get_future();
        c->Client::save_attachment(
                msg_id, 0, dest, nullptr,
                [done](std::optional<std::string> err) { done->set_value(std::move(err)); },
                notify);
        sync(*c);
        return waiter;
    };

    // Asked not to tell them, we do not -- the file still lands.
    {
        auto quiet = dir / "quiet.bin";
        auto waiter = save(quiet, false);
        REQUIRE(serve_downloads(*net, ciphertext) == 1);
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        CHECK_FALSE(waiter.get().has_value());
        CHECK(std::filesystem::exists(quiet));
        sync(*c);
        CHECK(stores(*net).empty());
    }

    // A file that fails to authenticate is a failure, not a corrupt file on disk: the ciphertext is
    // written to a temporary name and only renamed once it has been decrypted whole.
    {
        auto bad = dir / "bad.bin";
        auto corrupt = ciphertext;
        corrupt[corrupt.size() / 2] ^= std::byte{0xff};
        auto waiter = save(bad, true);
        REQUIRE(serve_downloads(*net, corrupt) == 1);
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        CHECK(waiter.get().has_value());
        CHECK_FALSE(std::filesystem::exists(bad));
        CHECK_FALSE(std::filesystem::exists(bad.string() + ".part"));
        // Nothing was saved, so nobody is told one was.
        sync(*c);
        CHECK(stores(*net).empty());
    }

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: an attachment we sent can be saved back", "[client][attachments]") {
    // The whole path in one go: a file is encrypted and uploaded by sending it, and then fetched,
    // decrypted and written by saving it.  Nothing here knows what the other half did except
    // through what was stored -- the url, its `d` fragment, the key and the size -- so a
    // disagreement between the two shows up as bytes that do not match.
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_roundtrip", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "original.bin";

    // Larger than one encryption chunk, so the streaming path is what runs rather than a single
    // block that would hide a chunk-boundary bug.
    std::vector<std::byte> contents(70 * 1024);
    for (size_t i = 0; i < contents.size(); i++)
        contents[i] = static_cast<std::byte>((i * 7 + i / 251) % 256);
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }

    auto id = c->send_message(
            ConversationId::dm(me), "here it is", {OutgoingAttachment{.path = source}});
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto msg = c->message(id);
    REQUIRE(msg.has_value());
    REQUIRE(msg->attachments.size() == 1);
    CHECK(msg->attachments[0].uploaded);
    // What the pointer advertises is the file's own length, not the padded ciphertext's.
    CHECK(msg->attachments[0].size == static_cast<int64_t>(contents.size()));

    auto dest = dir / "saved.bin";
    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg->id, 0, dest, nullptr,
            [&done](std::optional<std::string> err) { done.set_value(std::move(err)); });
    sync(*c);

    // Served from what the upload left behind, found by the id in the url the send generated.
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    REQUIRE(std::filesystem::exists(dest));
    REQUIRE(std::filesystem::file_size(dest) == contents.size());
    std::ifstream in{dest, std::ios::binary};
    std::vector<std::byte> got(contents.size());
    in.read(reinterpret_cast<char*>(got.data()), got.size());
    CHECK(!!(got == contents));

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a legacy attachment is saved", "[client][attachments][legacy]") {
    // Every Session client still sends attachments encrypted the old way, so this is the path most
    // received attachments actually take.  The blob is fixed rather than generated: libsession has
    // no legacy encryptor -- deliberately, since we never send these -- so producing one here would
    // mean writing the very thing we chose not to have, and testing it against itself.  It came
    // from an independent implementation written against session-android's
    // AttachmentCipherInputStream.
    //
    // 56 bytes of text, zero-padded to 128, then AES-256-CBC with an HMAC and a digest over it.
    constexpr auto LEGACY_KEY =
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"_hex_b;
    constexpr auto LEGACY_BLOB =
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf22bf91f23b4781cc75fcba799b05fa6d"
            "f93931dc76588ba849c27514c2e21560130db54a94a65303ea60adc0166ff90c"
            "e07d033f2107b1ed38ddc006b1c71c3bb796d591ebbb2f9877027962dcb6ab13"
            "b10b97cb736fddd7e2edd7b0908cd2b0ba84be5def8e67316556917af6faf793"
            "56695fbd811fad5de80b9f70b15eb6987e18eab948150964e6309b24c3367b59"
            "7a75cd3520a42061ce5ef6a0d647b1eb310fc355214c1f3eab964a9e7df62c65"_hex_b;
    constexpr auto LEGACY_DIGEST =
            "f75f0a8286252a371f131c711ddc5b04cc69092c8b8397b0460f1bc6946907c4"_hex_b;
    constexpr auto LEGACY_TEXT = "a legacy attachment, from a client that has not moved on"sv;

    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    // No `d` fragment on the url, a 64-byte key and a digest: that combination is what tells the
    // save which of the two schemes to use, and nothing else does.
    deliver(*c, peer, "", from_epoch_ms(3000), "legacy_hash", "", std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(9);
                a->set_url("http://fs.example/file/legacy1");
                a->set_key(std::string{
                        reinterpret_cast<const char*>(LEGACY_KEY.data()), LEGACY_KEY.size()});
                a->set_digest(std::string{
                        reinterpret_cast<const char*>(LEGACY_DIGEST.data()),
                        LEGACY_DIGEST.size()});
                a->set_size(LEGACY_TEXT.size());
                a->set_filename("legacy.txt");
            },
            44);
    sync(*c);

    auto msgs = c->messages(ConversationId::dm(peer.session_id));
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].attachments.size() == 1);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_legacy", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "legacy.txt";

    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msgs[0].id, 0, dest, nullptr,
            [&done](std::optional<std::string> err) { done.set_value(std::move(err)); });
    sync(*c);

    REQUIRE(serve_downloads(*net, LEGACY_BLOB) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    // Trimmed to the length the pointer claimed, with the zero padding that hid it gone.
    REQUIRE(std::filesystem::exists(dest));
    REQUIRE(std::filesystem::file_size(dest) == LEGACY_TEXT.size());
    std::ifstream in{dest, std::ios::binary};
    std::string got{std::istreambuf_iterator<char>{in}, {}};
    CHECK(got == LEGACY_TEXT);

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: sending to ourselves stores once", "[client][send]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    // Mirrors opening the conversation first, as a UI does, before sending into it.
    auto convo = c->create_conversation(ConversationId::dm(me));
    CHECK(convo.id == ConversationId::dm(me));

    auto id = c->send_message(ConversationId::dm(me), "note to self");
    CHECK(c->message(id)->body == "note to self");
    CHECK(c->conversation(ConversationId::dm(me))->last_message == "note to self");

    // One store reaching the swarm, not two: our own swarm is the recipient's, so the sync copy
    // would be the same store twice.
    CHECK(accept_stores(*net) == 1);

    // One swarm, so one send: there is no separate sync copy to have a state for.
    CHECK(c->message(id)->send_state.has_value());
    CHECK_FALSE(c->message(id)->sync_send_state.has_value());

    // That single store went to our own swarm, so its hash is one worth keeping.
    CHECK(c->message(id)->hash == store_hash_for(oxenc::to_hex(me)));
    CHECK(c->messages(ConversationId::dm(me)).size() == 1);

    // ...and when our own swarm hands it straight back on the next poll, which is what note to self
    // does, it must recognise its own message rather than storing a second copy.  What makes that
    // work is the msgid: the copy coming back carries the one we generated when sending, which is
    // exactly what a hash of the two copies could not do.
    auto ts = c->message(id)->timestamp;
    auto msgid = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<int64_t>(
                "SELECT msgid FROM messages WHERE id = ?", id);
    });
    SessionProtos::Content sent;
    sent.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(ts)));
    sent.set_msgid(msgid);
    sent.mutable_datamessage()->set_body("note to self");
    sent.mutable_datamessage()->set_timestamp(static_cast<uint64_t>(epoch_ms(ts)));
    sent.mutable_datamessage()->set_synctarget(oxenc::to_hex(me));
    auto plaintext = sent.SerializeAsString();
    auto encoded = encode_dm_v1(
            std::as_bytes(std::span{plaintext}), self_keys(*c).ed_sk, ts, me, std::nullopt);
    core::SwarmMessage sm{encoded, "swarmhash", ts, from_epoch_ms(1'000'000'000'000)};
    c->core.loop().call_get([&] {
        c->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
        return 0;
    });

    CHECK(c->messages(ConversationId::dm(me)).size() == 1);
}

// ── Core interoperability ───────────────────────────────────────────────────────────────────────

TEST_CASE("Client: an asynchronous call reports that it succeeded", "[client][callbacks]") {
    TempClient c;
    SenderKeys sender;
    deliver(*c, sender, "hello", from_epoch_ms(1000), "h1");
    sync(*c);

    // Qualified, because SyncClient masks the asynchronous forms deliberately: choosing the easy
    // class means choosing it for everything.
    std::optional<std::string> reported_error = "not called";
    std::vector<Conversation> got;
    c->Client::conversations([&](std::optional<std::string> error, std::vector<Conversation> cs) {
        reported_error = std::move(error);
        got = std::move(cs);
    });
    sync(*c);

    // Called exactly once, and saying it worked rather than leaving the caller to assume so.
    CHECK_FALSE(reported_error.has_value());
    REQUIRE(got.size() == 1);
    CHECK(got[0].id == ConversationId::dm(sender.session_id));
}

TEST_CASE("Client: handlers arrive through the dispatcher", "[client][callbacks]") {
    // Stands in for an application's loop: jobs are collected rather than run, so a handler that
    // ran on Core's loop instead of being handed over is visible as one that never happened.
    std::vector<std::function<void()>> queued;
    std::thread::id dispatched_on;

    Recorder r;
    TempClient c{r.handlers()};
    c->set_dispatcher([&](std::function<void()> job) {
        dispatched_on = std::this_thread::get_id();
        queued.push_back(std::move(job));
    });

    SenderKeys sender;
    deliver(*c, sender, "hello", from_epoch_ms(1000), "h1");
    sync(*c);

    // Handed over rather than called: nothing has reached the application yet.
    CHECK(r.msg_added.empty());
    CHECK(r.added.empty());
    REQUIRE(!queued.empty());

    // Handed over from Core's loop, which is the thread an application must not be touched from.
    CHECK(dispatched_on != std::this_thread::get_id());

    for (auto& job : queued)
        job();
    queued.clear();

    REQUIRE(r.msg_added.size() == 1);
    CHECK(r.msg_added[0].second.body == "hello");
    CHECK(r.added.size() == 1);

    // Unsetting puts things back the way they are without one, which is what an application does
    // when its loop stops accepting work.
    c->set_dispatcher(nullptr);
    deliver(*c, sender, "direct", from_epoch_ms(2000), "h2");
    sync(*c);

    CHECK(queued.empty());
    REQUIRE(r.msg_added.size() == 2);
    CHECK(r.msg_added[1].second.body == "direct");
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

TEST_CASE(
        "Client: a message with attachments needs readable files", "[client][send][attachments]") {
    TempClient c{};
    auto me = own_sid(*c);

    CHECK_THROWS_AS(
            c->send_message(
                    ConversationId::dm(me),
                    "here you go",
                    {OutgoingAttachment{.path = "/nonexistent/nope.png"}}),
            std::invalid_argument);

    // Rejected before anything was stored, rather than leaving a message that can never be sent.
    CHECK(c->messages(ConversationId::dm(me), 10, std::nullopt).empty());
}

TEST_CASE(
        "Client: attachments that cannot be uploaded fail the message",
        "[client][send][attachments]") {
    auto file = std::filesystem::temp_directory_path() / "libsession_attachment_test.bin";
    {
        std::ofstream out{file, std::ios::binary};
        out << "some file contents";
    }

    Recorder r;
    TempClient c{r.handlers()};
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    std::vector<std::tuple<size_t, int64_t, int64_t, std::optional<int>>> reports;

    // No network is attached, so the upload cannot even be attempted.  The message must still end
    // up somewhere final: the failure is what a caller waits on, and a message left in `uploading`
    // would wait forever.
    auto id = c->send_message(
            ConversationId::dm(me),
            "here you go",
            {OutgoingAttachment{.path = file}},
            [&](size_t idx, int64_t sent, int64_t total, std::optional<int> result) {
                reports.emplace_back(idx, sent, total, result);
            });
    sync(*c);

    auto msg = c->message(id);
    REQUIRE(msg);
    CHECK(msg->body == "here you go");
    CHECK(msg->send_state == SendState::failed);

    REQUIRE(reports.size() == 1);
    auto [idx, sent, total, result] = reports.front();
    CHECK(idx == 0);
    REQUIRE(result.has_value());
    CHECK(*result != 0);

    std::filesystem::remove(file);
}

TEST_CASE(
        "Client: throttling never squelches what a caller must hear",
        "[client][send][attachments]") {
    auto file = std::filesystem::temp_directory_path() / "libsession_throttle_test.bin";
    {
        std::ofstream out{file, std::ios::binary};
        out << "some file contents";
    }

    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    // Long enough that anything passing through the throttle would be dropped: what arrives is
    // exactly what is exempt from it.
    c->set_high_freq_dispatch_interval(1h);

    std::vector<std::optional<int>> results;
    auto id = c->send_message(
            ConversationId::dm(me),
            "here you go",
            {OutgoingAttachment{.path = file}},
            [&](size_t, int64_t, int64_t, std::optional<int> result) {
                results.push_back(result);
            });
    sync(*c);

    // With no network the upload cannot start, so the one report is its failure -- which is the
    // point: an outcome is never a thing the throttle may drop.
    CHECK(c->message(id)->send_state == SendState::failed);
    REQUIRE(results.size() == 1);
    REQUIRE(results.front().has_value());
    CHECK(*results.front() != 0);

    std::filesystem::remove(file);
}

TEST_CASE("Client: retrying a send that cannot work", "[client][send][attachments]") {
    auto file = std::filesystem::temp_directory_path() / "libsession_retry_test.bin";
    {
        std::ofstream out{file, std::ios::binary};
        out << "some file contents";
    }

    Recorder r;
    TempClient c{r.handlers()};
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto id = c->send_message(
            ConversationId::dm(me), "here you go", {OutgoingAttachment{.path = file}});
    sync(*c);
    REQUIRE(c->message(id)->send_state == SendState::failed);

    // Retrying is allowed while the failure is one that might not recur, and reports itself as
    // started rather than as succeeded -- the outcome arrives through the message's state.
    std::vector<std::optional<int>> results;
    CHECK(c->retry_send(id, [&](size_t, int64_t, int64_t, std::optional<int> result) {
        results.push_back(result);
    }));
    sync(*c);
    REQUIRE(results.size() == 1);
    CHECK(c->message(id)->send_state == SendState::failed);

    // With the file gone the retry can only ever fail the same way, so the message becomes
    // terminal rather than staying something an application would offer to try again.
    std::filesystem::remove(file);

    results.clear();
    CHECK(c->retry_send(id, [&](size_t, int64_t, int64_t, std::optional<int> result) {
        results.push_back(result);
    }));
    sync(*c);
    REQUIRE(results.size() == 1);
    CHECK(results.front() == ATTACHMENT_FILE_MISSING);
    CHECK(c->message(id)->send_state == SendState::unsendable);

    // ... and being terminal, it is refused rather than attempted again.
    CHECK_FALSE(c->retry_send(id));
}
