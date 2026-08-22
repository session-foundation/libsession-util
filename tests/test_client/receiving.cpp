#include "common.hpp"

// ── Receiving ───────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: a received DM creates a conversation and a message", "[client][receive]") {
    TempClient c;
    SenderKeys sender;
    approve(*c, sender.session_id);

    deliver(*c, sender, "hello there", from_epoch_ms(5000), "hash1", "Obi-Wan");

    auto convos = c->conversations(wait);
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id() == ConversationId::dm(sender.session_id));
    CHECK(convos[0].display_name() == "Obi-Wan");
    CHECK(convos[0].last_message() == "hello there");
    CHECK(convos[0].last_activity() == from_epoch_ms(5000));
    CHECK(convos[0].unread() == 1);

    auto msgs = c->conversation(convos[0].id(), wait)->messages(wait);
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].body == "hello there");
    CHECK_FALSE(msgs[0].outgoing);
    CHECK(msgs[0].sender == sender.session_id);
    CHECK(msgs[0].timestamp == from_epoch_ms(5000));
    CHECK(msgs[0].hash == "hash1");
    CHECK_FALSE(msgs[0].send_state.has_value());

    CHECK(c->message(msgs[0].id, wait)->body == "hello there");
    CHECK_FALSE(c->message(msgs[0].id + 1000, wait).has_value());
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

    auto convos = c->conversations(wait);
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id() == ConversationId::dm(peer.session_id));
    CHECK(convos[0].unread() == 0);

    auto msgs = c->conversation(convos[0].id(), wait)->messages(wait);
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

    auto convos = c->conversations(wait);
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id() == ConversationId::dm(me));
    CHECK(convos[0].unread() == 0);
    CHECK(convos[0].dm()->note_to_self);
    CHECK(c->is_note_to_self(convos[0].id()));

    auto msgs = c->conversation(convos[0].id(), wait)->messages(wait);
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

    CHECK(c->conversations(wait).empty());
    CHECK(c->message_requests(wait).empty());
    CHECK_FALSE(c->conversation(convo, wait).has_value());
    CHECK_FALSE(c->dm(convo, wait).has_value());
    CHECK_FALSE(c->message(1, wait).has_value());
    CHECK_FALSE(c->is_note_to_self(convo));

    // Nothing here asks what a *nonexistent* conversation's messages are, or what marking one read
    // does: with the operations on the conversation, there is nothing to call them on, so the
    // nullopt above is the whole answer.
}

TEST_CASE("Client: note to self is reported, not left to the caller", "[client][convos]") {
    TempClient c;
    SenderKeys peer;

    // open_dm hands back a DM rather than an AnyConversation, so the flag is a plain field: asking
    // for the kind is what removes the narrowing.
    auto self = c->open_dm(ConversationId::dm(own_sid(*c)), wait);
    CHECK(self.note_to_self);
    CHECK(c->conversation(self.id, wait)->dm()->note_to_self);
    CHECK(c->is_note_to_self(self.id));

    auto other = c->open_dm(ConversationId::dm(peer.session_id), wait);
    CHECK_FALSE(other.note_to_self);
    CHECK_FALSE(c->conversation(other.id, wait)->dm()->note_to_self);
    CHECK_FALSE(c->is_note_to_self(other.id));

    // A group or community is never note-to-self, whatever its id happens to be.
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    CHECK_FALSE(c->is_note_to_self(ConversationId::group(gid)));
    CHECK_FALSE(c->is_note_to_self(ConversationId::community("http://example.com", "room")));

    // The list form agrees with the single-conversation form.
    for (const auto& convo : c->conversations(wait))
        CHECK(convo.dm()->note_to_self == c->is_note_to_self(convo.id()));
}

TEST_CASE("Client: syncTarget from another sender is ignored", "[client][receive]") {
    TempClient c;
    SenderKeys peer, elsewhere;
    approve(*c, peer.session_id);

    deliver(*c, peer, "not yours to file", from_epoch_ms(5000), "h1", "", elsewhere.session_id);

    auto convos = c->conversations(wait);
    REQUIRE(convos.size() == 1);
    CHECK(convos[0].id() == ConversationId::dm(peer.session_id));

    auto msgs = c->conversation(convos[0].id(), wait)->messages(wait);
    REQUIRE(msgs.size() == 1);
    CHECK_FALSE(msgs[0].outgoing);
}

TEST_CASE("Client: redelivery of the same swarm hash is ignored", "[client][receive]") {
    TempClient c;
    SenderKeys sender;

    deliver(*c, sender, "only once", from_epoch_ms(5000), "dup");
    deliver(*c, sender, "only once", from_epoch_ms(5000), "dup");

    auto convo = ConversationId::dm(sender.session_id);
    CHECK(c->conversation(convo, wait)->messages(wait).size() == 1);
    CHECK(c->conversation(convo, wait)->unread() == 1);

    // A genuinely different message from the same sender still lands.
    deliver(*c, sender, "and again", from_epoch_ms(6000), "notdup");
    CHECK(c->conversation(convo, wait)->messages(wait).size() == 2);
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

    CHECK(c->conversation(convo, wait)->messages(wait).size() == 1);
    CHECK(c->conversation(convo, wait)->unread() == 1);

    // Same millisecond, different message: the case the timestamp alone cannot tell apart, and the
    // whole reason the id exists.  Identical body, so nothing but the id distinguishes them.
    deliver(*c, sender, "said once", from_epoch_ms(5000), "third_hash", "", std::nullopt, nullptr, 8);
    CHECK(c->conversation(convo, wait)->messages(wait).size() == 2);

    // A sender too old to set one has no identity beyond its timestamp, so two arrivals under
    // different swarm hashes cannot be told from one message stored twice.  Both land: a visible
    // duplicate is the failure we chose over silently dropping a real message.
    deliver(*c, sender, "from an old client", from_epoch_ms(6000), "old_a");
    deliver(*c, sender, "from an old client", from_epoch_ms(6000), "old_b");
    CHECK(c->conversation(convo, wait)->messages(wait).size() == 4);
}

TEST_CASE("Client: display name is unset rather than empty until known", "[client][convos]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "hi", from_epoch_ms(1000), "h1");

    // No profile has been seen, so the column holds NULL rather than an empty string.
    auto stored = c->core.database().conn().prepared_get<std::optional<std::string>>(
            "SELECT name FROM accounts WHERE session_id = ?", sender.session_id);
    CHECK_FALSE(stored.has_value());
    CHECK(c->conversation(convo, wait)->display_name().empty());
}

TEST_CASE("Client: a later profile name updates the conversation", "[client][receive]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "one", from_epoch_ms(1000), "h1");
    CHECK(c->conversation(convo, wait)->display_name().empty());
    // With no name known, name_or_id() falls back to the id rather than an empty string.
    CHECK(c->conversation(convo, wait)->name_or_id() == convo.to_string());

    deliver(*c, sender, "two", from_epoch_ms(2000), "h2", "Padmé");
    CHECK(c->conversation(convo, wait)->display_name() == "Padmé");
    CHECK(c->conversation(convo, wait)->name_or_id() == "Padmé");

    // A message with no profile does not erase the name we already have.
    deliver(*c, sender, "three", from_epoch_ms(3000), "h3");
    CHECK(c->conversation(convo, wait)->display_name() == "Padmé");
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

    CHECK(c->conversations(wait).empty());
}

// ── Ordering, unread, drafts ────────────────────────────────────────────────────────────────────

TEST_CASE("Client: conversations are ordered by most recent activity", "[client][convos]") {
    TempClient c;
    SenderKeys alice, bob;
    approve(*c, alice.session_id);
    approve(*c, bob.session_id);

    deliver(*c, alice, "first", from_epoch_ms(1000), "a1");
    deliver(*c, bob, "second", from_epoch_ms(2000), "b1");

    auto convos = c->conversations(wait);
    REQUIRE(convos.size() == 2);
    CHECK(convos[0].id() == ConversationId::dm(bob.session_id));
    CHECK(convos[1].id() == ConversationId::dm(alice.session_id));

    // Alice speaking again moves her back to the top.
    deliver(*c, alice, "third", from_epoch_ms(3000), "a2");
    convos = c->conversations(wait);
    CHECK(convos[0].id() == ConversationId::dm(alice.session_id));
    CHECK(convos[0].last_message() == "third");
}

TEST_CASE("Client: unread counting and the read watermark", "[client][unread]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "one", from_epoch_ms(1000), "h1");
    deliver(*c, sender, "two", from_epoch_ms(2000), "h2");
    deliver(*c, sender, "three", from_epoch_ms(3000), "h3");
    CHECK(c->conversation(convo, wait)->unread() == 3);

    c->conversation(convo, wait)->mark_read(from_epoch_ms(2000), wait);
    CHECK(c->conversation(convo, wait)->unread() == 1);

    // The watermark never moves backwards.
    c->conversation(convo, wait)->mark_read(from_epoch_ms(1000), wait);
    CHECK(c->conversation(convo, wait)->unread() == 1);

    c->conversation(convo, wait)->mark_read(wait);
    CHECK(c->conversation(convo, wait)->unread() == 0);

    // A new arrival after a full read is unread again: "read everything" must not mean "read
    // everything that will ever arrive".
    deliver(*c, sender, "four", from_epoch_ms(4000), "h4");
    CHECK(c->conversation(convo, wait)->unread() == 1);

    // Even one that arrives late, bearing a timestamp older than what we already read to.
    c->conversation(convo, wait)->mark_read(wait);
    deliver(*c, sender, "late", from_epoch_ms(3500), "h5");
    CHECK(c->conversation(convo, wait)->unread() == 0);  // known limitation of a timestamp watermark

    // Marking read on a conversation with nothing to read is a no-op, not an error.
    auto empty = ConversationId::dm(
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b);
    CHECK_NOTHROW(c->open_dm(empty, wait).mark_read(wait));
    CHECK(c->conversation(empty, wait)->unread() == 0);
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
        CHECK(c->conversation(convo, wait)->unread() == 3);
    }

    SECTION("marking read moves unread without touching the total") {
        c->conversation(convo, wait)->mark_read(from_epoch_ms(2000), wait);
        auto [n, unread, actual_n, actual_unread] = counts(alice.session_id);
        CHECK(n == actual_n);
        CHECK(unread == actual_unread);
        CHECK(n == 3);
        CHECK(unread == 1);
    }

    SECTION("count tracks deletes made behind the application's back") {
        auto id = c->conversation(convo, wait)->messages(wait).front().id;
        conn.prepared_exec("DELETE FROM messages WHERE id = ?", id);

        auto [n, unread, actual_n, actual_unread] = counts(alice.session_id);
        CHECK(n == actual_n);
        CHECK(n == 2);

        // unread_count is the application's to maintain, so a raw delete leaves it behind -- that
        // is the deliberate split, not a bug.  Whatever next recomputes it puts it right.
        CHECK(unread == 3);
        CHECK(actual_unread == 2);

        c->conversation(convo, wait)->mark_read(from_epoch_ms(1000), wait);
        auto [n2, unread2, actual_n2, actual_unread2] = counts(alice.session_id);
        CHECK(unread2 == actual_unread2);
    }

    SECTION("count follows a message moved between conversations") {
        auto convo_row = conn.prepared_get<int64_t>(
                "SELECT c.id FROM conversations c JOIN accounts a ON a.id = c.dm"
                " WHERE a.session_id = ?",
                bob.session_id);
        auto id = c->conversation(convo, wait)->messages(wait).front().id;
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

    CHECK_FALSE(c->conversation(convo, wait).has_value());

    auto created = c->open_dm(convo, wait);
    CHECK(created.id == convo);
    CHECK(created.unread == 0);
    CHECK(created.last_message.empty());
    CHECK(c->conversations(wait).size() == 1);

    // Opening one that already exists is not an error and does not duplicate it -- which is why
    // this is `open` and not `create`.
    c->open_dm(convo, wait);
    CHECK(c->conversations(wait).size() == 1);
}

// ── Paging ──────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: message history pages backwards by cursor", "[client][messages]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    for (int i = 1; i <= 10; i++)
        deliver(*c, sender, "msg{}"_format(i), from_epoch_ms(i * 1000), "h{}"_format(i));

    auto page1 = c->conversation(convo, wait)->messages(4, wait);
    REQUIRE(page1.size() == 4);
    CHECK(page1[0].body == "msg10");
    CHECK(page1[3].body == "msg7");

    auto page2 = c->conversation(convo, wait)->messages(4, page1.back().cursor(), wait);
    REQUIRE(page2.size() == 4);
    CHECK(page2[0].body == "msg6");
    CHECK(page2[3].body == "msg3");

    auto page3 = c->conversation(convo, wait)->messages(4, page2.back().cursor(), wait);
    REQUIRE(page3.size() == 2);
    CHECK(page3[0].body == "msg2");
    CHECK(page3[1].body == "msg1");

    CHECK(c->conversation(convo, wait)->messages(4, page3.back().cursor(), wait).empty());
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
        auto page = c->conversation(convo, wait)->messages(1, cursor, wait);
        if (page.empty())
            break;
        seen.push_back(page[0].body);
        cursor = page[0].cursor();
    }

    CHECK(seen == std::vector<std::string>{"same3", "same2", "same1"});
}

TEST_CASE("Client: a message can be shown as it was on the wire", "[client][messages][debug]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c,
            sender,
            "hello there",
            from_epoch_ms(5000),
            "h1",
            "Obi-Wan",
            std::nullopt,
            [](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(12345);
                a->set_contenttype("image/png");
                a->set_key("\x01\x02\x03\x04");
            },
            77);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 1);

    auto dump = c->message_debug(msgs[0].id, wait);
    REQUIRE(dump);
    INFO("dump:\n" << *dump);

    // Named *and* numbered, and nested beneath the field that holds them.  The number is what the
    // wire carries, so it is what a dump is compared against.
    //
    // A message field opens a brace and closes it at its own indent, rather than being followed by
    // an empty-looking `{}` with its contents underneath.
    CHECK(dump->find("dataMessage [1] {\n") != std::string::npos);
    CHECK(dump->find("\n}\n") != std::string::npos);
    CHECK(dump->find("  body [1]: \"hello there\"\n") != std::string::npos);
    CHECK(dump->find("    displayName [1]: \"Obi-Wan\"\n") != std::string::npos);
    CHECK(dump->find("    contentType [2]: \"image/png\"\n") != std::string::npos);
    // Bytes summarised as length plus hex rather than dumped raw.
    CHECK(dump->find("    key [3]: (4 bytes) 01020304\n") != std::string::npos);
    // Scalars at the top level of Content.
    CHECK(dump->find("sigTimestamp [15]: 5000\n") != std::string::npos);
    CHECK(dump->find("msgId [18]: 77\n") != std::string::npos);

    // The name as declared in the .proto, not the lowercased spelling protoc gives the accessor.
    CHECK(dump->find("sourcedevice") == std::string::npos);

    // A message with no stored wire form, and one that does not exist, are both "nothing to show"
    // rather than errors.
    CHECK_FALSE(c->message_debug(msgs[0].id + 1000, wait).has_value());
}

TEST_CASE("Client: deleting a message empties it but keeps its place", "[client][messages][delete]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "one", from_epoch_ms(1000), "h1");
    deliver(*c, sender, "two", from_epoch_ms(2000), "h2");
    deliver(*c, sender, "three", from_epoch_ms(3000), "h3");
    REQUIRE(c->conversation(convo, wait)->unread() == 3);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 3);
    auto middle = msgs[1];  // "two"
    REQUIRE(middle.body == "two");
    REQUIRE(middle.hash == "h2");

    CHECK(c->delete_message(middle.id, wait));

    // Hidden by default...
    auto visible = c->conversation(convo, wait)->messages(wait);
    REQUIRE(visible.size() == 2);
    CHECK(visible[0].body == "three");
    CHECK(visible[1].body == "one");

    // ...and in its original place when asked for, saying who and when but nothing else.
    auto all = c->conversation(convo, wait)->messages(50, std::nullopt, true, wait);
    REQUIRE(all.size() == 3);
    CHECK(all[1].id == middle.id);
    CHECK(all[1].deleted == Deletion::here);
    CHECK(all[1].body.empty());
    CHECK(all[1].timestamp == from_epoch_ms(2000));
    CHECK(all[1].sender == sender.session_id);
    // The hash stays: it is what stops a redelivery bringing the message back.
    CHECK(all[1].hash == "h2");

    // Nothing left to read, so it stops being unread.
    CHECK(c->conversation(convo, wait)->unread() == 2);

    // The stored wire form goes with it, which is where the body actually survived.
    CHECK_FALSE(c->message_debug(middle.id, wait).has_value());

    // A redelivery under the same hash is still recognised as one we have seen.
    deliver(*c, sender, "two", from_epoch_ms(2000), "h2");
    CHECK(c->conversation(convo, wait)->messages(50, std::nullopt, true, wait).size() == 3);

    // Deleting a message that does not exist is false, not an error.
    CHECK_FALSE(c->delete_message(middle.id + 10000, wait));
}

TEST_CASE("Client: the list preview skips a deleted last message", "[client][convos][delete]") {
    TempClient c;
    SenderKeys sender;
    approve(*c, sender.session_id);
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "older", from_epoch_ms(1000), "h1");
    deliver(*c, sender, "newest", from_epoch_ms(2000), "h2");

    auto newest = c->conversation(convo, wait)->messages(wait).front();
    REQUIRE(newest.body == "newest");
    REQUIRE(c->conversation(convo, wait)->last_message() == "newest");

    c->delete_message(newest.id, wait);

    // The list says what was last actually said, rather than going blank.
    CHECK(c->conversation(convo, wait)->last_message() == "older");
}

TEST_CASE("Client: purging removes what a deletion left", "[client][messages][delete]") {
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "one", from_epoch_ms(1000), "h1");
    deliver(*c, sender, "two", from_epoch_ms(2000), "h2");
    deliver(*c, sender, "three", from_epoch_ms(3000), "h3");

    auto msgs = c->conversation(convo, wait)->messages(wait);
    auto live = msgs[0].id;  // "three"
    c->delete_message(msgs[1].id, wait);
    c->delete_message(msgs[2].id, wait);

    SECTION("one at a time, and only what was deleted") {
        // A live message is refused: this is the one call that destroys history outright.
        CHECK_FALSE(c->purge_deleted_message(live, wait));
        CHECK(c->conversation(convo, wait)->messages(wait).size() == 1);

        CHECK(c->purge_deleted_message(msgs[1].id, wait));
        CHECK(c->conversation(convo, wait)->messages(50, std::nullopt, true, wait).size() == 2);

        // Purging the same row twice is false the second time rather than an error.
        CHECK_FALSE(c->purge_deleted_message(msgs[1].id, wait));
    }

    SECTION("all of them at once") {
        CHECK(c->conversation(convo, wait)->purge_deleted(wait) == 2);

        auto left = c->conversation(convo, wait)->messages(50, std::nullopt, true, wait);
        REQUIRE(left.size() == 1);
        CHECK(left[0].body == "three");

        // Nothing left to purge.
        CHECK(c->conversation(convo, wait)->purge_deleted(wait) == 0);

        // And having forgotten it, a redelivery is a new message again -- the cost the header warns
        // about, asserted here so it is a decision rather than a surprise.
        deliver(*c, sender, "two", from_epoch_ms(2000), "h2");
        CHECK(c->conversation(convo, wait)->messages(wait).size() == 2);
    }
}
