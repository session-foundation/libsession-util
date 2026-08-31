#include "common.hpp"

namespace {

/// Adds a quote naming `author` at `ts`, optionally with the target's msgid.
auto quoting(const b33& author, sys_ms ts, std::optional<int64_t> msgid = std::nullopt) {
    return [author, ts, msgid](SessionProtos::DataMessage& d) {
        auto* q = d.mutable_quote();
        q->set_msgtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
        q->set_author(oxenc::to_hex(author.begin(), author.end()));
        if (msgid)
            q->set_msgid(*msgid);
    };
}

}  // namespace

TEST_CASE("Client: a reply names what it answers", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto first = from_epoch_ms(1000);
    deliver(*c, peer, "the original", first, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c, peer, "the answer", from_epoch_ms(2000), "h2", "", std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 2);
    // Newest first.
    const auto& answer = msgs[0];
    const auto& original = msgs[1];

    REQUIRE(answer.reply);
    CHECK(answer.reply->author == peer.session_id);
    CHECK(answer.reply->timestamp == first);
    REQUIRE(answer.reply->message_id.has_value());
    CHECK(*answer.reply->message_id == original.id);

    // The original is not itself a reply -- unset means "not a reply", which is a different
    // statement from an unresolved reference.
    CHECK_FALSE(original.reply.has_value());
}

TEST_CASE("Client: a reply to a message we do not have still names its author",
          "[client][replies]") {
    TempClient c;
    SenderKeys peer;

    auto missing = from_epoch_ms(500);
    deliver(*c, peer, "answering something we never got", from_epoch_ms(2000), "h1", "",
            std::nullopt, quoting(peer.session_id, missing, 4242));
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].reply);
    // Unresolved, but the author and timestamp came off the wire, so a client can still say who
    // was replied to over an "original message not found" line.
    CHECK_FALSE(msgs[0].reply->message_id.has_value());
    CHECK(msgs[0].reply->author == peer.session_id);
    CHECK(msgs[0].reply->timestamp == missing);
}

TEST_CASE("Client: a reply resolves once its target arrives", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // Out of order: the answer first.  This is the case that makes resolving-on-read necessary
    // rather than merely tidy -- resolved once at receipt, this reference would stay empty forever.
    auto first = from_epoch_ms(1000);
    deliver(*c, peer, "the answer", from_epoch_ms(2000), "h2", "", std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].reply);
    REQUIRE_FALSE(msgs[0].reply->message_id.has_value());

    deliver(*c, peer, "the original", first, "h1", "", std::nullopt, nullptr, 7777);
    sync(*c);

    msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message_id.has_value());
    CHECK(*msgs[0].reply->message_id == msgs[1].id);
}

TEST_CASE("Client: msgid disambiguates a same-millisecond target", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // Two messages from one sender stamped identically: exactly what msgid exists for.
    auto same = from_epoch_ms(1000);
    deliver(*c, peer, "first", same, "h1", "", std::nullopt, nullptr, 111);
    deliver(*c, peer, "second", same, "h2", "", std::nullopt, nullptr, 222);
    deliver(*c, peer, "answering the second", from_epoch_ms(2000), "h3", "", std::nullopt,
            quoting(peer.session_id, same, 222));
    sync(*c);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 3);

    int64_t second_id = 0;
    for (const auto& m : msgs)
        if (m.body == "second")
            second_id = m.id;
    REQUIRE(second_id != 0);

    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message_id.has_value());
    CHECK(*msgs[0].reply->message_id == second_id);
}

TEST_CASE("Client: an ambiguous target resolves stably", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // No msgid on the quote: the wire cannot say which of the two was meant, so we pick the lowest
    // id.  Arbitrary, but the same answer on every read, which is what matters to a display.
    auto same = from_epoch_ms(1000);
    deliver(*c, peer, "first", same, "h1", "", std::nullopt, nullptr, 111);
    deliver(*c, peer, "second", same, "h2", "", std::nullopt, nullptr, 222);
    deliver(*c, peer, "answering one of them", from_epoch_ms(2000), "h3", "", std::nullopt,
            quoting(peer.session_id, same));
    sync(*c);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 3);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message_id.has_value());
    auto picked = *msgs[0].reply->message_id;

    auto again = c->conversation(convo, wait)->messages(wait);
    REQUIRE(again[0].reply->message_id == picked);

    // And it is one of the two candidates, not something else.
    CHECK((again[1].id == picked || again[2].id == picked));
}

TEST_CASE("Client: a quote with an unusable author is dropped", "[client][replies]") {
    TempClient c;
    SenderKeys peer;

    auto target = from_epoch_ms(1000);
    deliver(*c, peer, "the original", target, "h0", "", std::nullopt, nullptr, 999);
    deliver(*c, peer, "body survives", from_epoch_ms(2000), "h1", "", std::nullopt,
            [](SessionProtos::DataMessage& d) {
                auto* q = d.mutable_quote();
                q->set_msgtimestamp(1000);
                q->set_author("not a session id");
            });
    // A well-formed one alongside it, so that "no reply" here means the bad reference was rejected
    // rather than that nothing writes references at all.
    deliver(*c, peer, "a good reply", from_epoch_ms(3000), "h2", "", std::nullopt,
            quoting(peer.session_id, target, 999));
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait);
    REQUIRE(msgs.size() == 3);

    auto by_body = [&](std::string_view b) -> const Message& {
        auto it = std::ranges::find_if(msgs, [&](const Message& m) { return m.body == b; });
        REQUIRE(it != msgs.end());
        return *it;
    };

    // The message carrying the bad quote is kept; only the unusable reference is discarded.
    CHECK_FALSE(by_body("body survives").reply.has_value());
    CHECK(by_body("a good reply").reply.has_value());
}

TEST_CASE("Client: a reply is re-reported when its target arrives", "[client][replies]") {
    Recorder rec;
    TempClient c{rec.handlers()};
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto target_ts = from_epoch_ms(1000);
    deliver(*c, peer, "the answer", from_epoch_ms(2000), "h2", "", std::nullopt,
            quoting(peer.session_id, target_ts, 7777));
    sync(*c);

    REQUIRE(rec.msg_added.size() == 1);
    auto reply_id = rec.msg_added[0].second.id;
    REQUIRE_FALSE(rec.msg_added[0].second.reply->message_id.has_value());
    rec.msg_updated.clear();

    // The target lands afterwards.  Nothing about the reply's own row changes, but what it resolves
    // to does -- and a display holding it has no way to know that without being told.
    deliver(*c, peer, "the original", target_ts, "h1", "", std::nullopt, nullptr, 7777);
    sync(*c);

    auto reported = std::ranges::find_if(rec.msg_updated, [&](const auto& p) {
        return p.second.id == reply_id;
    });
    REQUIRE(reported != rec.msg_updated.end());
    REQUIRE(reported->second.reply);
    CHECK(reported->second.reply->message_id.has_value());
}

TEST_CASE("Client: deleting a target re-reports the replies to it", "[client][replies]") {
    Recorder rec;
    TempClient c{rec.handlers()};
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto target_ts = from_epoch_ms(1000);
    deliver(*c, peer, "the original", target_ts, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c, peer, "the answer", from_epoch_ms(2000), "h2", "", std::nullopt,
            quoting(peer.session_id, target_ts, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, wait)->messages(wait);
    REQUIRE(msgs.size() == 2);
    auto reply_id = msgs[0].id;
    auto target_id = msgs[1].id;
    rec.msg_updated.clear();

    c->delete_message(target_id, wait);
    sync(*c);

    // The target itself is reported, and so is the reply that points at it: what it should draw
    // has changed even though its own row has not.
    CHECK(std::ranges::any_of(rec.msg_updated, [&](const auto& p) {
        return p.second.id == target_id;
    }));
    CHECK(std::ranges::any_of(rec.msg_updated, [&](const auto& p) {
        return p.second.id == reply_id;
    }));
}
