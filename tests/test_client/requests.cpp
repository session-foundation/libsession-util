#include "config_helpers.hpp"

TEST_CASE("Client: a stranger's message is a request, not a conversation", "[client][requests]") {
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys sender;
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "hi, remember me?", from_epoch_ms(5000), "h1", "Jar Jar");
    sync(*c);

    CHECK(c->conversations(wait).empty());
    auto requests = c->message_requests(wait);
    REQUIRE(requests.size() == 1);
    CHECK(requests[0].id() == id);
    CHECK(requests[0].dm()->request);
    CHECK(requests[0].display_name() == "Jar Jar");
    CHECK(requests[0].unread() == 1);

    // A conversation in every other respect, including being announced as one -- what differs is
    // which list it belongs to, and `request` is what says so.
    REQUIRE(r.added.size() == 1);
    CHECK(r.added[0].dm()->request);
    REQUIRE(c->conversation(id, wait));
    CHECK(c->conversation(id, wait)->dm()->request);
    CHECK(c->conversation(id, wait)->messages(wait).size() == 1);

    // And it is synced, so a request answered on one device is not still waiting on another.  Their
    // writing to us is what says they approved us; nothing yet says we approved them.
    auto entry = c->core.configs.contacts().get(oxenc::to_hex(sender.session_id));
    REQUIRE(entry);
    CHECK(entry->approved_me);
    CHECK_FALSE(entry->approved);
}

TEST_CASE("Client: answering a request accepts it", "[client][requests]") {
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys sender;
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "hello?", from_epoch_ms(5000), "h1");
    sync(*c);
    REQUIRE(c->message_requests(wait).size() == 1);
    r.order.clear();

    // There is no separate accept: writing to someone is what approving them is.
    c->send_message(id, {.body = "hello yourself"}, wait);
    sync(*c);

    CHECK(c->message_requests(wait).empty());
    REQUIRE(c->conversations(wait).size() == 1);
    CHECK_FALSE(c->conversations(wait)[0].dm()->request);
    CHECK(c->core.configs.contacts().get(oxenc::to_hex(sender.session_id))->approved);

    // It left one list and joined the other, which is neither an addition nor a removal to either,
    // so both are replaced.
    CHECK(std::ranges::count(r.order, "replaced") == 1);
    CHECK(std::ranges::count(r.order, "requests") == 1);
}

TEST_CASE("Client: a linked device's answer accepts the request", "[client][requests]") {
    TempClient c;
    SenderKeys sender;
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "hello?", from_epoch_ms(5000), "h1");
    REQUIRE(c->message_requests(wait).size() == 1);

    // Our own message coming back off our own swarm because another device sent it.  syncTarget
    // says who it was addressed to, and sending to them is what approved them.
    deliver(*c,
            self_keys(*c),
            "answered elsewhere",
            from_epoch_ms(6000),
            "h2",
            "",
            sender.session_id);

    CHECK(c->message_requests(wait).empty());
    REQUIRE(c->conversations(wait).size() == 1);
    CHECK(c->conversations(wait)[0].id() == id);
}

TEST_CASE("Client: writing first leaves us awaiting their approval", "[client][requests]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);

    c->send_message(id, {.body = "are you there?"}, wait);
    sync(*c);

    // The mirror of a request: we are in *their* requests list, and nothing they could be sent
    // says so -- only a message back from them clears it.  Meanwhile it is an ordinary conversation
    // of ours, since we chose to start it.
    REQUIRE(c->conversations(wait).size() == 1);
    CHECK(c->conversations(wait)[0].dm()->awaiting_approval);
    CHECK_FALSE(c->conversations(wait)[0].dm()->request);
    CHECK(c->message_requests(wait).empty());

    deliver(*c, them, "here", from_epoch_ms(9000), "h1");

    REQUIRE(c->conversation(id, wait));
    CHECK_FALSE(c->conversation(id, wait)->dm()->awaiting_approval);
    CHECK_FALSE(c->conversation(id, wait)->dm()->request);
}

TEST_CASE("Client: note to self is never a message request", "[client][requests]") {
    TempClient c;
    auto me = self_convo(*c.client);

    c->send_message(me, {.body = "a note"}, wait);
    sync(*c);

    CHECK(c->message_requests(wait).empty());
    REQUIRE(c->conversation(me, wait));
    CHECK_FALSE(c->conversation(me, wait)->dm()->request);

    // Nor awaiting anything: there is nobody at the other end to accept.
    CHECK_FALSE(c->conversation(me, wait)->dm()->awaiting_approval);
}

TEST_CASE("Client: a blocked account's messages are refused", "[client][requests]") {
    TempClient c;
    SenderKeys sender;
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "first", from_epoch_ms(5000), "h1");
    REQUIRE(c->conversation(id, wait)->messages(wait).size() == 1);

    c->dm(id, wait)->set_blocked(true, wait);
    deliver(*c, sender, "and again", from_epoch_ms(6000), "h2");

    // Refused on arrival rather than hidden when drawing, so nothing they send becomes history or
    // an unread count.
    CHECK(c->conversation(id, wait)->messages(wait).size() == 1);
    CHECK(c->conversation(id, wait)->unread() == 1);

    c->dm(id, wait)->set_blocked(false, wait);
    deliver(*c, sender, "still there?", from_epoch_ms(7000), "h3");
    CHECK(c->conversation(id, wait)->messages(wait).size() == 2);
}

