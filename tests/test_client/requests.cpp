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

TEST_CASE("Client: accepting a request approves without answering it", "[client][requests]") {
    Recorder r;
    TempClient c{r.handlers()};
    auto* net = attach_mock_network(c->core);
    SenderKeys sender;
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "hello?", from_epoch_ms(5000), "h1");
    sync(*c);
    REQUIRE(c->message_requests(wait).size() == 1);
    r.order.clear();

    // No PFS keys published for them, so the acceptance falls back to a v1 send.
    TestHelper::seed_pfs_nak(c->core, sender.session_id);
    c->dm(id, wait)->approve(wait);
    sync(*c);

    // Accepted, and nothing was said: the history is still the one message they sent.
    CHECK(c->message_requests(wait).empty());
    REQUIRE(c->conversations(wait).size() == 1);
    CHECK_FALSE(c->conversations(wait)[0].dm()->request);
    CHECK(c->conversation(id, wait)->messages(wait).size() == 1);
    CHECK(c->core.configs.contacts().get(oxenc::to_hex(sender.session_id))->approved);

    // It left one list and joined the other, which is neither an addition nor a removal to either,
    // so both are replaced.
    CHECK(std::ranges::count(r.order, "replaced") == 1);
    CHECK(std::ranges::count(r.order, "requests") == 1);

    // One store, to their swarm and only theirs: an acceptance is not a message, so there is no
    // copy of it for our own devices -- what tells those is the Contacts config.
    CHECK(stores(*net).size() == 1);

    // And a second accept is not a second acceptance: nothing moved, so nobody is told again.
    r.order.clear();
    c->dm(id, wait)->approve(wait);
    sync(*c);
    CHECK(r.order.empty());
    CHECK(stores(*net).size() == 1);
}

TEST_CASE("Client: their acceptance is what stops us awaiting it", "[client][requests]") {
    TempClient us;
    TempClient them;
    auto* net = attach_mock_network(them->core);
    auto us_id = ConversationId::dm(own_sid(*them));
    auto them_id = ConversationId::dm(own_sid(*us));

    // We write first, which puts us in their requests and leaves us waiting on them.
    us->send_message(us_id, {.body = "are you there?"}, wait);
    sync(*us);
    REQUIRE(us->conversations(wait).size() == 1);
    REQUIRE(us->conversations(wait)[0].dm()->awaiting_approval);

    deliver(*them, self_keys(*us), "are you there?", from_epoch_ms(5000), "h1");
    REQUIRE(them->message_requests(wait).size() == 1);

    TestHelper::seed_pfs_nak(them->core, own_sid(*us));
    them->dm(them_id, wait)->approve(wait);
    sync(*them);

    // Their acceptance as they actually sent it, read by the client it was addressed to.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 1);
    // Named: SwarmMessage::data is a span, so a temporary here would be read after it had gone.
    auto payload = store_payload(*sent[0]);
    core::SwarmMessage sm{payload, "h2", from_epoch_ms(6000), from_epoch_ms(1'000'000'000'000)};
    us->core.loop().call_get([&] {
        us->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
        return 0;
    });
    sync(*us);

    // Accepted, and still not a word from them: what changed is the flag, not the history.
    REQUIRE(us->conversation(us_id, wait));
    CHECK_FALSE(us->conversation(us_id, wait)->dm()->awaiting_approval);
    CHECK(us->conversation(us_id, wait)->messages(wait).size() == 1);
    CHECK(us->core.configs.contacts().get(oxenc::to_hex(own_sid(*them)))->approved_me);

    // Theirs to approve us, not to move us: the conversation was ours from the moment we wrote it.
    CHECK(us->conversations(wait).size() == 1);
    CHECK(us->message_requests(wait).empty());
}

TEST_CASE("Client: a response that accepts nothing is not recorded", "[client][requests]") {
    TempClient c;

    // Built here rather than sent by another client, because no client sends either of these.
    auto respond = [&](const SenderKeys& from, bool approved, sys_ms at) {
        SessionProtos::Content content;
        content.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(at)));
        content.mutable_messagerequestresponse()->set_isapproved(approved);

        auto plaintext = content.SerializeAsString();
        auto encoded = encode_dm_v1(
                std::as_bytes(std::span{plaintext}), from.ed_sk, at, own_sid(*c), std::nullopt);
        core::SwarmMessage sm{
                encoded, random::unique_id("h", 8), at, from_epoch_ms(1'000'000'000'000)};
        c->core.loop().call_get([&] {
            c->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
            return 0;
        });
        sync(*c);
    };

    // An acceptance from someone we never wrote to answers a request we never made, and there is no
    // relationship of ours for it to be a fact about -- so it makes neither.
    SenderKeys stranger;
    respond(stranger, true, from_epoch_ms(5000));
    CHECK(c->conversations(wait).empty());
    CHECK(c->message_requests(wait).empty());
    CHECK_FALSE(c->core.configs.contacts().get(oxenc::to_hex(stranger.session_id)));

    // And a refusal from someone we did write to says nothing either: approval has no reverse, so
    // this is not the un-approval it reads as.
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    c->send_message(id, {.body = "are you there?"}, wait);
    sync(*c);

    respond(them, false, from_epoch_ms(6000));
    CHECK(c->conversation(id, wait)->dm()->awaiting_approval);
    CHECK_FALSE(c->core.configs.contacts().get(oxenc::to_hex(them.session_id))->approved_me);
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

