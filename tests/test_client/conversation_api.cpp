#include "config_helpers.hpp"

TEST_CASE("Client: a conversation reports the settings it carries", "[client][convos]") {
    TempClient c;
    auto them = "05" + std::string(64, 'a');
    auto id = dm_from_hex(them);
    c->open_dm(id, wait);

    auto convo = [&] { return *c->conversation(id, wait); };

    // Defaults, and the ones a screen needs in order to draw a toggle rather than a button.
    CHECK(convo().notifications() == config::notify_mode::defaulted);
    CHECK(convo().mute_until() == std::chrono::sys_seconds{});
    CHECK(convo().exp_mode() == config::expiration_mode::none);
    CHECK_FALSE(convo().dm()->blocked);

    c->conversation(id, wait)->set_notifications(config::notify_mode::disabled, wait);
    c->conversation(id, wait)->set_mute_until(std::chrono::sys_seconds{1700000000s}, wait);
    c->conversation(id, wait)->set_expiry(config::expiration_mode::after_read, 86400s, wait);
    c->set_blocked(id, true, wait);
    c->dm(id, wait)->set_nickname("Bilbo", wait);

    CHECK(convo().notifications() == config::notify_mode::disabled);
    CHECK(convo().mute_until() == std::chrono::sys_seconds{1700000000s});
    CHECK(convo().exp_mode() == config::expiration_mode::after_read);
    CHECK(convo().exp_timer() == 86400s);
    CHECK(convo().dm()->blocked);

    // The two halves display_name merges.  A row wants the merge; a screen that edits the nickname
    // has to show both, and cannot when only the resolved answer arrives.
    CHECK(convo().dm()->nickname == "Bilbo");
    CHECK(convo().display_name() == "Bilbo");
    CHECK(convo().dm()->name.empty());

    // All of it reaches the Contacts config, which is what makes it follow the account rather than
    // the device.
    auto entry = c->core.configs.contacts().get(them);
    REQUIRE(entry);
    CHECK(entry->notifications == config::notify_mode::disabled);
    CHECK(entry->mute_until == 1700000000);
    CHECK(entry->exp_mode == config::expiration_mode::after_read);
    CHECK(entry->exp_timer == 86400s);
    CHECK(entry->blocked);
    CHECK(entry->nickname == "Bilbo");

    // Clearing the nickname falls back to what they call themselves.
    c->dm(id, wait)->set_nickname("", wait);
    CHECK(convo().dm()->nickname.empty());
    CHECK_FALSE(c->core.configs.contacts().get(them)->nickname == "Bilbo");

    // A timer without a mode expires nothing, so it is not stored as though it were a setting.
    c->conversation(id, wait)->set_expiry(config::expiration_mode::none, 3600s, wait);
    CHECK(convo().exp_mode() == config::expiration_mode::none);
    CHECK(convo().exp_timer() == 0s);
}

TEST_CASE("Client: settings from another device reach the conversation", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, 'b');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) {
        e.set_name("Frodo");
        e.set_nickname("Mr Underhill");
        e.approved = true;
        e.blocked = true;
        e.notifications = config::notify_mode::disabled;
        e.mute_until = 1700000000;
        e.exp_mode = config::expiration_mode::after_send;
        e.exp_timer = 600s;
    });
    merge_contacts(*c.client, pushed);

    auto convo = c->conversation(id, wait);
    REQUIRE(convo);
    CHECK(convo->notifications() == config::notify_mode::disabled);
    CHECK(convo->mute_until() == std::chrono::sys_seconds{1700000000s});
    CHECK(convo->exp_mode() == config::expiration_mode::after_send);
    CHECK(convo->exp_timer() == 600s);
    REQUIRE(convo->dm());
    CHECK(convo->dm()->blocked);
    CHECK(convo->dm()->name == "Frodo");
    CHECK(convo->dm()->nickname == "Mr Underhill");
    CHECK(convo->display_name() == "Mr Underhill");
}

TEST_CASE("Client: a conversation knows which kind it is", "[client][convos]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    c->open_dm(id, wait);

    auto convo = c->conversation(id, wait);
    REQUIRE(convo);

    // The kind is what makes a question askable: `request` is a thing only a DM can be, and asking
    // it of a community should not compile rather than quietly answering false.
    REQUIRE(convo->dm());
    CHECK_FALSE(convo->dm()->request);
    CHECK_FALSE(convo->group());
    CHECK_FALSE(convo->community());

    // Common fields reach through whichever kind it is.
    CHECK(convo->id() == id);
    CHECK(convo->unread() == 0);
}

TEST_CASE("Client: a handler-form operation outlives the conversation it came from",
          "[client][convos]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    approve(*c, them.session_id);
    deliver(*c, them, "hi", from_epoch_ms(5000), "h1");
    REQUIRE(c->conversation(id, wait)->unread() == 1);

    // The natural way to write any of these is on something that has already gone by the time the
    // work runs: a temporary, a handler's parameter, or a list element whose list got replaced.  So
    // the operation must not reach back into the object -- and only the handler form can get this
    // wrong, since the waiting form runs before it returns.
    std::optional<std::string> error = "not called";
    {
        auto convo = c->conversation(id, wait);
        REQUIRE(convo);
        convo->mark_read([&](auto err) { error = std::move(err); });
    }  // convo destroyed here, before the loop has run the work
    sync(*c);

    CHECK_FALSE(error.has_value());
    CHECK(c->conversation(id, wait)->unread() == 0);

    // And on an outright temporary, which is how it reads at a call site.
    std::optional<std::string> paged = "not called";
    size_t got = 0;
    c->conversation(id, wait)->messages(50, [&](auto err, auto msgs) {
        paged = std::move(err);
        got = msgs.size();
    });
    sync(*c);
    CHECK_FALSE(paged.has_value());
    CHECK(got == 1);
}

TEST_CASE("Client: every conversation kind starts with its base", "[client][convos]") {
    // What makes reading a common field off AnyConversation free: each alternative holds its
    // `Conversation` at offset zero, so every arm of the variant's dispatch computes the same
    // address and the compiler folds it away.  Put another base ahead of `Conversation` and that
    // silently becomes a runtime selection instead.
    //
    TempClient c;
    Conversation base{*c.client, dm_from_hex("05" + std::string(64, '9'))};
    DM dm{base};
    Group group{base};
    Community community{base};
    CHECK(static_cast<const void*>(&dm) == static_cast<const Conversation*>(&dm));
    CHECK(static_cast<const void*>(&group) == static_cast<const Conversation*>(&group));
    CHECK(static_cast<const void*>(&community) == static_cast<const Conversation*>(&community));
}

