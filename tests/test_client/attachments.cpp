#include "../../src/client/download_cache.hpp"
#include "../utils.hpp"
#include "common.hpp"

namespace cache = session::client::cache;

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

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait);
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
             OutgoingAttachment{.path = mystery, .voice_message = true}}, wait);

    auto msg = c->message(id, wait);
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
    msg = c->message(id, wait);
    REQUIRE(msg.has_value());
    for (const auto& a : msg->attachments) {
        CHECK(a.uploaded);
        CHECK(a.size == static_cast<int64_t>(std::string_view{"not really a file"}.size()));
    }

    // The same list reaches a paged read, not only the single-message one.
    auto page = c->conversation(ConversationId::dm(me), wait)->messages(wait);
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

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait);
    REQUIRE(msgs.size() == 1);
    auto msg_id = msgs[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_save", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";

    std::vector<AttachmentProgress> reports;
    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg_id, 0, dest,
            [&](const AttachmentProgress& p) { reports.push_back(p); },
            [&](std::optional<std::string> err, std::filesystem::path) {
                done.set_value(std::move(err));
            });

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

    // Progress reported as a send does: an opening 0/0 that says it has begun, then exactly one
    // terminal result.  Each report says which attachment of which message it is about, since a
    // caller may be watching several.
    REQUIRE(reports.size() >= 2);
    CHECK_FALSE(reports.front().result.has_value());
    CHECK(reports.front().done == 0);
    CHECK(reports.front().total == 0);
    CHECK(reports.back().result == 0);
    for (const auto& r : reports) {
        CHECK(r.message_id == msg_id);
        CHECK(r.index == 0);
    }

    // And the sender is told, since nothing said otherwise.
    sync(*c);
    CHECK(stores(*net).size() == 1);

    // We also remember that we saved it, which is what stops a client offering "save" forever and
    // writing a second copy.  Recorded whether or not the sender was told.
    auto saved = c->message(msg_id, wait);
    REQUIRE(saved.has_value());
    REQUIRE(saved->attachments.size() == 1);
    REQUIRE(saved->attachments[0].saved_at.has_value());
    CHECK(*saved->attachments[0].saved_at > from_epoch_ms(0));

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
    auto msg_id = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait)[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_save", 7);
    std::filesystem::create_directories(dir);

    // The promise is shared rather than captured by reference: save_attachment's callback outlives
    // this scope, and a reference to a local here would dangle by the time the download is served.
    auto save = [&](const std::filesystem::path& dest, bool notify) {
        auto done = std::make_shared<std::promise<std::optional<std::string>>>();
        auto waiter = done->get_future();
        c->Client::save_attachment(
                msg_id, 0, dest, nullptr,
                [done](std::optional<std::string> err, std::filesystem::path) {
                    done->set_value(std::move(err));
                },
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

        // Telling them and remembering it ourselves are separate: a private save is still a save.
        CHECK(c->message(msg_id, wait)->attachments[0].saved_at.has_value());
    }

    // The account's own answer refuses the notification even when the caller asked for it, so a
    // client that never grew a setting for this still honours one made on another device.
    {
        c->core.configs.user_profile().set_notify_media_saved(false);
        auto loud = dir / "still-quiet.bin";
        auto waiter = save(loud, true);
        REQUIRE(serve_downloads(*net, ciphertext) == 1);
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        CHECK_FALSE(waiter.get().has_value());
        CHECK(std::filesystem::exists(loud));
        sync(*c);
        CHECK(stores(*net).empty());
        c->core.configs.user_profile().set_notify_media_saved(true);
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
            ConversationId::dm(me), "here it is", {OutgoingAttachment{.path = source}}, wait);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto msg = c->message(id, wait);
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
            [&done](std::optional<std::string> err, std::filesystem::path) {
                done.set_value(std::move(err));
            });
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

    // Stamped, even though the message is outgoing: this conversation is with ourselves, so the
    // recipient saving it and us saving it are the same event.
    CHECK(c->message(id, wait)->attachments[0].saved_at.has_value());

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a save does not destroy files it was not asked to touch",
          "[client][attachments]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_clobber", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "sent.bin";
    std::vector<std::byte> contents(1024, std::byte{0x11});
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }
    auto id = c->send_message(
            ConversationId::dm(me), "here", {OutgoingAttachment{.path = source}}, wait);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto dest = dir / "report.pdf";

    // Two files the caller never mentioned: somebody's own scratch file from another downloader,
    // and something that appeared at the destination after the caller checked it was free.
    auto their_part = dir / "report.pdf.part";
    {
        std::ofstream out{their_part};
        out << "theirs";
    }
    {
        std::ofstream out{dest};
        out << "appeared since";
    }

    std::promise<std::pair<std::optional<std::string>, std::filesystem::path>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            id, 0, dest, nullptr,
            [&done](std::optional<std::string> err, std::filesystem::path where) {
                done.set_value({std::move(err), std::move(where)});
            });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    auto [err, saved_to] = waiter.get();
    REQUIRE_FALSE(err.has_value());

    // Neither file was touched, and the caller is told where its own went.
    CHECK(std::filesystem::exists(their_part));
    CHECK(std::filesystem::file_size(their_part) == 6);
    CHECK(std::filesystem::file_size(dest) == 14);
    CHECK(saved_to == dir / "report (1).pdf");
    CHECK(std::filesystem::file_size(saved_to) == contents.size());

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: an approved replacement is not renamed out of the way",
          "[client][attachments]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_replace", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "sent.bin";
    std::vector<std::byte> contents(1024, std::byte{0x22});
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }
    auto id = c->send_message(
            ConversationId::dm(me), "here", {OutgoingAttachment{.path = source}}, wait);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto dest = dir / "report.pdf";
    {
        std::ofstream out{dest};
        out << "the one the user chose to replace";
    }

    std::promise<std::filesystem::path> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            id, 0, dest, nullptr,
            [&done](std::optional<std::string>, std::filesystem::path where) {
                done.set_value(std::move(where));
            },
            /*notify_sender=*/true,
            /*replace=*/true);
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);

    // Renaming here would be worse than clobbering: the file the user agreed to replace would still
    // be sitting there, and their answer would have been thrown away.
    CHECK(waiter.get() == dest);
    CHECK(std::filesystem::file_size(dest) == contents.size());
    CHECK_FALSE(std::filesystem::exists(dir / "report (1).pdf"));

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: saving what we sent someone else does not claim they saved it",
          "[client][attachments]") {
    TempClient c;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    SenderKeys peer;
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_theirs", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "sent.bin";
    std::vector<std::byte> contents(2048, std::byte{0x5a});
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }

    auto id = c->send_message(
            ConversationId::dm(peer.session_id),
            "for you",
            {OutgoingAttachment{.path = source}},
            wait);
    sync(*c);
    REQUIRE(accept_stores(*net) >= 1);

    auto dest = dir / "my-copy.bin";
    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            id, 0, dest, nullptr,
            [&done](std::optional<std::string> err, std::filesystem::path) {
                done.set_value(std::move(err));
            });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    REQUIRE_FALSE(waiter.get().has_value());
    REQUIRE(std::filesystem::exists(dest));

    // `saved_at` on an outgoing attachment means *they* saved it, which is what lets a sender read
    // it as "the file reached a person rather than a file server".  Our own copy says nothing about
    // that, so it must leave the field alone -- otherwise a UI reports "they have it" about someone
    // who may never have opened the conversation.
    auto msg = c->message(id, wait);
    REQUIRE(msg);
    REQUIRE(msg->attachments.size() == 1);
    CHECK_FALSE(msg->attachments[0].saved_at.has_value());

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a peer can tell us they saved what we sent", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    TestHelper::seed_pfs_nak(c->core, peer.session_id);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_notified", 7);
    std::filesystem::create_directories(dir);
    auto one = dir / "one.bin";
    auto two = dir / "two.bin";
    std::ofstream{one, std::ios::binary} << "first file";
    std::ofstream{two, std::ios::binary} << "second file";

    auto id = c->send_message(
            ConversationId::dm(peer.session_id),
            "two of them",
            {OutgoingAttachment{.path = one}, OutgoingAttachment{.path = two}}, wait);
    sync(*c);
    REQUIRE(accept_stores(*net) == 2);

    auto sent = c->message(id, wait);
    REQUIRE(sent.has_value());
    REQUIRE(sent->attachments.size() == 2);
    // Nobody has said anything yet, and an upload reaching the file server is not someone saving it.
    CHECK_FALSE(sent->attachments[0].saved_at.has_value());
    CHECK_FALSE(sent->attachments[1].saved_at.has_value());

    // What the peer's client sends when its user saves one file out of the message.
    auto msgid = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<int64_t>(
                "SELECT msgid FROM messages WHERE id = ?", id);
    });
    auto notify = [&](auto&& fill, sys_ms at) {
        SessionProtos::Content content;
        content.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(at)));
        auto* note = content.mutable_dataextractionnotification();
        note->set_type(SessionProtos::DataExtractionNotification::MEDIA_SAVED);
        fill(note);

        auto plaintext = content.SerializeAsString();
        auto encoded = encode_dm_v1(
                std::as_bytes(std::span{plaintext}), peer.ed_sk, at, own_sid(*c), std::nullopt);
        core::SwarmMessage sm{
                encoded, random::unique_id("h", 8), at, from_epoch_ms(1'000'000'000'000)};
        c->core.loop().call_get([&] {
            c->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
            return 0;
        });
        sync(*c);
    };

    auto saved_at = from_epoch_ms(9'000'000);
    notify([&](auto* note) {
        note->set_msgtimestamp(static_cast<uint64_t>(epoch_ms(sent->timestamp)));
        note->set_msgid(msgid);
        note->set_attindex(1);
    }, saved_at);

    auto after = c->message(id, wait);
    REQUIRE(after.has_value());
    // Only the one they named, and stamped with when *they* saved it -- not the message's own
    // timestamp, which is what identifies it and is generally older.
    CHECK_FALSE(after->attachments[0].saved_at.has_value());
    REQUIRE(after->attachments[1].saved_at.has_value());
    CHECK(*after->attachments[1].saved_at == saved_at);

    // -1 is "all of them, together", which is what saving from a gallery view reports.
    auto all_at = from_epoch_ms(9'500'000);
    notify([&](auto* note) {
        note->set_msgtimestamp(static_cast<uint64_t>(epoch_ms(sent->timestamp)));
        note->set_msgid(msgid);
        note->set_attindex(-1);
    }, all_at);

    auto all = c->message(id, wait);
    REQUIRE(all->attachments[0].saved_at == all_at);
    // The later save overwrites the earlier one: what this answers is "is there any point offering
    // save again", not a history of every time they did.
    CHECK(all->attachments[1].saved_at == all_at);

    // A notification naming a message we do not have changes nothing, and neither does one that
    // names no message at all -- which is every notification the other clients send today, since
    // their `timestamp` field means something different in each of them.
    notify([&](auto* note) {
        note->set_msgtimestamp(static_cast<uint64_t>(epoch_ms(sent->timestamp)));
        note->set_msgid(msgid + 1);
        note->set_attindex(0);
    }, from_epoch_ms(9'900'000));
    notify([&](auto* note) { note->set_timestamp(12345); }, from_epoch_ms(9'900'000));

    auto unchanged = c->message(id, wait);
    CHECK(unchanged->attachments[0].saved_at == all_at);
    CHECK(unchanged->attachments[1].saved_at == all_at);

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

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].attachments.size() == 1);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_legacy", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "legacy.txt";

    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msgs[0].id, 0, dest, nullptr,
            [&done](std::optional<std::string> err, std::filesystem::path) {
                done.set_value(std::move(err));
            });
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

TEST_CASE(
        "Client: a message with attachments needs readable files", "[client][send][attachments]") {
    TempClient c{};
    auto me = own_sid(*c);

    CHECK_THROWS_AS(
            c->send_message(
                    ConversationId::dm(me),
                    "here you go",
                    {OutgoingAttachment{.path = "/nonexistent/nope.png"}}, wait),
            std::invalid_argument);

    // Rejected before anything was stored, rather than leaving a message that can never be sent --
    // and not even a conversation, which is a stronger thing to be able to say than that it has no
    // messages in it.
    CHECK_FALSE(c->conversation(ConversationId::dm(me), wait).has_value());
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
            }, wait);
    sync(*c);

    auto msg = c->message(id, wait);
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
            }, wait);
    sync(*c);

    // With no network the upload cannot start, so the one report is its failure -- which is the
    // point: an outcome is never a thing the throttle may drop.
    CHECK(c->message(id, wait)->send_state == SendState::failed);
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
            ConversationId::dm(me), "here you go", {OutgoingAttachment{.path = file}}, wait);
    sync(*c);
    REQUIRE(c->message(id, wait)->send_state == SendState::failed);

    // Retrying is allowed while the failure is one that might not recur, and reports itself as
    // started rather than as succeeded -- the outcome arrives through the message's state.
    std::vector<std::optional<int>> results;
    CHECK(c->retry_send(
            id,
            [&](size_t, int64_t, int64_t, std::optional<int> result) {
                results.push_back(result);
            },
            wait));
    sync(*c);
    REQUIRE(results.size() == 1);
    CHECK(c->message(id, wait)->send_state == SendState::failed);

    // With the file gone the retry can only ever fail the same way, so the message becomes
    // terminal rather than staying something an application would offer to try again.
    std::filesystem::remove(file);

    results.clear();
    CHECK(c->retry_send(
            id,
            [&](size_t, int64_t, int64_t, std::optional<int> result) {
                results.push_back(result);
            },
            wait));
    sync(*c);
    REQUIRE(results.size() == 1);
    CHECK(results.front() == ATTACHMENT_FILE_MISSING);
    CHECK(c->message(id, wait)->send_state == SendState::unsendable);

    // ... and being terminal, it is refused rather than attempted again.
    CHECK_FALSE(c->retry_send(id, wait));
}

TEST_CASE("Client: a stream attachment must be the size its sender claimed",
          "[client][attachments][size]") {
    // The pointer's size is exact -- the file server is told the byte count up front and refuses
    // anything else -- so a file that decrypts to a different length is not a file we asked for.
    // Nothing else catches this for a stream attachment: the format strips its own padding and
    // never consults the pointer, so before this the claim was simply ignored.
    // One short, one long: over-reporting and under-reporting are both lies.
    int64_t claimed = GENERATE(8999, 9001);


    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);

    deliver(*c, peer, "", from_epoch_ms(1000), "h1", "", std::nullopt,
            [&, claimed](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/1#d");
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                // A lie in one direction or the other; the truth is 9000.
                a->set_size(static_cast<uint32_t>(claimed));
                a->set_filename("payload.bin");
            },
            42);
    sync(*c);

    auto msg_id = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait)[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_size", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";

    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg_id, 0, dest, nullptr, [&](std::optional<std::string> err, std::filesystem::path) {
                done.set_value(std::move(err));
            });

    sync(*c);
    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);

    // Reported as a failure rather than saved short or saved long.
    auto err = waiter.get();
    REQUIRE(err.has_value());
    CHECK(err->find("sender said") != std::string::npos);

    // And nothing is left on disk that could be mistaken for the file.
    CHECK_FALSE(std::filesystem::exists(dest));
    CHECK_FALSE(std::filesystem::exists(dest.string() + ".part"));

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: two askers for one attachment share one download", "[client][attachments][join]") {
    // A conversation opening while its attachments are being fetched asks for bytes that are not in
    // the cache yet.  Without joining, that starts a second download of the same file: the cache is
    // still empty, so a display sees a miss and fetches it again.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    net->served["shared"] = ciphertext;

    deliver(*c, peer, "", from_epoch_ms(1000), "h1", "", std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("shared", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            42);
    sync(*c);
    auto msg_id = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait)[0].id;

    std::vector<std::optional<std::vector<std::byte>>> got(2);
    std::vector<std::vector<AttachmentProgress>> seen(2);
    for (int i = 0; i < 2; i++)
        c->attachment_data(
                msg_id, 0,
                [&, i](const AttachmentProgress& p) { seen[i].push_back(p); },
                [&, i](std::optional<std::string> err, std::vector<std::byte> d) {
                    REQUIRE_FALSE(err.has_value());
                    got[i] = std::move(d);
                });
    sync(*c);

    // One transfer, not two.
    REQUIRE(net->downloads.size() == 1);

    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    sync(*c);

    // Both askers get the whole file.
    for (int i = 0; i < 2; i++) {
        REQUIRE(got[i]);
        CHECK(*got[i] == plaintext);
        // ...and both were told how it was going, not only the one that started it.
        CHECK_FALSE(seen[i].empty());
        CHECK(seen[i].back().result == 0);
        CHECK(seen[i].back().message_id == msg_id);
    }

    // The second asker joined midway and was told where it had got to straight away, rather than
    // being left with nothing until the next chunk.
    CHECK_FALSE(seen[1].empty());

    // And having finished, a third ask is served from the cache with no download at all.
    net->downloads.clear();
    std::optional<std::vector<std::byte>> third;
    c->attachment_data(msg_id, 0, nullptr,
                       [&](std::optional<std::string> err, std::vector<std::byte> d) {
                           REQUIRE_FALSE(err.has_value());
                           third = std::move(d);
                       });
    sync(*c);
    CHECK(net->downloads.empty());
    REQUIRE(third);
    CHECK(*third == plaintext);
}

TEST_CASE("Client: saving joins a fetch already under way", "[client][attachments][join]") {
    // The direction that *can* combine: something is being accumulated for the cache -- a gallery,
    // or the auto-downloader -- and a save asks for the same file.  Waiting on it costs nothing,
    // since that buffer is committed either way, and fetching it twice would be two transfers of
    // one file.
    //
    // (The reverse cannot: a save streams to disk and keeps nothing, so a display arriving midway
    // has no way to be given the half already written.)
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    c->set_cache_dir(dir.path);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    net->served["both"] = ciphertext;

    deliver(*c, peer, "", from_epoch_ms(1000), "h1", "", std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("both", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            42);
    sync(*c);
    auto msg_id = c->conversation(ConversationId::dm(peer.session_id), wait)->messages(wait)[0].id;

    // A display asks first, so the file is being accumulated.
    std::optional<std::vector<std::byte>> shown;
    c->attachment_data(msg_id, 0, nullptr,
                       [&](std::optional<std::string> err, std::vector<std::byte> d) {
                           REQUIRE_FALSE(err.has_value());
                           shown = std::move(d);
                       });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    // Now a save of the same attachment, while that is still in flight.
    auto dest = dir.path / "saved.png";
    std::vector<AttachmentProgress> saw;
    std::promise<std::optional<std::string>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg_id, 0, dest,
            [&](const AttachmentProgress& p) { saw.push_back(p); },
            [&](std::optional<std::string> err, std::filesystem::path) {
                done.set_value(std::move(err));
            });
    sync(*c);

    // Still one transfer: the save waited rather than asking for the same bytes again.
    CHECK(net->downloads.size() == 1);

    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());
    sync(*c);

    // Both callers got what they asked for: the display its bytes, the save its file.
    REQUIRE(shown);
    CHECK(*shown == plaintext);
    REQUIRE(std::filesystem::exists(dest));
    CHECK(std::filesystem::file_size(dest) == plaintext.size());
    {
        std::ifstream in{dest, std::ios::binary};
        std::vector<std::byte> got(plaintext.size());
        in.read(reinterpret_cast<char*>(got.data()), got.size());
        CHECK(!!(got == plaintext));
    }

    // The save was told how the transfer it joined was going, not left silent until it finished.
    CHECK_FALSE(saw.empty());
    CHECK(saw.back().result == 0);
}

TEST_CASE("Client: a conversation set to auto-download fetches on arrival", "[client][auto]") {
    TempCacheDir dir;
    std::vector<std::pair<ConversationId, AttachmentProgress>> progress;
    callbacks cbs;
    cbs.attachment_progress = [&](const ConversationId& id, const AttachmentProgress& p) {
        progress.emplace_back(id, p);
    };
    TempClient c{cbs};
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    c->set_cache_dir(dir.path);

    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, wait);

    std::vector<std::byte> image(4000), doc(4000);
    random::fill(image);
    random::fill(doc);
    auto seed = random::random(32);
    auto [image_ct, image_key] = attachment::encrypt(seed, image, attachment::Domain::ATTACHMENT);
    auto [doc_ct, doc_key] = attachment::encrypt(seed, doc, attachment::Domain::ATTACHMENT);
    net->served["img"] = image_ct;
    net->served["doc"] = doc_ct;

    auto arrive = [&](std::string hash, bool with_doc) {
        deliver(*c, peer, "", from_epoch_ms(1000), hash, "", std::nullopt,
                [&](SessionProtos::DataMessage& data) {
                    auto* a = data.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url("img", {}, true));
                    a->set_key(std::string{
                            reinterpret_cast<const char*>(image_key.data()), image_key.size()});
                    a->set_size(image.size());
                    a->set_contenttype("image/png");
                    if (with_doc) {
                        auto* b = data.add_attachments();
                        b->set_id(2);
                        b->set_url(network::file_server::generate_download_url("doc", {}, true));
                        b->set_key(std::string{
                                reinterpret_cast<const char*>(doc_key.data()), doc_key.size()});
                        b->set_size(doc.size());
                        b->set_contenttype("application/pdf");
                    }
                });
        sync(*c);
    };

    SECTION("unasked means nothing is fetched") {
        // Never having been asked is not consent, and is what a client prompts on.
        REQUIRE_FALSE(c->conversation(convo, wait)->auto_download().has_value());
        arrive("h1", false);
        CHECK(net->downloads.empty());
        CHECK(progress.empty());
        CHECK_FALSE(c->conversation(convo, wait)->messages(wait)[0].gallery);
    }

    SECTION("images only fetches the image and leaves the document") {
        c->conversation(convo, wait)->set_auto_download(AutoDownload::image_attachments, wait);
        arrive("h2", true);
        REQUIRE(net->downloads.size() == 1);
        CHECK(net->downloads[0].download_url.find("img") != std::string::npos);

        // Not a gallery: one of its attachments is not an image, so it cannot be shown as one.
        auto m = c->conversation(convo, wait)->messages(wait)[0];
        CHECK_FALSE(m.gallery_viewable);
        CHECK_FALSE(m.gallery);
    }

    SECTION("all fetches both, and an all-image message opens as a gallery") {
        c->conversation(convo, wait)->set_auto_download(AutoDownload::all, wait);
        arrive("h3", true);
        CHECK(net->downloads.size() == 2);

        // Two attachments, one of them a pdf: still not gallery viewable even though both were
        // fetched.  What is downloaded and what can be displayed as a gallery are different
        // questions.
        CHECK_FALSE(c->conversation(convo, wait)->messages(wait)[0].gallery);

        arrive("h4", false);
        auto m = c->conversation(convo, wait)->messages(wait)[0];
        CHECK(m.gallery_viewable);
        CHECK(m.gallery);
    }

    SECTION("a size limit refuses what is too big, before fetching it") {
        c->conversation(convo, wait)->set_auto_download(AutoDownload::all, wait);
        c->set_auto_download_max_size(1000, wait);
        arrive("h5", false);
        CHECK(net->downloads.empty());

        // Raising it lets the next one through, so the limit is read per message rather than
        // remembered from startup.
        c->set_auto_download_max_size(std::nullopt, wait);
        arrive("h6", false);
        CHECK(net->downloads.size() == 1);
    }

    SECTION("the fetch is reported, cached, and never told to the sender") {
        c->conversation(convo, wait)->set_auto_download(AutoDownload::all, wait);
        arrive("h7", false);
        REQUIRE(net->downloads.size() == 1);
        REQUIRE(serve_downloads(*net, image_ct) == 1);
        sync(*c);

        // Broadcast, since nobody asked for it and there is no caller to hand a report to.
        REQUIRE_FALSE(progress.empty());
        CHECK(progress.back().first == convo);
        CHECK(progress.back().second.result == 0);

        // In the cache, so opening the conversation costs nothing...
        CHECK(std::filesystem::exists(
                cache::path_for(dir.path, cache::ATTACHMENT_DIR,
                                network::file_server::generate_download_url("img", {}, true))));

        // ...and the sender is *not* told, because nobody has saved anything.  That notification
        // belongs to a save, whether or not the bytes came from the cache.
        CHECK(stores(*net).empty());
    }
}

TEST_CASE("Client: the cache evicts least recently used", "[client][auto][evict]") {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto net = std::make_shared<MockNetwork>();
    c->core.set_network(net);
    c->set_cache_dir(dir.path);

    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, wait);
    c->conversation(convo, wait)->set_auto_download(AutoDownload::all, wait);

    // `last_used` is a millisecond timestamp, and the whole of this test would otherwise run inside
    // one of them, leaving every row tied and the eviction order arbitrary.  Real uses are spread
    // out; these have to be spread out by hand.
    ScopedClockOffset clock{0s};
    auto later = [t = 0s]() mutable { AdjustedClock::set_offset(t += 1s); };

    auto seed = random::random(32);
    // Three files, fetched in order, each about the same size on disk.
    std::vector<std::string> urls;
    std::vector<int64_t> ids;
    for (int i = 0; i < 3; i++) {
        later();
        std::vector<std::byte> data(3000);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        auto file_id = "f{}"_format(i);
        net->served[file_id] = ct;
        auto url = network::file_server::generate_download_url(file_id, {}, true);
        urls.push_back(url);

        deliver(*c, peer, "", from_epoch_ms(1000 + i), "h{}"_format(i), "", std::nullopt,
                [&, url](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(static_cast<uint64_t>(i + 1));
                    a->set_url(url);
                    a->set_key(std::string{
                            reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(data.size());
                    a->set_contenttype("image/png");
                });
        sync(*c);
        REQUIRE(serve_downloads(*net, ct) == 1);
        sync(*c);
        ids.push_back(c->conversation(convo, wait)->messages(wait)[0].id);
    }

    auto cached = [&](const std::string& url) {
        return std::filesystem::exists(cache::path_for(dir.path, cache::ATTACHMENT_DIR, url));
    };
    for (const auto& u : urls)
        REQUIRE(cached(u));

    // Reach for the *oldest* one, which makes it the most recently used.  Under oldest-first
    // eviction it would still be first to go; under least-recently-used it is last.
    later();
    c->attachment_data(ids[0], 0, nullptr, [](auto, auto) {});
    sync(*c);

    // Now a limit that only two of the three fit under.
    auto one = std::filesystem::file_size(cache::path_for(dir.path, cache::ATTACHMENT_DIR, urls[0]));
    c->set_attachment_cache_limit(static_cast<int64_t>(one * 2 + one / 2), wait);

    // Nothing happens until something is added, which is the only moment the total can grow.
    CHECK(cached(urls[1]));

    // A fourth arrival pushes it over and evicts.
    later();
    std::vector<std::byte> more(3000);
    random::fill(more);
    auto [more_ct, more_key] = attachment::encrypt(seed, more, attachment::Domain::ATTACHMENT);
    net->served["f3"] = more_ct;
    auto more_url = network::file_server::generate_download_url("f3", {}, true);
    deliver(*c, peer, "", from_epoch_ms(2000), "h3", "", std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(9);
                a->set_url(more_url);
                a->set_key(std::string{
                        reinterpret_cast<const char*>(more_key.data()), more_key.size()});
                a->set_size(more.size());
                a->set_contenttype("image/png");
            });
    sync(*c);
    REQUIRE(serve_downloads(*net, more_ct) == 1);
    sync(*c);

    // The one just fetched is kept -- a download that completed and immediately vanished would read
    // as a failure.
    CHECK(cached(more_url));
    // The one that was read most recently is kept, though it is the oldest by arrival.
    CHECK(cached(urls[0]));
    // The one nobody has touched since it arrived is gone.
    CHECK_FALSE(cached(urls[1]));

    // The index agrees with the directory rather than describing files that are no longer there.
    auto rows = c->core.database().conn().prepared_get<int64_t>(
            "SELECT count(*) FROM attachment_cache");
    size_t on_disk = 0;
    for (const auto& e :
         std::filesystem::directory_iterator{dir.path / cache::ATTACHMENT_DIR})
        if (!e.path().filename().string().ends_with(cache::PARTIAL_SUFFIX))
            on_disk++;
    CHECK(static_cast<size_t>(rows) == on_disk);
}
