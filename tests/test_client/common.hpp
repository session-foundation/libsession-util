#pragma once

#include <SessionProtos.pb.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <fstream>
#include <future>
#include <oxen/quic/loop.hpp>
#include <session/attachments.hpp>
#include <session/client.hpp>
#include <session/clock.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/expiring.hpp>
#include <session/config/namespaces.hpp>
#include <session/config/user_profile.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/random.hpp>
#include <session/session_protocol.hpp>
#include <thread>

#include "../test_helper.hpp"

using namespace session;
using namespace session::client;
using namespace std::literals;
using namespace oxenc::literals;

/// Named rather than anonymous, and `inline` rather than `static`: nine translation units include
/// this, and an anonymous namespace would give each its own copy of every helper and a warning for
/// each one it happens not to use.  The using-directive at the bottom is what keeps the test bodies
/// reading as they did when they were all one file.
namespace client_test {

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
            client{std::make_unique<Client>(
                    path, std::move(cbs), std::forward<Opts>(opts)...)} {}

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

inline b33 own_sid(Client& c) {
    b33 out;
    std::ranges::copy(c.core.globals.session_id(), out.begin());
    return out;
}

/// `c`'s own sending keys, for building the copy of an outgoing message that Session stores on the
/// sender's own swarm.
inline SenderKeys self_keys(Client& c) {
    SenderKeys k;
    auto seed = c.core.globals.account_seed();
    std::ranges::copy(seed.ed25519_secret(), k.ed_sk.begin());
    std::ranges::copy(seed.ed25519_secret().last<32>(), k.ed_pk.begin());
    std::ranges::copy(c.core.globals.session_id(), k.session_id.begin());
    return k;
}

/// Marks an account as approved, which is what having written to them would have done.
///
/// A stranger's first message is a message request, so a test that is about anything else -- the
/// ordering of the list, what a priority does, what a handler is told -- has to say that this is an
/// ordinary conversation, or the list it is asking about is empty.
inline void approve(Client& c, const b33& sid) {
    c.core.loop().call_get([&] {
        auto conn = c.core.database().conn();
        conn.prepared_exec("INSERT OR IGNORE INTO accounts (session_id) VALUES (?)", sid);
        conn.prepared_exec(
                R"(
            INSERT INTO contacts (account, approved)
            VALUES ((SELECT id FROM accounts WHERE session_id = ?), 1)
            ON CONFLICT (account) DO UPDATE SET approved = 1
        )",
                sid);
        return 0;
    });
}

/// Builds, encrypts and delivers a v1 DM into `to` as if it had arrived from the swarm.
inline void deliver(
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
    std::vector<AnyConversation> added, updated;
    std::vector<ConversationId> removed;
    std::vector<std::vector<AnyConversation>> replaced, requests_replaced;
    std::vector<std::pair<ConversationId, Message>> msg_added, msg_updated;

    callbacks handlers() {
        return {
                .conversation_added =
                        [this](const AnyConversation& c) {
                            order.push_back("added");
                            added.push_back(c);
                        },
                .conversation_updated =
                        [this](const AnyConversation& c) {
                            order.push_back("updated");
                            updated.push_back(c);
                        },
                .conversation_removed =
                        [this](const ConversationId& id) {
                            order.push_back("removed");
                            removed.push_back(id);
                        },
                .conversation_list_replaced =
                        [this](std::vector<AnyConversation> l) {
                            order.push_back("replaced");
                            replaced.push_back(std::move(l));
                        },
                .request_list_replaced =
                        [this](std::vector<AnyConversation> l) {
                            order.push_back("requests");
                            requests_replaced.push_back(std::move(l));
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
inline void sync(Client& c) {
    c.core.loop().call_get([] { return 0; });
}

}  // namespace client_test

using namespace client_test;
