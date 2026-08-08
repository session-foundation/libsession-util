#include <SQLiteCpp/Transaction.h>
#include <SessionProtos.pb.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <oxen/log.hpp>
#include <oxen/quic/loop.hpp>
#include <session/client.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
#include <session/sqlite.hpp>
#include <stdexcept>

namespace session::client {

namespace log = oxen::log;
static auto cat = log::Cat("client");

using namespace std::literals;

// Domain separation for the message content hash.  The sender is hashed alongside the content
// because the sender is not inside the Content protobuf -- it rides in the envelope (v1) or is
// recovered from the signature (v2) -- so without it two participants sending byte-identical
// content in the same millisecond would collide.
static constexpr auto CONTENT_HASH_PERS = "SessionMsgIdHash"_b2b_pers;

static int64_t to_ms(sys_ms t) {
    return t.time_since_epoch().count();
}

/// The message's stable cross-client identity: BLAKE2b over the sender and the unpadded serialised
/// Content.  Both sides of a conversation compute the same value from bytes they already hold at
/// libsession's public API boundary, with no protocol change and no round trip.
static std::array<std::byte, 32> content_hash(
        std::span<const std::byte, 33> sender, std::span<const std::byte> content) {
    return hash::blake2b_pers<32>(CONTENT_HASH_PERS, sender, content);
}

static SendState state_for(core::MessageSendStatus status) {
    switch (status) {
        case core::MessageSendStatus::awaiting_keys: return SendState::pending;
        case core::MessageSendStatus::sending:
        case core::MessageSendStatus::retrying: return SendState::sending;
        case core::MessageSendStatus::success: return SendState::sent;
        case core::MessageSendStatus::network_error:
        case core::MessageSendStatus::no_network:
        case core::MessageSendStatus::encrypt_failed: return SendState::failed;
    }
    return SendState::failed;
}

static bool is_terminal(core::MessageSendStatus status) {
    switch (status) {
        case core::MessageSendStatus::success:
        case core::MessageSendStatus::network_error:
        case core::MessageSendStatus::no_network:
        case core::MessageSendStatus::encrypt_failed: return true;
        default: return false;
    }
}

// Returns the accounts row id for a session ID, creating it if this is the first time we have seen
// the account.  Must be called inside the caller's transaction.
static int64_t account_id(sqlite::Connection& c, std::span<const std::byte, 33> session_id) {
    c.prepared_exec("INSERT OR IGNORE INTO accounts (session_id) VALUES (?)", session_id);
    return c.prepared_get<int64_t>("SELECT id FROM accounts WHERE session_id = ?", session_id);
}

// The conversations column a given kind occupies, plus the queries that resolve or create the row
// in the table that column references.
struct ConvoKind {
    std::string_view column;
    std::string_view find;
    std::string_view create;
};

static ConvoKind kind_of(ConversationId::Type type) {
    switch (type) {
        case ConversationId::Type::dm:
            return {"dm",
                    "SELECT id FROM accounts WHERE session_id = ?",
                    "INSERT OR IGNORE INTO accounts (session_id) VALUES (?)"};
        case ConversationId::Type::group:
            return {"closed_group",
                    "SELECT id FROM groups WHERE group_id = ?",
                    "INSERT OR IGNORE INTO groups (group_id) VALUES (?)"};
        case ConversationId::Type::community:
            return {"community",
                    "SELECT id FROM communities WHERE base_url = ? AND room = ?",
                    "INSERT OR IGNORE INTO communities (base_url, room) VALUES (?, ?)"};
    }
    throw std::logic_error{"unhandled conversation kind"};
}

// Invokes `run` with a ConvoKind query and whichever bind parameters that kind's identity takes:
// one blob for a DM or group, two strings for a community.
template <typename R>
static R with_identity_binds(const ConversationId& id, std::string_view query, auto&& run) {
    if (id.type() == ConversationId::Type::community) {
        auto [url, room] = id.community();
        return run(std::string{query}, url, room);
    }
    auto raw = id.type() == ConversationId::Type::dm ? id.session_id() : id.group_id();
    return run(std::string{query}, raw);
}

// Returns the identity row id for what a conversation is with, creating it if absent.  Must be
// called inside the caller's transaction.
static int64_t identity_id(sqlite::Connection& c, const ConversationId& id) {
    auto kind = kind_of(id.type());
    with_identity_binds<int>(id, kind.create, [&](const std::string& q, const auto&... b) {
        return c.prepared_exec(q, b...);
    });
    return with_identity_binds<int64_t>(id, kind.find, [&](const std::string& q, const auto&... b) {
        return c.prepared_get<int64_t>(q, b...);
    });
}

// Rebuilds a ConversationId from whichever identity a conversation row joined to.  Exactly one is
// set -- that is what the table's CHECK constraint enforces -- so the throw is unreachable unless
// the database has been corrupted or written behind our back.
static ConversationId subject_to_id(
        int64_t convo,
        const std::optional<sqlite::blob_guts<b33>>& sid,
        const std::optional<sqlite::blob_guts<b33>>& gid,
        const std::optional<std::string>& url,
        const std::optional<std::string>& room) {
    if (sid)
        return ConversationId::dm(*sid);
    if (gid)
        return ConversationId::group(*gid);
    if (url && room)
        return ConversationId::community(*url, *room);
    throw std::runtime_error{"conversation {} has no subject"_format(convo)};
}

static constexpr auto SUBJECT_JOIN = R"(
    FROM conversations c
    LEFT JOIN accounts a ON a.id = c.dm
    LEFT JOIN groups g ON g.id = c.closed_group
    LEFT JOIN communities m ON m.id = c.community
)"sv;

static ConversationId conversation_id_at(sqlite::Connection& c, int64_t convo) {
    auto [sid, gid, url, room] = c.prepared_get<
            std::optional<sqlite::blob_guts<b33>>,
            std::optional<sqlite::blob_guts<b33>>,
            std::optional<std::string>,
            std::optional<std::string>>(
            "SELECT a.session_id, g.group_id, m.base_url, m.room {} WHERE c.id = ?"_format(
                    SUBJECT_JOIN),
            convo);
    return subject_to_id(convo, sid, gid, url, room);
}

struct ConvoRow {
    int64_t id;
    bool created;
};

// Creates the conversation row if it is missing and moves last_activity forward to `activity` if
// that is newer, returning its row id.  Must be called inside the caller's transaction along with
// whatever change prompted it.
static ConvoRow ensure_conversation(
        sqlite::Connection& c, const ConversationId& id, sys_ms activity) {
    auto kind = kind_of(id.type());
    auto subject = identity_id(c, id);
    auto ms = to_ms(activity);

    bool created = c.prepared_exec(
                           R"(
        INSERT OR IGNORE INTO conversations ({}, created, last_activity) VALUES (?, ?, ?)
    )"_format(kind.column),
                           subject,
                           ms,
                           ms) > 0;
    if (!created)
        c.prepared_exec(
                R"(
            UPDATE conversations SET last_activity = ?2
            WHERE {} = ?1 AND last_activity < ?2
        )"_format(kind.column),
                subject,
                ms);

    return {c.prepared_get<int64_t>(
                    "SELECT id FROM conversations WHERE {} = ?"_format(kind.column), subject),
            created};
}

// Returns the conversation row id, or nullopt if we have no such conversation.
static std::optional<int64_t> find_conversation(sqlite::Connection& c, const ConversationId& id) {
    auto kind = kind_of(id.type());
    auto subject = with_identity_binds<std::optional<int64_t>>(
            id, kind.find, [&](const std::string& q, const auto&... b) {
                return c.prepared_maybe_get<int64_t>(q, b...);
            });
    if (!subject)
        return std::nullopt;
    return c.prepared_maybe_get<int64_t>(
            "SELECT id FROM conversations WHERE {} = ?"_format(kind.column), *subject);
}

core::callbacks Client::_intercept_callbacks(core::callbacks app) {
    // Capturing `this` here is safe despite running in Core's member-init list: the two callbacks
    // we install can only fire from receive_messages() and send_dm(), neither of which Core calls
    // during its own construction.  Everything else in `app` is passed through untouched and may
    // fire during construction (device_link_request does) without touching Client.
    auto cb = std::move(app);

    cb.message_received = [this,
                           chain = std::move(cb.message_received)](core::ReceivedMessage&& msg) {
        // Persist first, then notify: a throwing callback is a bug Core can only log, so Client
        // must never rely on an exception to reject a batch.
        if (chain) {
            auto copy = msg;
            _on_message_received(std::move(msg));
            chain(std::move(copy));
        } else
            _on_message_received(std::move(msg));
    };

    cb.message_send_status = [this, chain = std::move(cb.message_send_status)](
                                     int64_t id, core::MessageSendStatus status) {
        _on_send_status(id, status);
        if (chain)
            chain(id, status);
    };

    return cb;
}

void Client::_init() {
    // Core's send queue is in-memory, so anything still mid-flight when the last run ended is not
    // resumed and its outcome is unknowable.  Say so rather than guessing either way.
    auto c = core.database().conn();
    c.prepared_exec(
            R"(
        UPDATE messages SET send_state = ? WHERE send_state IN (?, ?)
    )",
            static_cast<int>(SendState::interrupted),
            static_cast<int>(SendState::pending),
            static_cast<int>(SendState::sending));
}

// -- Change notification ----------------------------------------------------------------------

Subscription Client::subscribe(std::function<void(const Change&)> handler) {
    std::lock_guard lock{_signals->mutex};
    auto id = _signals->next_id++;
    _signals->handlers.emplace(id, std::move(handler));
    return Subscription{_signals, id};
}

void Client::_emit(const Change& change) {
    // Iterate over a copy of the handler list: a handler is allowed to subscribe or unsubscribe
    // (including its own subscription) from inside the callback.
    std::vector<std::function<void(const Change&)>> handlers;
    {
        std::lock_guard lock{_signals->mutex};
        handlers.reserve(_signals->handlers.size());
        for (const auto& [id, h] : _signals->handlers)
            handlers.push_back(h);
    }

    for (const auto& h : handlers) {
        try {
            h(change);
        } catch (const std::exception& e) {
            log::error(cat, "client change handler threw: {}", e.what());
        }
    }
}

// -- Asynchronous interface ---------------------------------------------------------------------

void Client::_require_dm(const ConversationId& id) {
    // Checked on the calling thread so caller error surfaces at the call site rather than inside
    // the loop, where the callback form would only be able to log it.
    if (id.type() != ConversationId::Type::dm)
        throw std::invalid_argument{
                "send_message: only DM conversations are supported so far (got type {})"_format(
                        static_cast<int>(id.type()))};
}

void Client::_dispatch(std::function<void()> work) {
    core.loop().call([work = std::move(work)] {
        try {
            work();
        } catch (const std::exception& e) {
            // Nowhere to throw to: the caller's stack is gone, and letting this escape would take
            // the event loop with it.
            log::error(cat, "Client operation failed: {}", e.what());
        }
    });
}

// Blocking forms: call_get runs the job on the loop and waits, or runs it inline when the caller is
// already there.  Exceptions propagate back to the caller, which is the whole advantage of this
// form over the callback one.

std::vector<Conversation> Client::conversations() {
    return core.loop().call_get([this] { return _conversations(); });
}

std::optional<Conversation> Client::conversation(const ConversationId& id) {
    return core.loop().call_get([this, &id] { return _conversation(id); });
}

Conversation Client::create_conversation(const ConversationId& id) {
    return core.loop().call_get([this, &id] { return _create_conversation(id); });
}

// Not dispatched onto the loop: reads nothing but the session ID, which cannot change underneath
// it.  See the declaration.
bool Client::is_note_to_self(const ConversationId& id) {
    return id.type() == ConversationId::Type::dm &&
           std::ranges::equal(id.session_id(), _self_or_none());
}

void Client::mark_read(const ConversationId& id, std::optional<sys_ms> up_to) {
    core.loop().call_get([this, &id, up_to] {
        _mark_read(id, up_to);
        return 0;
    });
}

std::vector<Message> Client::messages(
        const ConversationId& id, int limit, std::optional<MessageCursor> before) {
    return core.loop().call_get(
            [this, &id, limit, before] { return _messages(id, limit, before); });
}

std::optional<Message> Client::message(int64_t id) {
    return core.loop().call_get([this, id] { return _message(id); });
}

int64_t Client::send_message(const ConversationId& id, std::string_view body) {
    _require_dm(id);
    return core.loop().call_get([this, &id, body] { return _send_message(id, body); });
}

// Callback forms: dispatch and return, delivering the result on the loop thread.

void Client::conversations(std::function<void(std::vector<Conversation>)> cb) {
    _dispatch([this, cb = std::move(cb)] { cb(_conversations()); });
}

void Client::conversation(
        const ConversationId& id, std::function<void(std::optional<Conversation>)> cb) {
    _dispatch([this, id, cb = std::move(cb)] { cb(_conversation(id)); });
}

void Client::create_conversation(const ConversationId& id, std::function<void(Conversation)> cb) {
    _dispatch([this, id, cb = std::move(cb)] { cb(_create_conversation(id)); });
}

void Client::mark_read(const ConversationId& id, std::function<void()> cb) {
    mark_read(id, std::nullopt, std::move(cb));
}

void Client::mark_read(
        const ConversationId& id, std::optional<sys_ms> up_to, std::function<void()> cb) {
    _dispatch([this, id, up_to, cb = std::move(cb)] {
        _mark_read(id, up_to);
        if (cb)
            cb();
    });
}

void Client::messages(const ConversationId& id, std::function<void(std::vector<Message>)> cb) {
    messages(id, 50, std::nullopt, std::move(cb));
}

void Client::messages(
        const ConversationId& id, int limit, std::function<void(std::vector<Message>)> cb) {
    messages(id, limit, std::nullopt, std::move(cb));
}

void Client::messages(
        const ConversationId& id,
        int limit,
        std::optional<MessageCursor> before,
        std::function<void(std::vector<Message>)> cb) {
    _dispatch([this, id, limit, before, cb = std::move(cb)] { cb(_messages(id, limit, before)); });
}

void Client::message(int64_t id, std::function<void(std::optional<Message>)> cb) {
    _dispatch([this, id, cb = std::move(cb)] { cb(_message(id)); });
}

void Client::send_message(
        const ConversationId& id, std::string_view body, std::function<void(int64_t)> cb) {
    _require_dm(id);
    _dispatch([this, id, body = std::string{body}, cb = std::move(cb)] {
        auto msg_id = _send_message(id, body);
        if (cb)
            cb(msg_id);
    });
}

// -- Conversations ----------------------------------------------------------------------------

// Only a DM has a name source so far; groups and communities gain one with the features.
static const auto CONVO_COLUMNS = R"(
    SELECT c.id, a.session_id, g.group_id, m.base_url, m.room,
           a.display_name, c.last_activity,
           coalesce((SELECT b.body FROM messages b WHERE b.conversation = c.id
                      ORDER BY b.timestamp DESC, b.id DESC LIMIT 1), ''),
           c.unread_count
    {}
)"_format(SUBJECT_JOIN);

// `self` is our own session ID, for flagging the Note to Self conversation; it is not part of the
// query because the row does not know whose database it is in.  Empty when there is no account
// yet, under which circumstance nothing can be a conversation with ourselves.
template <typename... Bind>
static std::vector<Conversation> query_conversations(
        sqlite::Connection& c,
        std::span<const std::byte> self,
        const std::string& query,
        const Bind&... bind) {
    std::vector<Conversation> out;
    for (auto [convo, sid, gid, url, room, name, activity, preview, unread] :
         c.prepared_results<
                 int64_t,
                 std::optional<sqlite::blob_guts<b33>>,
                 std::optional<sqlite::blob_guts<b33>>,
                 std::optional<std::string>,
                 std::optional<std::string>,
                 std::optional<std::string>,
                 int64_t,
                 std::string,
                 int>(query, bind...))
        out.push_back(Conversation{
                .id = subject_to_id(convo, sid, gid, url, room),
                .display_name = name.value_or(""),
                .last_message = std::move(preview),
                .last_activity = from_epoch_ms(activity),
                .unread = unread,
                .note_to_self = sid && std::ranges::equal(static_cast<const b33&>(*sid), self)});
    return out;
}

// Our own session ID, or empty when no account exists yet.  Reads are expected to work before
// onboarding under defer_account -- "no account" and "no conversations" are the same answer -- so
// nothing on a read path may reach for the identity unconditionally.
std::span<const std::byte> Client::_self_or_none() {
    if (!core.globals.have_account())
        return {};
    return core.globals.session_id();
}

std::vector<Conversation> Client::_conversations() {
    auto c = core.database().conn();
    return query_conversations(
            c, _self_or_none(), "{} ORDER BY c.last_activity DESC, c.id"_format(CONVO_COLUMNS));
}

std::optional<Conversation> Client::_conversation(const ConversationId& id) {
    auto c = core.database().conn();
    auto convo = find_conversation(c, id);
    if (!convo)
        return std::nullopt;
    auto found = query_conversations(
            c, _self_or_none(), "{} WHERE c.id = ?"_format(CONVO_COLUMNS), *convo);
    if (found.empty())
        return std::nullopt;
    return std::move(found.front());
}

Conversation Client::_create_conversation(const ConversationId& id) {
    bool created;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        created = ensure_conversation(c, id, clock_now_ms()).created;
        tx.commit();
    }
    if (created)
        _emit({ChangeType::conversation_added, id, std::nullopt});
    return *_conversation(id);
}

void Client::_mark_read(const ConversationId& id, std::optional<sys_ms> up_to) {
    int changed = 0;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = find_conversation(c, id);
        if (!convo)
            return;

        int64_t target;
        if (up_to)
            target = to_ms(*up_to);
        else {
            // "Everything" means every message that exists now, not every message that ever will:
            // parking the watermark at infinity would silently mark all future arrivals read.
            auto newest = c.prepared_get<std::optional<int64_t>>(
                    R"(
                SELECT max(timestamp) FROM messages WHERE conversation = ? AND outgoing = 0
            )",
                    *convo);
            if (!newest)
                return;
            target = *newest;
        }

        // Moving last_read changes what counts as unread without touching any message, so the
        // triggers cannot see it; recompute here, where it is rare, rather than per list query.
        changed = c.prepared_exec(
                R"(
            UPDATE conversations
            SET last_read = ?1,
                unread_count = (SELECT COUNT(*) FROM messages
                                 WHERE conversation = ?2 AND outgoing = 0 AND timestamp > ?1)
            WHERE id = ?2 AND last_read < ?1
        )",
                target,
                *convo);
        tx.commit();
    }
    if (changed > 0)
        _emit({ChangeType::conversation_updated, id, std::nullopt});
}

// -- Messages ---------------------------------------------------------------------------------

// No join back to conversations: every row of a given query belongs to one conversation, so its
// ConversationId is resolved once by the caller rather than rebuilt per row.
static constexpr auto MESSAGE_COLUMNS = R"(
    SELECT m.id, m.swarm_hash, a.session_id, m.outgoing, m.timestamp, m.body, m.send_state
    FROM messages m
    JOIN accounts a ON a.id = m.sender
)"sv;

template <typename... Bind>
static std::vector<Message> query_messages(
        sqlite::Connection& c,
        const ConversationId& convo,
        const std::string& query,
        const Bind&... bind) {
    std::vector<Message> out;
    for (auto [id, swarm_hash, sender, outgoing, ts, body, send_state] :
         c.prepared_results<
                 int64_t,
                 std::optional<std::string>,
                 sqlite::blob_guts<b33>,
                 int,
                 int64_t,
                 std::string,
                 std::optional<int>>(query, bind...))
        out.push_back(Message{
                .id = id,
                .conversation = convo,
                .sender = sender,
                .outgoing = outgoing != 0,
                .timestamp = from_epoch_ms(ts),
                .body = std::move(body),
                .send_state = send_state ? std::optional{static_cast<SendState>(*send_state)}
                                         : std::nullopt,
                .hash = std::move(swarm_hash)});
    return out;
}

std::vector<Message> Client::_messages(
        const ConversationId& id, int limit, std::optional<MessageCursor> before) {
    auto c = core.database().conn();
    auto convo = find_conversation(c, id);
    if (!convo)
        return {};

    if (!before)
        return query_messages(
                c,
                id,
                R"(
            {} WHERE m.conversation = ? ORDER BY m.timestamp DESC, m.id DESC LIMIT ?
        )"_format(MESSAGE_COLUMNS),
                *convo,
                limit);

    // Strictly-older-than comparison on (timestamp, id), spelled out rather than as an SQL row
    // value so this does not depend on the SQLite version's row-value support.
    return query_messages(
            c,
            id,
            R"(
        {} WHERE m.conversation = ?1
             AND (m.timestamp < ?2 OR (m.timestamp = ?2 AND m.id < ?3))
           ORDER BY m.timestamp DESC, m.id DESC LIMIT ?4
    )"_format(MESSAGE_COLUMNS),
            *convo,
            to_ms(before->timestamp),
            before->id,
            limit);
}

std::optional<Message> Client::_message(int64_t id) {
    auto c = core.database().conn();
    auto convo =
            c.prepared_maybe_get<int64_t>("SELECT conversation FROM messages WHERE id = ?", id);
    if (!convo)
        return std::nullopt;

    auto found = query_messages(
            c, conversation_id_at(c, *convo), "{} WHERE m.id = ?"_format(MESSAGE_COLUMNS), id);
    if (found.empty())
        return std::nullopt;
    return std::move(found.front());
}

int64_t Client::_send_message(const ConversationId& id, std::string_view body) {
    if (id.type() != ConversationId::Type::dm)
        throw std::invalid_argument{
                "send_message: only DM conversations are supported so far (got type {})"_format(
                        static_cast<int>(id.type()))};

    auto now = clock_now_ms();
    auto self = core.globals.session_id();

    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(to_ms(now)));
    auto* data = content.mutable_datamessage();
    data->set_body(std::string{body});
    data->set_timestamp(static_cast<uint64_t>(to_ms(now)));

    auto serialised = content.SerializeAsString();
    auto raw = std::span{reinterpret_cast<const std::byte*>(serialised.data()), serialised.size()};
    auto cid = content_hash(self, raw);

    bool created;
    int64_t client_id;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = ensure_conversation(c, id, now);
        created = convo.created;

        c.prepared_exec(
                R"(
            INSERT INTO messages
                (conversation, content_hash, sender, outgoing, timestamp, body, send_state)
            VALUES (?, ?, ?, 1, ?, ?, ?)
        )",
                convo.id,
                cid,
                account_id(c, self),
                to_ms(now),
                body,
                static_cast<int>(SendState::pending));
        client_id = c.sql.getLastInsertRowid();

        c.prepared_exec(
                "INSERT INTO message_raw_content (message, content) VALUES (?, ?)", client_id, raw);
        tx.commit();
    }

    if (created)
        _emit({ChangeType::conversation_added, id, std::nullopt});
    _emit({ChangeType::new_message, id, client_id});
    _emit({ChangeType::conversation_updated, id, std::nullopt});

    log::debug(cat, "send_message: message {} to conversation {}", client_id, id.to_string());

    auto core_id = core.send_dm(id.session_id(), content, now);
    _send_ids[core_id] = client_id;

    // send_dm() reports its first status synchronously, i.e. before we knew the id to map it to.
    if (auto stashed = _early_status.extract(core_id))
        _apply_send_status(client_id, stashed.mapped());

    return client_id;
}

// -- Core event handling ----------------------------------------------------------------------

void Client::_on_message_received(core::ReceivedMessage&& msg) {
    SessionProtos::Content content;
    if (!content.ParseFromArray(msg.content.data(), static_cast<int>(msg.content.size()))) {
        log::warning(cat, "Dropping message {}: Content protobuf did not parse", msg.hash);
        return;
    }

    // Receipts, typing indicators and call signalling are not conversation history; ignore them
    // rather than materialising an empty conversation for a stranger who is merely typing.
    if (!content.has_datamessage())
        return;
    const auto& data = content.datamessage();
    if (data.body().empty())
        return;

    // A one-to-one message is stored on both participants' swarms, so our own sent messages come
    // back to us from our own swarm.  For those the sender is us, which says nothing about which
    // conversation they belong to; the recipient is carried in syncTarget instead.
    //
    // syncTarget is only honoured on a self-send.  Session's other clients honour it on any
    // incoming message, which lets a peer file their message into a conversation they are not part
    // of; there is no case where a message from someone else needs it, so this does not.
    bool outgoing = std::ranges::equal(msg.sender_session_id, core.globals.session_id());

    b33 convo_with = msg.sender_session_id;
    if (outgoing && data.has_synctarget()) {
        const auto& target = data.synctarget();
        if (target.size() != 66 || !oxenc::is_hex(target)) {
            log::warning(
                    cat,
                    "Dropping message {}: syncTarget is not a session ID: {}",
                    msg.hash,
                    target);
            return;
        }
        oxenc::from_hex(target.begin(), target.end(), reinterpret_cast<char*>(convo_with.data()));
    }

    if (convo_with[0] != std::byte{0x05}) {
        log::warning(
                cat, "Dropping message {}: conversation target is not a 0x05 session ID", msg.hash);
        return;
    }
    auto convo_id = ConversationId::dm(convo_with);

    // The signed timestamp is the authenticated one; the swarm's upload time is not.
    auto ts = content.has_sigtimestamp()
                    ? from_epoch_ms(static_cast<int64_t>(content.sigtimestamp()))
                    : msg.timestamp;

    std::string_view name;
    if (data.has_profile() && data.profile().has_displayname())
        name = data.profile().displayname();

    auto cid = content_hash(msg.sender_session_id, msg.content);

    bool created = false, inserted = false, renamed = false;
    int64_t client_id = 0;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        // Every incoming DM materialises a visible conversation.  Session's actual behaviour gates
        // this: a message from an account you have not approved belongs in the message requests
        // list, and only becomes an ordinary conversation once you approve it.
        //
        // Worth knowing before implementing that: the gate is not "do not create the conversation".
        // The message still needs somewhere to live, and a request is shown as a real conversation
        // once opened -- so it is classification, not suppression.  Approval state belongs on the
        // accounts row, reconciled from the Contacts config; conversations() then filters on it and
        // a separate accessor lists the requests.  Unread splits the same way, Session counting
        // request unreads separately from the conversation badge.
        auto convo = ensure_conversation(c, convo_id, ts);
        created = convo.created;
        auto sender = account_id(c, msg.sender_session_id);

        // Delivery is at-least-once -- the swarm cursor advances per batch, so a crash mid-batch
        // re-delivers it -- and either unique index is enough to recognise the redelivery.
        inserted = c.prepared_exec(
                           R"(
            INSERT OR IGNORE INTO messages
                (conversation, content_hash, swarm_hash, sender, outgoing, timestamp, body,
                 send_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        )",
                           convo.id,
                           cid,
                           msg.hash,
                           sender,
                           outgoing ? 1 : 0,
                           to_ms(ts),
                           data.body(),
                           // Retrieving it from a swarm is proof it got there, whichever device
                           // put it there.
                           outgoing ? std::optional<int>{static_cast<int>(SendState::sent)}
                                    : std::optional<int>{}) > 0;
        if (inserted) {
            client_id = c.sql.getLastInsertRowid();
            c.prepared_exec(
                    "INSERT INTO message_raw_content (message, content) VALUES (?, ?)",
                    client_id,
                    std::span<const std::byte>{msg.content});

            // Whether an arrival is unread is this layer's decision, not the trigger's.  Today
            // that is just "newer than the watermark"; mutes and message requests will land here.
            if (!outgoing)
                c.prepared_exec(
                        R"(
                UPDATE conversations SET unread_count = unread_count + 1
                WHERE id = ?1 AND ?2 > last_read
            )",
                        convo.id,
                        to_ms(ts));
        }

        // Skipped for a self-send: the LokiProfile on one of those is our own, which belongs to the
        // UserProfile config rather than to anything observed on the wire, and `name` here is used
        // to name the conversation partner.
        //
        // `IS NOT` rather than `!=`: the column is NULL until a name is known, and `NULL != 'x'`
        // is NULL, so `!=` would never fire for the first name we learn.
        if (!outgoing && !name.empty())
            renamed = c.prepared_exec(
                              R"(
                UPDATE accounts SET display_name = ?1
                WHERE id = ?2 AND display_name IS NOT ?1
            )",
                              name,
                              sender) > 0;

        tx.commit();
    }

    if (created)
        _emit({ChangeType::conversation_added, convo_id, std::nullopt});
    if (inserted)
        _emit({ChangeType::new_message, convo_id, client_id});
    if (inserted || renamed)
        _emit({ChangeType::conversation_updated, convo_id, std::nullopt});
}

void Client::_on_send_status(int64_t core_id, core::MessageSendStatus status) {
    auto it = _send_ids.find(core_id);
    if (it == _send_ids.end()) {
        // Fired from inside send_dm(), before it returned us the id to map.  send_message() drains
        // this as soon as it has the mapping.
        _early_status.insert_or_assign(core_id, status);
        return;
    }

    auto client_id = it->second;
    if (is_terminal(status))
        _send_ids.erase(it);
    _apply_send_status(client_id, status);
}

void Client::_apply_send_status(int64_t client_id, core::MessageSendStatus status) {
    auto state = state_for(status);
    std::optional<ConversationId> convo;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        if (c.prepared_exec(
                    R"(
            UPDATE messages SET send_state = ? WHERE id = ? AND send_state IS NOT ?
        )",
                    static_cast<int>(state),
                    client_id,
                    static_cast<int>(state)) > 0) {
            auto convo_row = c.prepared_maybe_get<int64_t>(
                    "SELECT conversation FROM messages WHERE id = ?", client_id);
            if (convo_row)
                convo = conversation_id_at(c, *convo_row);
        }
        tx.commit();
    }

    if (convo)
        _emit({ChangeType::message_updated, *convo, client_id});
}

}  // namespace session::client
