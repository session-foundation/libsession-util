#include <SQLiteCpp/Transaction.h>
#include <SessionProtos.pb.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <charconv>
#include <oxen/log.hpp>
#include <oxen/quic/loop.hpp>
#include <session/attachments.hpp>
#include <session/client.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/network/session_network.hpp>
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

// AttachmentPointer.Flags.VOICE_MESSAGE.  Mirrored rather than taken from the generated header so
// that the column's meaning is legible where it is written.
constexpr int ATTACHMENT_FLAG_VOICE_MESSAGE = 1;

// An attachment is a whole file rather than a swarm request, so it gets its own, longer allowances:
// the per-request one covers a stalled transfer, and the overall one bounds the upload entire.
constexpr auto ATTACHMENT_REQUEST_TIMEOUT = 60s;
constexpr auto ATTACHMENT_OVERALL_TIMEOUT = 10min;

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
    _jobs.reset(new oxen::quic::JobQueue{core.loop()});

    // Core's send queue is in-memory, so anything still mid-flight when the last run ended is not
    // resumed and its outcome is unknowable.  Say so rather than guessing either way.
    auto c = core.database().conn();
    c.prepared_exec(
            R"(
        UPDATE messages SET send_state = ?1 WHERE send_state IN (?2, ?3)
    )",
            static_cast<int>(SendState::interrupted),
            static_cast<int>(SendState::pending),
            static_cast<int>(SendState::sending));
    c.prepared_exec(
            R"(
        UPDATE messages SET sync_send_state = ?1 WHERE sync_send_state IN (?2, ?3)
    )",
            static_cast<int>(SendState::interrupted),
            static_cast<int>(SendState::pending),
            static_cast<int>(SendState::sending));

    // A message whose attachments were still uploading is not in that same doubt: nothing can have
    // reached a swarm, because the message could not be built until the uploads finished.  So it
    // failed outright rather than unknowably, and it is squarely retryable -- its attachment rows
    // record which files did get up, so resuming re-uploads only the rest.
    c.prepared_exec(
            "UPDATE messages SET send_state = ?1 WHERE send_state = ?2",
            static_cast<int>(SendState::failed),
            static_cast<int>(SendState::uploading));
    c.prepared_exec(
            "UPDATE messages SET sync_send_state = ?1 WHERE sync_send_state = ?2",
            static_cast<int>(SendState::failed),
            static_cast<int>(SendState::uploading));
}

// -- Change notification ----------------------------------------------------------------------

void Client::_emit(const std::function<void(const callbacks&)>& invoke) {
    try {
        invoke(_cbs);
    } catch (const std::exception& e) {
        log::error(cat, "client change handler threw: {}", e.what());
    }
}

void Client::_emit_conversation_added(const ConversationId& id) {
    auto convo = _conversation(id);
    if (!convo)
        return;
    _emit([&](const callbacks& cbs) {
        if (cbs.conversation_added)
            cbs.conversation_added(*convo);
    });
}

void Client::_emit_message(bool added, const ConversationId& id, int64_t message_id) {
    auto msg = _message(message_id);
    if (!msg)
        return;
    _emit([&](const callbacks& cbs) {
        const auto& h = added ? cbs.message_added : cbs.message_updated;
        if (h)
            h(id, *msg);
    });
}

void Client::JobsDeleter::operator()(oxen::quic::JobQueue* p) const {
    delete p;
}

void Client::_touch(const ConversationId& id) {
    if (std::ranges::find(_dirty, id) == _dirty.end())
        _dirty.push_back(id);

    // Deferred to the end of the loop's current turn rather than reported here: everything that
    // dirties a conversation runs on the loop, so by the time this fires a whole received batch has
    // been stored and the conversation has one settled state to report instead of fifty.
    if (!_flush_scheduled) {
        _flush_scheduled = true;
        _jobs->call_soon([this] { _flush_pending(); });
    }
}

void Client::_flush_pending() {
    _flush_scheduled = false;
    auto dirty = std::move(_dirty);
    _dirty.clear();

    for (const auto& id : dirty) {
        auto convo = _conversation(id);
        if (!convo)
            continue;
        _emit([&](const callbacks& cbs) {
            if (cbs.conversation_updated)
                cbs.conversation_updated(*convo);
        });
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

void Client::set_priority(const ConversationId& id, int priority) {
    core.loop().call_get([this, &id, priority] {
        _set_priority(id, priority);
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

int64_t Client::send_message(
        const ConversationId& id,
        std::string_view body,
        std::vector<OutgoingAttachment> attachments,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload) {
    _require_dm(id);

    // Checked here rather than at upload time so that an unreadable file throws where the mistake
    // was made, instead of failing a message that has already been stored and shown.
    for (const auto& a : attachments) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(a.path, ec) || ec)
            throw std::invalid_argument{
                    "send_message: attachment {} is not a readable file"_format(a.path.string())};
        if (std::filesystem::file_size(a.path, ec) == 0 || ec)
            throw std::invalid_argument{
                    "send_message: attachment {} is empty"_format(a.path.string())};
    }

    return core.loop().call_get(
            [&] { return _send_message(id, body, attachments, std::move(on_upload)); });
}

bool Client::retry_send(
        int64_t message_id,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload) {
    return core.loop().call_get([&] { return _retry_send(message_id, std::move(on_upload)); });
}

void Client::retry_send(
        int64_t message_id,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload,
        std::function<void(bool)> cb) {
    _dispatch([this, message_id, on_upload = std::move(on_upload), cb = std::move(cb)] {
        auto started = _retry_send(message_id, on_upload);
        if (cb)
            cb(started);
    });
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

void Client::set_priority(const ConversationId& id, int priority, std::function<void()> cb) {
    _dispatch([this, id, priority, cb = std::move(cb)] {
        _set_priority(id, priority);
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
           c.unread_count, c.priority
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
    for (auto [convo, sid, gid, url, room, name, activity, preview, unread, priority] :
         c.prepared_results<
                 int64_t,
                 std::optional<sqlite::blob_guts<b33>>,
                 std::optional<sqlite::blob_guts<b33>>,
                 std::optional<std::string>,
                 std::optional<std::string>,
                 std::optional<std::string>,
                 int64_t,
                 std::string,
                 int,
                 int>(query, bind...))
        out.push_back(
                Conversation{
                        .id = subject_to_id(convo, sid, gid, url, room),
                        .display_name = name.value_or(""),
                        .last_message = std::move(preview),
                        .last_activity = from_epoch_ms(activity),
                        .unread = unread,
                        .priority = priority,
                        .note_to_self =
                                sid && std::ranges::equal(static_cast<const b33&>(*sid), self)});
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
            c,
            _self_or_none(),
            // Hidden (negative priority) conversations are not part of the list at all; pinned ones
            // lead it, and equal priorities form a block that sorts among itself by recency.
            "{} WHERE c.priority >= 0 ORDER BY c.priority DESC, c.last_activity DESC, c.id"_format(
                    CONVO_COLUMNS));
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
        _emit_conversation_added(id);
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
        _touch(id);
}

void Client::_set_priority(const ConversationId& id, int priority) {
    int changed = 0;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        // Not ensure_conversation() for one that already exists: that moves last_activity forward,
        // and pinning is not activity -- it would reorder the very list it is being used to order.
        auto existing = find_conversation(c, id);
        auto convo = existing ? *existing : ensure_conversation(c, id, clock_now_ms()).id;

        changed = c.prepared_exec(
                "UPDATE conversations SET priority = ?1 WHERE id = ?2 AND priority IS NOT ?1",
                priority,
                convo);
        tx.commit();
    }

    if (changed > 0)
        _emit_list_replaced();
}

void Client::_emit_list_replaced() {
    auto convos = _conversations();
    _emit([&](const callbacks& cbs) {
        if (cbs.conversation_list_replaced)
            cbs.conversation_list_replaced(convos);
    });
}

// -- Messages ---------------------------------------------------------------------------------

// No join back to conversations: every row of a given query belongs to one conversation, so its
// ConversationId is resolved once by the caller rather than rebuilt per row.
static constexpr auto MESSAGE_COLUMNS = R"(
    SELECT m.id, m.swarm_hash, a.session_id, m.outgoing, m.timestamp, m.body, m.send_state,
           m.sync_send_state
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
    for (auto [id, swarm_hash, sender, outgoing, ts, body, send_state, sync_send_state] :
         c.prepared_results<
                 int64_t,
                 std::optional<std::string>,
                 sqlite::blob_guts<b33>,
                 int,
                 int64_t,
                 std::string,
                 std::optional<int>,
                 std::optional<int>>(query, bind...))
        out.push_back(
                Message{.id = id,
                        .conversation = convo,
                        .sender = sender,
                        .outgoing = outgoing != 0,
                        .timestamp = from_epoch_ms(ts),
                        .body = std::move(body),
                        .send_state = send_state
                                            ? std::optional{static_cast<SendState>(*send_state)}
                                            : std::nullopt,
                        .sync_send_state = sync_send_state ? std::optional{static_cast<SendState>(
                                                                     *sync_send_state)}
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

    // Two artifacts: the copy the recipient gets, and the copy we deposit in our own swarm so that
    // our other devices see it.  They differ only in syncTarget, which is what tells those devices
    // which conversation an outgoing message belongs to -- the sender being us either way.
    //
    // What we store locally is the *sync* copy, so that our row is identical whether we sent the
    // message or a linked device did.  Anything re-sent out of the database therefore has to clear
    // syncTarget again before it goes to a recipient.
    SessionProtos::Content synced = content;
    synced.mutable_datamessage()->set_synctarget(oxenc::to_hex(id.session_id()));

    auto serialised = synced.SerializeAsString();
    auto raw = std::span{reinterpret_cast<const std::byte*>(serialised.data()), serialised.size()};
    auto cid = content_hash(self, raw);

    // Note to self is one swarm, not two: sending both copies there would deposit the same message
    // twice, and both would come back.  So there is no separate sync send to have a state for.
    bool to_self = std::ranges::equal(id.session_id(), self);

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
                (conversation, content_hash, sender, outgoing, timestamp, body, send_state,
                 sync_send_state)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        )",
                convo.id,
                cid,
                account_id(c, self),
                to_ms(now),
                body,
                static_cast<int>(SendState::pending),
                to_self ? std::optional<int>{}
                        : std::optional{static_cast<int>(SendState::pending)});
        client_id = c.sql.getLastInsertRowid();
        log::debug(
                cat, "send_message: stored message {} ({}B content)", client_id, serialised.size());

        c.prepared_exec(
                "INSERT INTO message_raw_content (message, content) VALUES (?, ?)", client_id, raw);
        tx.commit();
    }

    if (created)
        _emit_conversation_added(id);
    _emit_message(true, id, client_id);
    _touch(id);

    log::debug(cat, "send_message: message {} to conversation {}", client_id, id.to_string());

    _dispatch_sends(client_id, id, content, synced, now, to_self);

    return client_id;
}

void Client::_dispatch_sends(
        int64_t client_id,
        const ConversationId& id,
        const SessionProtos::Content& content,
        const SessionProtos::Content& synced,
        sys_ms now,
        bool to_self) {
    auto self = core.globals.session_id();

    auto core_id =
            to_self ? core.send_dm(self, synced, now) : core.send_dm(id.session_id(), content, now);
    _send_ids[core_id] = client_id;

    // send_dm() reports its first status synchronously, i.e. before we knew the id to map it to.
    if (auto stashed = _early_status.extract(core_id))
        _apply_send_status(client_id, stashed.mapped(), false);

    if (!to_self) {
        auto sync_id = core.send_dm(self, synced, now);
        _sync_sends[sync_id] = client_id;
        if (auto stashed = _early_status.extract(sync_id))
            _apply_send_status(client_id, stashed.mapped(), true);
    }
}

// -- Attachments ------------------------------------------------------------------------------

int64_t Client::_send_message(
        const ConversationId& id,
        std::string_view body,
        const std::vector<OutgoingAttachment>& attachments,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload) {
    if (attachments.empty())
        return _send_message(id, body);

    auto now = clock_now_ms();
    auto self = core.globals.session_id();
    bool to_self = std::ranges::equal(id.session_id(), self);

    // Stored with the body alone for now.  What finally goes to the swarms also names the uploaded
    // files, which nothing knows yet -- that is what the uploads are for -- so the content and its
    // hash are rewritten in _finish_attachment_send once they do.
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
                (conversation, content_hash, sender, outgoing, timestamp, body, send_state,
                 sync_send_state)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        )",
                convo.id,
                cid,
                account_id(c, self),
                to_ms(now),
                body,
                static_cast<int>(SendState::uploading),
                to_self ? std::optional<int>{}
                        : std::optional{static_cast<int>(SendState::uploading)});
        client_id = c.sql.getLastInsertRowid();

        c.prepared_exec(
                "INSERT INTO message_raw_content (message, content) VALUES (?, ?)", client_id, raw);

        for (size_t i = 0; i < attachments.size(); i++) {
            const auto& a = attachments[i];
            c.prepared_exec(
                    R"(
                INSERT INTO message_attachments
                    (message, idx, path, content_type, filename, caption, flags, width, height)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            )",
                    client_id,
                    static_cast<int64_t>(i),
                    a.path.string(),
                    a.content_type,
                    a.filename ? a.filename : std::optional{a.path.filename().string()},
                    a.caption,
                    a.voice_message ? ATTACHMENT_FLAG_VOICE_MESSAGE : 0,
                    a.width ? std::optional<int64_t>{*a.width} : std::nullopt,
                    a.height ? std::optional<int64_t>{*a.height} : std::nullopt);
        }

        tx.commit();
    }

    if (created)
        _emit_conversation_added(id);
    _emit_message(true, id, client_id);
    _touch(id);

    log::debug(
            cat,
            "send_message: message {} to conversation {} with {} attachment(s)",
            client_id,
            id.to_string(),
            attachments.size());

    _upload_next(client_id, std::move(on_upload));
    return client_id;
}

void Client::_upload_next(
        int64_t client_id,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload) {
    std::optional<std::tuple<int64_t, std::string>> next;
    {
        auto c = core.database().conn();
        next = c.prepared_maybe_get<int64_t, std::string>(
                R"(
            SELECT idx, path FROM message_attachments
            WHERE message = ? AND url IS NULL
            ORDER BY idx LIMIT 1
        )",
                client_id);
    }

    // Nothing left without a url means every file is up, and the message can finally be built.
    if (!next)
        return _finish_attachment_send(client_id);

    auto [idx, path] = *next;
    auto index = static_cast<size_t>(idx);

    // Checked here rather than only at send_message, because that check is on the other side of
    // however long the message sat waiting: a file present when it was attached can be gone by the
    // time its turn comes, and a message resumed in a later run may have been waiting for days.
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        log::warning(
                cat,
                "Attachment {} of message {} is gone ({}); the message cannot be sent",
                idx,
                client_id,
                path);
        if (on_upload)
            on_upload(index, 0, 0, ATTACHMENT_FILE_MISSING);
        return _fail_attachment_send(client_id, /*permanent=*/true);
    }

    auto net = core.network();
    if (!net) {
        log::warning(
                cat,
                "Cannot upload attachment {} of message {}: no network is attached",
                idx,
                client_id);
        if (on_upload)
            on_upload(index, 0, 0, network::ERROR_NO_TRANSPORT_LAYER);
        return _fail_attachment_send(client_id);
    }

    network::FileUploadRequest req;
    req.file = path;
    req.domain = attachment::Domain::ATTACHMENT;
    // The limit this guards is the one onion requests impose, and an attachment goes to the file
    // server rather than through them; the server enforces its own.
    req.allow_large = true;
    req.request_timeout = ATTACHMENT_REQUEST_TIMEOUT;
    req.overall_timeout = ATTACHMENT_OVERALL_TIMEOUT;

    if (on_upload)
        req.on_progress = [index, on_upload](int64_t sent, int64_t total) {
            on_upload(index, sent, total, std::nullopt);
        };

    req.on_complete =
            [this, client_id, index, on_upload](
                    std::variant<std::pair<network::file_metadata, cleared_b32>, int16_t> result,
                    bool /*timeout*/) {
                // Delivered on the network's loop; everything below touches the database, which is
                // Core's loop's alone.
                _dispatch([this, client_id, index, on_upload, result = std::move(result)] {
                    if (auto* err = std::get_if<int16_t>(&result)) {
                        log::warning(
                                cat,
                                "Upload of attachment {} of message {} failed: {}",
                                index,
                                client_id,
                                *err);
                        if (on_upload)
                            on_upload(index, 0, 0, *err);
                        return _fail_attachment_send(client_id);
                    }

                    const auto& [meta, key] = std::get<0>(result);
                    auto url = network::file_server::generate_download_url(
                            meta.id, core.network()->file_server_config);

                    {
                        auto c = core.database().conn();
                        c.prepared_exec(
                                "UPDATE message_attachments SET url = ?, key = ?, size = ?"
                                " WHERE message = ? AND idx = ?",
                                url,
                                std::span<const std::byte>{key},
                                meta.size,
                                client_id,
                                static_cast<int64_t>(index));
                    }

                    log::debug(
                            cat,
                            "Uploaded attachment {} of message {} ({} bytes) to {}",
                            index,
                            client_id,
                            meta.size,
                            url);

                    if (on_upload)
                        on_upload(index, meta.size, meta.size, 0);

                    _upload_next(client_id, on_upload);
                });
            };

    log::debug(cat, "Uploading attachment {} of message {}: {}", idx, client_id, path);
    // Bound to a name: the accessor's span is deliberately unavailable on a temporary.
    auto seed_access = core.globals.account_seed();
    net->upload_file(std::move(req), seed_access.seed());
}

bool Client::_retry_send(
        int64_t client_id,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload) {
    std::optional<ConversationId> convo_id;
    bool has_uploads_left;
    {
        auto c = core.database().conn();

        auto row = c.prepared_maybe_get<int64_t, int, std::optional<int>>(
                "SELECT conversation, outgoing, send_state FROM messages WHERE id = ?", client_id);
        if (!row) {
            log::warning(cat, "Cannot retry message {}: it does not exist", client_id);
            return false;
        }
        auto [convo_row, outgoing, state] = *row;

        // Only a send of ours can be retried, and only one that is over: retrying something still
        // in flight would double it up on the swarm rather than rescue it.
        if (!outgoing || !state) {
            log::warning(cat, "Cannot retry message {}: it is not an outgoing send", client_id);
            return false;
        }
        auto send_state = static_cast<SendState>(*state);
        if (send_state != SendState::failed && send_state != SendState::interrupted) {
            log::warning(
                    cat,
                    "Cannot retry message {}: it is in state {}, which is not a failure to retry",
                    client_id,
                    *state);
            return false;
        }

        convo_id = conversation_id_at(c, convo_row);

        has_uploads_left = c.prepared_get<int64_t>(
                                   "SELECT COUNT(*) FROM message_attachments WHERE message = ? AND "
                                   "url IS NULL",
                                   client_id) > 0;

        // Only worth saying while there is uploading left to do; otherwise the message goes
        // straight back to a send, and _finish_attachment_send sets that state itself.
        if (has_uploads_left)
            c.prepared_exec(
                    "UPDATE messages SET send_state = ?, sync_send_state ="
                    " CASE WHEN sync_send_state IS NULL THEN NULL ELSE ? END WHERE id = ?",
                    static_cast<int>(SendState::uploading),
                    static_cast<int>(SendState::uploading),
                    client_id);
    }

    if (has_uploads_left)
        _emit_message(false, *convo_id, client_id);

    log::debug(
            cat,
            "Retrying message {}{}",
            client_id,
            has_uploads_left ? " (attachments still to upload)" : "");

    // Resumes wherever it was left: _upload_next takes the first attachment with no url, so the
    // ones that already got up are not sent again, and a message needing none goes straight to
    // being dispatched.
    _upload_next(client_id, std::move(on_upload));
    return true;
}

void Client::_finish_attachment_send(int64_t client_id) {
    auto self = core.globals.session_id();

    // Rebuilt from the database rather than from what send_message was handed, so that a message
    // whose uploads finished can be completed by anything that finds it -- a retry, or a later run.
    std::optional<ConversationId> convo_id;
    std::string body;
    int64_t timestamp = 0;
    SessionProtos::Content content;

    {
        auto c = core.database().conn();

        auto row = c.prepared_maybe_get<int64_t, std::string, int64_t>(
                "SELECT conversation, body, timestamp FROM messages WHERE id = ?", client_id);
        if (!row) {
            log::warning(cat, "Cannot finish message {}: it is gone", client_id);
            return;
        }
        auto [convo_row, msg_body, msg_ts] = *row;
        convo_id = conversation_id_at(c, convo_row);
        body = std::move(msg_body);
        timestamp = msg_ts;

        content.set_sigtimestamp(static_cast<uint64_t>(timestamp));
        auto* data = content.mutable_datamessage();
        data->set_body(body);
        data->set_timestamp(static_cast<uint64_t>(timestamp));

        for (auto&& [url, key, size, ctype, fname, caption, flags, width, height] :
             c.prepared_results<
                     std::string,
                     sqlite::blobn<32>,
                     int64_t,
                     std::optional<std::string>,
                     std::optional<std::string>,
                     std::optional<std::string>,
                     int,
                     std::optional<int>,
                     std::optional<int>>(
                     R"(
            SELECT url, key, size, content_type, filename, caption, flags, width, height
            FROM message_attachments WHERE message = ? ORDER BY idx
        )",
                     client_id)) {
            auto* attach = data->add_attachments();
            attach->set_url(url);

            // Deprecated in favour of `url`, which is what current clients read, but still required
            // by the protobuf and still read by old ones.  It is the url's last segment, so it is
            // taken back out of the url rather than tracked separately -- and it is only a number
            // for as long as the file server hands out numbers, which it is expected to stop doing.
            uint64_t legacy_id = 0;
            if (auto parsed = network::file_server::parse_download_url(url)) {
                const auto& fid = parsed->file_id;
                if (!fid.empty() &&
                    std::ranges::all_of(fid, [](char ch) { return ch >= '0' && ch <= '9'; })) {
                    auto [_, ec] = std::from_chars(fid.data(), fid.data() + fid.size(), legacy_id);
                    if (ec != std::errc{})
                        legacy_id = 0;
                }
            }
            attach->set_id(legacy_id);

            // `key` views the statement's current row, so it has to be copied out before the loop
            // steps to the next one.
            attach->set_key(reinterpret_cast<const char*>(key.data()), key.size());
            attach->set_size(static_cast<uint32_t>(size));

            if (ctype)
                attach->set_contenttype(*ctype);
            if (fname)
                attach->set_filename(*fname);
            if (caption)
                attach->set_caption(*caption);
            if (flags != 0)
                attach->set_flags(static_cast<uint32_t>(flags));
            if (width)
                attach->set_width(static_cast<uint32_t>(*width));
            if (height)
                attach->set_height(static_cast<uint32_t>(*height));
        }
    }

    bool to_self = std::ranges::equal(convo_id->session_id(), self);

    SessionProtos::Content synced = content;
    synced.mutable_datamessage()->set_synctarget(oxenc::to_hex(convo_id->session_id()));

    // What we store is the sync copy, as the plain send does, and its hash has to be the hash of
    // what we store: it is what the copy coming back off our own swarm dedupes against, and the
    // provisional one written before the uploads describes content nobody will ever send.
    auto serialised = synced.SerializeAsString();
    auto raw = std::span{reinterpret_cast<const std::byte*>(serialised.data()), serialised.size()};
    auto cid = content_hash(self, raw);

    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        c.prepared_exec(
                "UPDATE messages SET content_hash = ?, send_state = ?, sync_send_state = ?"
                " WHERE id = ?",
                cid,
                static_cast<int>(SendState::pending),
                to_self ? std::optional<int>{}
                        : std::optional{static_cast<int>(SendState::pending)},
                client_id);
        c.prepared_exec(
                "UPDATE message_raw_content SET content = ? WHERE message = ?", raw, client_id);
        tx.commit();
    }

    _emit_message(false, *convo_id, client_id);

    _dispatch_sends(
            client_id,
            *convo_id,
            content,
            synced,
            sys_ms{std::chrono::milliseconds{timestamp}},
            to_self);
}

void Client::_fail_attachment_send(int64_t client_id, bool permanent) {
    auto state = static_cast<int>(permanent ? SendState::unsendable : SendState::failed);
    std::optional<ConversationId> convo_id;
    {
        auto c = core.database().conn();
        auto convo = c.prepared_maybe_get<int64_t>(
                "SELECT conversation FROM messages WHERE id = ?", client_id);
        if (!convo)
            return;
        convo_id = conversation_id_at(c, *convo);

        // The rows are left alone: what has already been uploaded stays recorded, which is what
        // makes retrying send only what did not get through.
        c.prepared_exec(
                "UPDATE messages SET send_state = ?, sync_send_state ="
                " CASE WHEN sync_send_state IS NULL THEN NULL ELSE ? END WHERE id = ?",
                state,
                state,
                client_id);
    }

    _emit_message(false, *convo_id, client_id);
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
        _emit_conversation_added(convo_id);
    if (inserted)
        _emit_message(true, convo_id, client_id);
    if (inserted || renamed)
        _touch(convo_id);
}

void Client::_on_send_status(int64_t core_id, core::MessageSendStatus status) {
    if (auto sync = _sync_sends.find(core_id); sync != _sync_sends.end()) {
        log::debug(
                cat, "sync copy of send {} reached status {}", core_id, static_cast<int>(status));
        auto client_id = sync->second;
        if (is_terminal(status))
            _sync_sends.erase(sync);
        _apply_send_status(client_id, status, true);
        return;
    }

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
    _apply_send_status(client_id, status, false);
}

void Client::_apply_send_status(int64_t client_id, core::MessageSendStatus status, bool sync) {
    auto state = state_for(status);
    std::optional<ConversationId> convo;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        // The two sends own one column each, so a status for one never disturbs the other.
        auto column = sync ? "sync_send_state"sv : "send_state"sv;
        if (c.prepared_exec(
                    "UPDATE messages SET {0} = ?1 WHERE id = ?2 AND {0} IS NOT ?1"_format(column),
                    static_cast<int>(state),
                    client_id) > 0) {
            auto convo_row = c.prepared_maybe_get<int64_t>(
                    "SELECT conversation FROM messages WHERE id = ?", client_id);
            if (convo_row)
                convo = conversation_id_at(c, *convo_row);
        }
        tx.commit();
    }

    if (convo)
        _emit_message(false, *convo, client_id);
}

}  // namespace session::client
