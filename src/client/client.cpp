#include <SQLiteCpp/Transaction.h>
#include <SessionProtos.pb.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <oxen/log.hpp>
#include <oxen/quic/loop.hpp>
#include <session/attachments.hpp>
#include <session/client.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/expiring.hpp>
#include <session/config/user_profile.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
#include <session/random.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/network/session_network.hpp>
#include <session/sqlite.hpp>
#include <set>
#include <stdexcept>
#include <tuple>

namespace session::client {

namespace log = oxen::log;
static auto cat = log::Cat("client");

using namespace std::literals;

static int64_t to_ms(sys_ms t) {
    return t.time_since_epoch().count();
}

/// A message identifier: an opaque 64-bit pattern, compared for equality and never ordered or
/// counted.  Signed all the way through -- the protobuf declares it sfixed64 for exactly that
/// reason -- so no conversion is needed anywhere between the wire and the database.
using MsgId = int64_t;

/// A new message's Content.msgId.  Must be generated before the message is copied for its recipient
/// and for our own swarm, so that both copies carry it: it is the only identifier every party
/// agrees on, the two copies differing in syncTarget and so not hashing alike.
static MsgId new_msgid() {
    return static_cast<MsgId>(csrng());
}

/// Reads a message's identifier out of arriving content.  Absent from anything sent by a client
/// that predates the field, which then has no identity beyond its timestamp.
static std::optional<MsgId> msgid_of(const SessionProtos::Content& content) {
    if (!content.has_msgid())
        return std::nullopt;
    return content.msgid();
}

// AttachmentPointer.Flags.VOICE_MESSAGE.  Mirrored rather than taken from the generated header so
// that the column's meaning is legible where it is written.
constexpr int ATTACHMENT_FLAG_VOICE_MESSAGE = 1;

// An attachment is a whole file rather than a swarm request, so it gets its own, longer allowances:
// the per-request one covers a stalled transfer, and the overall one bounds the upload entire.
constexpr auto ATTACHMENT_REQUEST_TIMEOUT = 60s;
constexpr auto ATTACHMENT_OVERALL_TIMEOUT = 10min;

// Rate limits one stream of updates, so that a producer reporting faster than a consumer can
// usefully act on cannot flood it.  `allow()` is true at most once per interval.
//
// One of these belongs to each thing being reported on, never to the reporter: a single instance
// shared between several streams would let whichever of them happened to be first in each window
// squelch the others indefinitely, so a transfer could appear to have stalled while it was in fact
// progressing.
class update_throttle {
    std::chrono::milliseconds _interval;
    std::optional<std::chrono::steady_clock::time_point> _emitted;

  public:
    explicit update_throttle(std::chrono::milliseconds interval) : _interval{interval} {}

    bool allow() {
        if (_interval <= 0ms)
            return true;
        auto now = std::chrono::steady_clock::now();
        if (_emitted && now - *_emitted < _interval)
            return false;
        _emitted = now;
        return true;
    }
};

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

static std::optional<std::string_view> opt_view(const std::optional<std::string>& s) {
    if (s)
        return *s;
    return std::nullopt;
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
    LEFT JOIN contacts ct ON ct.account = a.id
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
                           epoch_seconds(activity),
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

// Makes an account a contact if it is not one already, and says whether that changed anything.
// Must be called inside the caller's transaction.
//
// Anything that records a fact about a relationship needs this first: the fact belongs in the
// Contacts config, and a row here is what an entry there is made from, so there is nowhere to put
// it otherwise.
static bool ensure_contact(sqlite::Connection& c, int64_t account, bool approved) {
    return c.prepared_exec(
                   "INSERT OR IGNORE INTO contacts (account, approved) VALUES (?, ?)",
                   account,
                   approved ? 1 : 0) > 0;
}

// Records that we have approved whoever an outgoing message is addressed to, and says whether that
// changed anything.  Must be called inside the caller's transaction.
//
// Writing to someone is what approving them is -- there is no separate accept -- so answering a
// message request is what takes it out of the requests list.  Never for note to self, which is not
// a contact and cannot be a request.
static bool approve_recipient(
        sqlite::Connection& c, const ConversationId& id, std::span<const std::byte> self) {
    if (std::ranges::equal(id.session_id(), self))
        return false;
    auto account = identity_id(c, id);
    auto made = ensure_contact(c, account, true);
    auto flagged =
            c.prepared_exec(
                    "UPDATE contacts SET approved = 1 WHERE account = ? AND NOT approved", account) >
            0;
    return made || flagged;
}

// Carries out a delete-before instruction, and says whether anything went.  Must be called inside
// the caller's transaction.
//
// The unread count is recomputed rather than decremented by what was deleted: what counts as unread
// is the application's policy and is about to grow (mutes, requests, tombstones), so a second place
// applying it is a second place to get it wrong.
static bool delete_messages_before(sqlite::Connection& c, int64_t convo, sys_ms before) {
    if (c.prepared_exec(
                "DELETE FROM messages WHERE conversation = ?1 AND timestamp < ?2",
                convo,
                to_ms(before)) == 0)
        return false;

    c.prepared_exec(
            R"(
        UPDATE conversations SET unread_count = (
            SELECT COUNT(*) FROM messages m
            WHERE m.conversation = conversations.id AND m.outgoing = 0
              AND m.timestamp > conversations.last_read)
        WHERE id = ?
    )",
            convo);
    return true;
}

// As above for a delete-attachments-before instruction, which takes the files but leaves the
// messages that carried them.  Must be called inside the caller's transaction.
static bool delete_attachments_before(sqlite::Connection& c, int64_t convo, sys_ms before) {
    return c.prepared_exec(
                   R"(
        DELETE FROM message_attachments WHERE message IN
            (SELECT id FROM messages WHERE conversation = ?1 AND timestamp < ?2)
    )",
                   convo,
                   to_ms(before)) > 0;
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

core::callbacks Client::_core_callbacks() {
    // Capturing `this` here is safe despite running in Core's member-init list: every callback we
    // install can only fire from receive_messages(), send_dm(), or a config merge, none of which
    // Core calls during its own construction.
    //
    // These are Client's own wiring, and an application cannot supply any of its own: what it is
    // promised is `client::callbacks`, which is reported through the dispatcher and carries whole
    // state.  Anything it needs that only Core knows is reported by handling it here and
    // re-reporting it there.
    core::callbacks cb;

    // Persist first, then notify: a throwing callback is a bug Core can only log, so Client must
    // never rely on an exception to reject a batch.
    cb.message_received = [this](core::ReceivedMessage&& msg) {
        _on_message_received(std::move(msg));
    };

    cb.message_send_status = [this](int64_t id,
                                    core::MessageSendStatus status,
                                    std::optional<std::string_view> swarm_hash) {
        _on_send_status(id, status, swarm_hash);
    };

    cb.configs_changed = [this](std::span<const config::Namespace> changed) {
        _on_configs_changed(changed);
    };

    return cb;
}

void Client::_init() {
    _jobs.reset(new oxen::quic::JobQueue{loop});

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
    c.prepared_exec(
            R"(
        UPDATE messages SET sync_send_state = ? WHERE sync_send_state IN (?, ?)
    )",
            static_cast<int>(SendState::interrupted),
            static_cast<int>(SendState::pending),
            static_cast<int>(SendState::sending));

    // A message whose attachments were still uploading is not in that same doubt: nothing can have
    // reached a swarm, because the message could not be built until the uploads finished.  So it
    // failed outright rather than unknowably, and it is squarely retryable -- its attachment rows
    // record which files did get up, so resuming re-uploads only the rest.
    c.prepared_exec(
            "UPDATE messages SET send_state = ? WHERE send_state = ?",
            static_cast<int>(SendState::failed),
            static_cast<int>(SendState::uploading));
    c.prepared_exec(
            "UPDATE messages SET sync_send_state = ? WHERE sync_send_state = ?",
            static_cast<int>(SendState::failed),
            static_cast<int>(SendState::uploading));

    // Guarded because a Core opened with defer_account has no account yet, and the configs are
    // encrypted to its key.  Nothing is missed by skipping it: an account that does not exist has
    // no configs to have fallen behind, and whatever arrives once it does comes through a merge,
    // which reports itself.
    if (core.globals.have_account())
        _reconcile_all();
}

// -- Change notification ----------------------------------------------------------------------

void Client::_emit(std::function<void(const callbacks&)> invoke) {
    _dispatch_out([cbs = _cbs, invoke = std::move(invoke)] { invoke(*cbs); });
}

void Client::set_dispatcher(dispatcher d) {
    loop.call([this, d = std::move(d)]() mutable { _dispatcher = std::move(d); });
}

void Client::set_high_freq_dispatch_interval(std::chrono::milliseconds interval) {
    loop.call([this, interval] { _high_freq_dispatch_interval = interval; });
}

void Client::_dispatch_out(std::function<void()> job) {
    auto guarded = [job = std::move(job)] {
        try {
            job();
        } catch (const std::exception& e) {
            log::error(cat, "client handler threw: {}", e.what());
        }
    };

    if (_dispatcher)
        _dispatcher(std::move(guarded));
    else
        guarded();
}

void Client::_emit_conversation_added(const ConversationId& id) {
    auto convo = _conversation(id);
    if (!convo)
        return;
    _emit([convo = std::move(*convo)](const callbacks& cbs) {
        if (cbs.conversation_added)
            cbs.conversation_added(convo);
    });
}

void Client::_emit_conversation_removed(const ConversationId& id) {
    _emit([id](const callbacks& cbs) {
        if (cbs.conversation_removed)
            cbs.conversation_removed(id);
    });
}

void Client::_emit_history_replaced(const ConversationId& id) {
    _emit([id](const callbacks& cbs) {
        if (cbs.history_replaced)
            cbs.history_replaced(id);
    });
}

void Client::_emit_message(bool added, const ConversationId& id, int64_t message_id) {
    auto msg = _message(message_id);
    if (!msg)
        return;
    _emit([added, id, msg = std::move(*msg)](const callbacks& cbs) {
        const auto& h = added ? cbs.message_added : cbs.message_updated;
        if (h)
            h(id, msg);
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
        _emit([convo = std::move(*convo)](const callbacks& cbs) {
            if (cbs.conversation_updated)
                cbs.conversation_updated(convo);
        });
    }
}

// -- Asynchronous interface ---------------------------------------------------------------------

// Checked on the calling thread so that an unreadable file throws where the mistake was made,
// rather than failing a message that has already been stored and shown.
void Client::_require_readable(const std::vector<OutgoingAttachment>& attachments) {
    for (const auto& a : attachments) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(a.path, ec) || ec)
            throw std::invalid_argument{
                    "send_message: attachment {} is not a readable file"_format(a.path.string())};
        if (std::filesystem::file_size(a.path, ec) == 0 || ec)
            throw std::invalid_argument{
                    "send_message: attachment {} is empty"_format(a.path.string())};
    }
}

void Client::_require_dm(std::string_view op, const ConversationId& id) {
    // Checked on the calling thread so caller error surfaces at the call site rather than inside
    // the loop, where the callback form would only be able to log it.
    if (id.type() != ConversationId::Type::dm)
        throw std::invalid_argument{
                "{}: only DM conversations are supported so far (got type {})"_format(
                        op, static_cast<int>(id.type()))};
}

void Client::_require_contact(std::string_view op, const ConversationId& id) {
    _require_dm(op, id);
    // Our own account is not a contact of ours -- there is no entry to block or to remove, and
    // what note to self does have lives in UserProfile.
    if (is_note_to_self(id))
        throw std::invalid_argument{"{}: not applicable to your own account"_format(op)};
}

void Client::log_operation_failure(const std::exception& e) {
    log::error(cat, "Client operation failed: {}", e.what());
}

// Not dispatched onto the loop: reads nothing but the session ID, which cannot change underneath
// it.  See the declaration.
bool Client::is_note_to_self(const ConversationId& id) {
    return id.type() == ConversationId::Type::dm &&
           std::ranges::equal(id.session_id(), _self_or_none());
}

void Client::retry_send(
        int64_t message_id,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload,
        std::function<void(std::optional<std::string>, bool)> cb) {
    _async(
            [this, message_id, on_upload = std::move(on_upload)] {
                return _retry_send(message_id, on_upload);
            },
            std::move(cb));
}

void Client::send_message(
        const ConversationId& id,
        std::string_view body,
        std::vector<OutgoingAttachment> attachments,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload,
        std::function<void(std::optional<std::string>, int64_t)> cb) {
    _require_dm("send_message", id);
    _require_readable(attachments);

    _async([this,
            id,
            body = std::string{body},
            attachments = std::move(attachments),
            on_upload = std::move(
                    on_upload)] { return _send_message(id, body, attachments, on_upload); },
           std::move(cb));
}

// Callback forms: dispatch and return, delivering the result on the loop thread.

void Client::conversations(
        std::function<void(std::optional<std::string>, std::vector<AnyConversation>)> cb) {
    _async([this] { return _conversations(); }, std::move(cb));
}

void Client::message_requests(
        std::function<void(std::optional<std::string>, std::vector<AnyConversation>)> cb) {
    _async([this] { return _message_requests(); }, std::move(cb));
}

void Client::conversation(
        const ConversationId& id,
        std::function<void(std::optional<std::string>, std::optional<AnyConversation>)> cb) {
    _async([this, id] { return _conversation(id); }, std::move(cb));
}

void Client::create_conversation(
        const ConversationId& id,
        std::function<void(std::optional<std::string>, std::optional<AnyConversation>)> cb) {
    _require_dm("create_conversation", id);
    _async([this, id] { return std::optional{_create_conversation(id)}; }, std::move(cb));
}

void Client::mark_read(
        const ConversationId& id, std::function<void(std::optional<std::string>)> cb) {
    mark_read(id, std::nullopt, std::move(cb));
}

void Client::mark_read(
        const ConversationId& id,
        std::optional<sys_ms> up_to,
        std::function<void(std::optional<std::string>)> cb) {
    _async([this, id, up_to] { _mark_read(id, up_to); }, std::move(cb));
}

void Client::set_priority(
        const ConversationId& id,
        int priority,
        std::function<void(std::optional<std::string>)> cb) {
    _async([this, id, priority] { _set_priority(id, priority); }, std::move(cb));
}

void Client::set_marked_unread(
        const ConversationId& id,
        bool unread,
        std::function<void(std::optional<std::string>)> cb) {
    _async([this, id, unread] { _set_marked_unread(id, unread); }, std::move(cb));
}

void Client::set_blocked(
        const ConversationId& id,
        bool blocked,
        std::function<void(std::optional<std::string>)> cb) {
    _require_contact("set_blocked", id);
    _async([this, id, blocked] { _set_blocked(id, blocked); }, std::move(cb));
}

void Client::clear_messages(
        const ConversationId& id, std::function<void(std::optional<std::string>)> cb) {
    _require_dm("clear_messages", id);
    _async([this, id] { _clear_messages(id); }, std::move(cb));
}

void Client::delete_conversation(
        const ConversationId& id, std::function<void(std::optional<std::string>)> cb) {
    delete_conversation(id, false, std::move(cb));
}

void Client::delete_conversation(
        const ConversationId& id,
        bool keep_messages,
        std::function<void(std::optional<std::string>)> cb) {
    _require_dm("delete_conversation", id);
    _async([this, id, keep_messages] { _delete_conversation(id, keep_messages); }, std::move(cb));
}

void Client::delete_contact(
        const ConversationId& id, std::function<void(std::optional<std::string>)> cb) {
    _require_contact("delete_contact", id);
    _async([this, id] { _delete_contact(id); }, std::move(cb));
}

void Client::messages(
        const ConversationId& id,
        std::function<void(std::optional<std::string>, std::vector<Message>)> cb) {
    messages(id, 50, std::nullopt, std::move(cb));
}

void Client::messages(
        const ConversationId& id,
        int limit,
        std::function<void(std::optional<std::string>, std::vector<Message>)> cb) {
    messages(id, limit, std::nullopt, std::move(cb));
}

void Client::messages(
        const ConversationId& id,
        int limit,
        std::optional<MessageCursor> before,
        std::function<void(std::optional<std::string>, std::vector<Message>)> cb) {
    _async([this, id, limit, before] { return _messages(id, limit, before); }, std::move(cb));
}

void Client::message(
        int64_t id, std::function<void(std::optional<std::string>, std::optional<Message>)> cb) {
    _async([this, id] { return _message(id); }, std::move(cb));
}

void Client::send_message(
        const ConversationId& id,
        std::string_view body,
        std::function<void(std::optional<std::string>, int64_t)> cb) {
    _require_dm("send_message", id);
    _async([this, id, body = std::string{body}] { return _send_message(id, body); }, std::move(cb));
}

void Client::save_attachment(
        int64_t message_id,
        size_t index,
        std::filesystem::path dest,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_progress,
        failable_function<void()> cb,
        bool notify_sender) {

    // Checked on the calling thread so a caller's own mistake surfaces at the call site, where they
    // still have a stack to make sense of it.
    if (std::filesystem::is_directory(dest))
        throw std::invalid_argument{
                "save_attachment: {} is a directory"_format(dest.string())};
    if (auto dir = dest.parent_path(); !dir.empty() && !std::filesystem::is_directory(dir))
        throw std::invalid_argument{
                "save_attachment: {} does not exist"_format(dir.string())};

    // Not _async: what that reports is the *start* of the transfer, and the answer a caller wants
    // is whether the file arrived, which is minutes away.  So the callback is carried down to the
    // download's own completion, and only the failures that happen before it starts come back here.
    loop.call([this,
               message_id,
               index,
               dest = std::move(dest),
               on_progress = std::move(on_progress),
               cb,
               notify_sender]() mutable {
        try {
            _save_attachment(
                    message_id, index, std::move(dest), std::move(on_progress), cb, notify_sender);
        } catch (const std::exception& e) {
            log_operation_failure(e);
            _report(cb, std::optional{std::string{e.what()}});
        }
    });
}

// -- Conversations ----------------------------------------------------------------------------

// Only a DM has a name source so far; groups and communities gain one with the features.
static const auto CONVO_COLUMNS = R"(
    SELECT c.id, a.session_id, g.group_id, m.base_url, m.room,
           -- A nickname is ours for them and wins over the name they chose for themselves; falling
           -- back means an account we have seen but never made a contact of still has a name.
           coalesce(ct.nickname, a.name), c.last_activity,
           coalesce((SELECT b.body FROM messages b WHERE b.conversation = c.id
                      ORDER BY b.timestamp DESC, b.id DESC LIMIT 1), ''),
           c.unread_count, c.priority, coalesce(ct.approved, 0), coalesce(ct.approved_me, 0),
           c.marked_unread
    {}
)"_format(SUBJECT_JOIN);

// Which conversations are message requests, as a fragment both list queries need: a DM with someone
// we have never written to.  No entry at all counts, which is the usual case -- a stranger's first
// message creates the row that says they have approved us and nothing that says we approved them.
//
// Note to self is exempt because it cannot be a request; we are not our own contact, and the entry
// that would carry the approval is one that has no business existing.
static constexpr auto IS_REQUEST =
        "(c.dm IS NOT NULL AND coalesce(ct.approved, 0) = 0 AND a.session_id IS NOT ?1)"sv;

// `self` is our own session ID, for flagging the Note to Self conversation; it is not part of the
// query because the row does not know whose database it is in.  Empty when there is no account
// yet, under which circumstance nothing can be a conversation with ourselves.
template <typename... Bind>
static std::vector<AnyConversation> query_conversations(
        sqlite::Connection& c,
        std::span<const std::byte> self,
        const std::string& query,
        const Bind&... bind) {
    std::vector<AnyConversation> out;
    for (auto [convo, sid, gid, url, room, name, activity, preview, unread, priority, approved,
               approved_me, marked_unread] :
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
                 int,
                 int,
                 int,
                 int>(query, bind...)) {
        Conversation base{
                .id = subject_to_id(convo, sid, gid, url, room),
                .display_name = name.value_or(""),
                .last_message = std::move(preview),
                .last_activity = from_epoch_ms(activity),
                .unread = unread,
                .marked_unread = marked_unread != 0,
                .priority = priority};

        // The same branch that decided which identity the row joined to decides which kind it is:
        // exactly one of them is set, which is what the table's CHECK constraint enforces.
        if (gid)
            out.push_back(Group{std::move(base)});
        else if (url && room)
            out.push_back(Community{std::move(base)});
        else {
            bool me = std::ranges::equal(static_cast<const b33&>(*sid), self);
            DM dm{std::move(base)};
            dm.request = !me && !approved;
            dm.awaiting_approval = !me && !approved_me;
            dm.note_to_self = me;
            out.push_back(std::move(dm));
        }
    }
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

std::vector<AnyConversation> Client::_conversations() {
    auto c = core.database().conn();
    auto self = _self_or_none();
    return query_conversations(
            c,
            self,
            // Hidden (negative priority) conversations are not part of the list at all; pinned ones
            // lead it, and equal priorities form a block that sorts among itself by recency.
            "{} WHERE c.priority >= 0 AND NOT {} ORDER BY c.priority DESC, c.last_activity DESC, c.id"_format(
                    CONVO_COLUMNS, IS_REQUEST),
            self);
}

std::vector<AnyConversation> Client::_message_requests() {
    auto c = core.database().conn();
    auto self = _self_or_none();
    // No priority ordering: a request cannot be pinned -- pinning is a property of the config entry
    // and there is nothing there to pin until it is approved -- so recency is the only order there
    // is.  Hidden ones are still omitted, since hiding is the one thing another device *can* say
    // about a request it does not want to see.
    return query_conversations(
            c,
            self,
            "{} WHERE c.priority >= 0 AND {} ORDER BY c.last_activity DESC, c.id"_format(
                    CONVO_COLUMNS, IS_REQUEST),
            self);
}

std::optional<AnyConversation> Client::_conversation(const ConversationId& id) {
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

AnyConversation Client::_create_conversation(const ConversationId& id) {
    bool created, contacted = false;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        created = ensure_conversation(c, id, clock_now_ms()).created;

        // Opening a conversation with someone makes them an approved contact: choosing to write to
        // them is what approving them is.  It is also the only way the conversation can be synced
        // at all, since everything a one-to-one conversation carries lives in that entry.
        //
        // Deliberately not what an incoming message from a stranger does -- that is a message
        // request, and stays one until we answer it.
        if (id.type() == ConversationId::Type::dm && !is_note_to_self(id))
            contacted = ensure_contact(c, identity_id(c, id), true);
        tx.commit();
    }
    if (created || contacted)
        _sync_conversation(id);
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

        // Reading a conversation undoes having marked it unread, which is the only thing that
        // could still be holding it bold.  Separate from the watermark because it survives having
        // read everything, so moving the watermark cannot clear it as a side effect.
        changed += c.prepared_exec(
                "UPDATE conversations SET marked_unread = 0 WHERE id = ? AND marked_unread",
                *convo);
        tx.commit();
    }
    if (changed > 0) {
        _sync_convo_volatile(id);
        _touch(id);
    }
}

void Client::_set_marked_unread(const ConversationId& id, bool unread) {
    int changed = 0;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = find_conversation(c, id);
        if (!convo)
            return;

        changed = c.prepared_exec(
                "UPDATE conversations SET marked_unread = ?2"
                " WHERE id = ?1 AND marked_unread IS NOT ?2",
                *convo,
                unread ? 1 : 0);
        tx.commit();
    }
    if (changed > 0) {
        _sync_convo_volatile(id);
        _touch(id);
    }
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

    if (changed > 0) {
        _sync_conversation(id);
        _emit_lists_replaced();
    }
}

void Client::_set_blocked(const ConversationId& id, bool blocked) {
    bool changed = false;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        auto account = identity_id(c, id);

        // Blocking someone we have never made a contact of is the ordinary case rather than the
        // exception -- a message request is exactly that -- so the row is created rather than
        // required.  Not approved by it: refusing someone's messages is not accepting them.
        changed = ensure_contact(c, account, false);
        changed |= c.prepared_exec(
                           "UPDATE contacts SET blocked = ?2"
                           " WHERE account = ?1 AND blocked IS NOT ?2",
                           account,
                           blocked ? 1 : 0) > 0;
        tx.commit();
    }

    if (!changed)
        return;
    _sync_contact(id);
    _touch(id);
}

void Client::_clear_messages(const ConversationId& id) {
    auto now = clock_now_ms();
    bool emptied = false;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = find_conversation(c, id);
        if (!convo)
            return;

        emptied = delete_messages_before(c, *convo, now);
        tx.commit();
    }

    // Published whether or not this device had anything to delete: the instruction is about what
    // every device holds, and finding none here says nothing about the rest.
    _set_delete_before(id, now);

    if (emptied) {
        _emit_history_replaced(id);
        _touch(id);
    }
}

void Client::_delete_conversation(const ConversationId& id, bool keep_messages) {
    auto now = clock_now_ms();
    bool emptied = false, hidden = false;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = find_conversation(c, id);
        if (!convo)
            return;

        if (!keep_messages)
            emptied = delete_messages_before(c, *convo, now);

        // Hidden rather than deleted, and that is the whole difference from delete_contact: what
        // says the conversation exists is the config entry, which stays, so removing the row would
        // only have it reinstated by the next reconciliation.  A pinned conversation loses its pin
        // along the way, which is why this is not conditional on the priority being 0.
        hidden = c.prepared_exec(
                         "UPDATE conversations SET priority = -1 WHERE id = ? AND priority >= 0",
                         *convo) > 0;
        tx.commit();
    }

    if (!keep_messages)
        _set_delete_before(id, now);
    _sync_conversation(id);

    if (emptied)
        _emit_history_replaced(id);
    if (hidden)
        _emit_lists_replaced();
}

void Client::_delete_contact(const ConversationId& id) {
    bool removed = false;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto account = c.prepared_maybe_get<int64_t>(
                "SELECT id FROM accounts WHERE session_id = ?", id.session_id());
        if (!account)
            return;

        // The nickname, both approvals and the block are columns of the row being deleted, so
        // there is nothing to reset first: they exist only for as long as the relationship does.
        c.prepared_exec("DELETE FROM contacts WHERE account = ?", *account);

        // Messages, their raw content and their attachments follow the conversation by cascade;
        // the files those attachments name belong to the user and are not unlinked.  The account
        // row stays -- see _reconcile_contacts, which deletes the same way for the same reasons.
        removed = c.prepared_exec("DELETE FROM conversations WHERE dm = ?", *account) > 0;
        tx.commit();
    }

    // No delete-before instruction here, and none is owed: the entry going from the config is
    // itself the instruction, and a device merging that removes the conversation and its history.
    _sync_contact(id);

    if (removed) {
        _emit_conversation_removed(id);
        _emit_lists_replaced();
    }
}

void Client::_set_delete_before(const ConversationId& id, sys_ms before) {
    // The configs carry seconds.  Truncating rather than rounding is what keeps the instruction
    // from reaching a message sent just after it: this device has already deleted to the
    // millisecond, so the others delete the same set less any straggler within the same second.
    auto secs = std::chrono::floor<std::chrono::seconds>(before);

    // Never backwards, in either config: an instruction to destroy history is not something a
    // later but smaller value is entitled to take back.
    if (is_note_to_self(id)) {
        auto& profile = core.configs.user_profile();
        if (profile.get_nts_delete_before() < secs)
            profile.set_nts_delete_before(secs);
        return;
    }

    auto& contacts = core.configs.contacts();
    auto entry = contacts.get(oxenc::to_hex(id.session_id()));
    if (!entry || entry->delete_before >= secs)
        return;
    entry->delete_before = secs;
    contacts.set(*entry);
}

// Both lists, always, and deliberately not one or the other: what moves a conversation between them
// is approval, what removes it from either is hiding or deletion, and a caller that had to work out
// which of those it just did would eventually get it wrong.  A replacement is idempotent, so the
// cost of sending one nobody needed is a query.
void Client::_emit_lists_replaced() {
    auto convos = _conversations();
    auto requests = _message_requests();
    _emit([convos = std::move(convos), requests = std::move(requests)](const callbacks& cbs) {
        if (cbs.conversation_list_replaced)
            cbs.conversation_list_replaced(convos);
        if (cbs.request_list_replaced)
            cbs.request_list_replaced(requests);
    });
}

// -- Config reconciliation ----------------------------------------------------------------------

void Client::_on_configs_changed(std::span<const config::Namespace> changed) {
    bool conversations_moved = false;
    for (auto ns : changed) {
        switch (ns) {
            case config::Namespace::UserProfile:
                _reconcile_user_profile();
                conversations_moved = true;
                break;
            case config::Namespace::Contacts:
                _reconcile_contacts();
                conversations_moved = true;
                break;
            default: break;  // The rest land with the configs that model them.
        }
    }

    // Last, and also whenever anything above may have created a conversation: read state is about
    // conversations rather than a statement that they exist, so an entry for one we do not have is
    // skipped -- and the config that would have created it may only just have been applied.
    if (conversations_moved ||
        std::ranges::find(changed, config::Namespace::ConvoInfoVolatile) != changed.end())
        _reconcile_convo_volatile();
}

void Client::_reconcile_all() {
    // Outward before inward, and the order is load-bearing: reconciling inward can delete a contact
    // the config does not mention, and a row whose dump was never written looks exactly like one
    // deleted elsewhere.  Publishing what we hold first tells those two apart.
    _sync_all_contacts();
    _sync_all_convo_volatile();

    // Each config joins this as it gains a reconciler; the sweep is what makes adding one apply to
    // state that arrived before it existed, rather than only to the next change after it.
    _reconcile_user_profile();
    _reconcile_contacts();

    // After the two above, which are what bring conversations into being.
    _reconcile_convo_volatile();
}

void Client::_reconcile_contacts() {
    auto& contacts = core.configs.contacts();
    auto me = core.globals.session_id();

    std::vector<ConversationId> touched;
    std::vector<ConversationId> added;
    std::vector<ConversationId> removed;
    std::vector<ConversationId> cleared;
    bool order_changed = false, requests_changed = false;

    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        // Ordered rather than a vector because the deletion pass below looks every stored contact up
        // in it: scanning instead would make a routine merge quadratic in the size of the contact
        // list, which is exactly the size that is allowed to be large.
        std::set<b33> in_config;

        for (const auto& entry : contacts) {
            // Our own entry has no business being here -- our profile is UserProfile's, and we are
            // not our own contact -- but another client may have written one, so it is skipped
            // rather than trusted.
            auto raw = oxenc::from_hex(entry.session_id);
            if (raw.size() != 33)
                continue;
            b33 sid;
            std::memcpy(sid.data(), raw.data(), 33);
            if (std::ranges::equal(sid, me))
                continue;

            in_config.insert(sid);

            auto id = ConversationId::dm(sid);
            auto account = identity_id(c, id);

            std::optional<std::string> pic_url;
            std::optional<std::span<const std::byte>> pic_key;
            if (!entry.profile_picture.empty()) {
                pic_url = entry.profile_picture.url;
                pic_key = std::span<const std::byte>{
                        entry.profile_picture.key.data(), entry.profile_picture.key.size()};
            }

            // Only when the config's stamp is at least as new as ours: a name observed from a
            // message that arrived late must not displace a newer one.
            bool renamed = false;
            if (epoch_seconds(entry.profile_updated) >=
                c.prepared_get<int64_t>("SELECT profile_updated FROM accounts WHERE id = ?", account))
                renamed = c.prepared_exec(
                                  R"(
UPDATE accounts SET name = ?2, profile_pic_url = ?3, profile_pic_key = ?4, profile_updated = ?5
WHERE id = ?1
  AND (name, profile_pic_url, profile_pic_key, profile_updated) IS NOT (?2, ?3, ?4, ?5)
)",
                                  account,
                                  entry.name.empty() ? std::optional<std::string>{}
                                                     : std::optional<std::string>{entry.name},
                                  pic_url,
                                  pic_key,
                                  epoch_seconds(entry.profile_updated)) > 0;

            // Pro flags are the profile's claim about itself, so they follow the profile.
            c.prepared_exec(
                    "UPDATE accounts SET pro_flags = ?2 WHERE id = ?1 AND pro_flags IS NOT ?2",
                    account,
                    static_cast<int64_t>(entry.profile_flags));

            // Read before the upsert rather than derived from it: what moves a conversation between
            // the two lists is this one column, and the upsert reports only that *something* in the
            // row changed.
            bool was_request =
                    !c.prepared_get<int>(
                            "SELECT coalesce((SELECT approved FROM contacts WHERE account = ?), 0)",
                            account);

            // Existence here *is* being a contact, so this is an upsert rather than an update: the
            // row appearing is the fact being recorded.
            //
            // Approval only ever goes up, in either direction, because neither has a reverse: what
            // sets it is a message having been sent, and no later config can make that not have
            // happened.  Copying the value verbatim would let an un-approval reach us -- other
            // clients clear both flags on their way to deleting a contact, and a device that merged
            // the clearing but not the deletion would otherwise file the conversation back under
            // message requests.
            bool new_contact = c.prepared_exec(
                                       R"(
INSERT INTO contacts (account, nickname, approved, approved_me, blocked) VALUES (?1, ?2, ?3, ?4, ?5)
ON CONFLICT (account) DO UPDATE
    SET nickname = ?2, approved = max(approved, ?3), approved_me = max(approved_me, ?4), blocked = ?5
WHERE (nickname, approved, approved_me, blocked)
   IS NOT (?2, max(approved, ?3), max(approved_me, ?4), ?5)
)",
                                       account,
                                       entry.nickname.empty()
                                               ? std::optional<std::string>{}
                                               : std::optional<std::string>{entry.nickname},
                                       entry.approved ? 1 : 0,
                                       entry.approved_me ? 1 : 0,
                                       entry.blocked ? 1 : 0) > 0;

            // The config saying a contact exists is what brings the conversation into being -- a
            // conversation is not defined by having messages in it, or emptying one would lose it.
            auto convo = find_conversation(c, id);
            bool created = false;
            if (!convo) {
                auto row = ensure_conversation(
                        c,
                        id,
                        entry.created > 0 ? from_epoch_s(entry.created) : clock_now_ms());
                convo = row.id;
                created = row.created;
            }

            auto settings_changed =
                    c.prepared_exec(
                            R"(
UPDATE conversations SET priority = ?2, notifications = ?3, mute_until = ?4, exp_mode = ?5,
                         exp_timer = ?6, created = min(created, ?7)
WHERE id = ?1
  AND (priority, notifications, mute_until, exp_mode, exp_timer, created)
   IS NOT (?2, ?3, ?4, ?5, ?6, min(created, ?7))
)",
                            *convo,
                            entry.priority,
                            static_cast<int>(entry.notifications),
                            entry.mute_until,
                            static_cast<int>(entry.exp_mode),
                            static_cast<int64_t>(entry.exp_timer.count()),
                            entry.created > 0 ? entry.created
                                              : epoch_seconds(clock_now_ms())) > 0;

            // Retroactive by definition: what a delete-before instruction is about is the history
            // that was there when someone chose to destroy it, so it is applied to what we hold and
            // not only to what arrives afterwards.  Idempotent, so re-applying it on every merge
            // costs a lookup and deletes nothing the second time.
            bool history_changed = false;
            if (entry.delete_before > std::chrono::sys_seconds{})
                history_changed = delete_messages_before(c, *convo, sys_ms{entry.delete_before});
            if (entry.delete_attach_before > std::chrono::sys_seconds{})
                history_changed |= delete_attachments_before(
                        c, *convo, sys_ms{entry.delete_attach_before});
            if (history_changed)
                cleared.push_back(id);

            if (created)
                added.push_back(id);
            else if (renamed || new_contact || settings_changed || history_changed)
                touched.push_back(id);
            if (created || settings_changed)
                order_changed = true;
            if (was_request && entry.approved)
                requests_changed = true;
        }

        // A contact we hold that the merged config does not mention was removed on another device,
        // and removing a contact takes the conversation and its history with it -- deliberately:
        // someone who deletes a conversation means it deleted, not hidden on one device.  Merely
        // *hiding* is a negative priority and arrives as an ordinary settings change above, so an
        // absent entry can only mean the stronger thing.
        //
        // The account row stays: we may have seen them in a group or community, and their profile is
        // needed to render that.  What is deleted is the relationship, not the person.
        //
        // Safe because the outward sweep runs first (see _reconcile_all): a contact of ours the
        // config has never heard of gets published rather than reaching here.
        std::vector<ConversationId> doomed;
        for (auto sid : c.prepared_results<sqlite::blob_guts<b33>>(
                     "SELECT a.session_id FROM contacts ct JOIN accounts a ON a.id = ct.account"))
            if (!in_config.count(sid))
                doomed.push_back(ConversationId::dm(sid));

        for (const auto& id : doomed) {
            auto account = c.prepared_get<int64_t>(
                    "SELECT id FROM accounts WHERE session_id = ?", id.session_id());
            c.prepared_exec("DELETE FROM contacts WHERE account = ?", account);

            // Messages, their raw content and their attachments go with the conversation, by
            // cascade.  The files those attachments name are the user's -- theirs to attach, or
            // theirs to have saved -- so nothing is unlinked.
            //
            // That stops being the whole story once attachments are cached: a cached file *is*
            // ours, and cascade will take the row naming it without any of our code running,
            // leaving the file on disk with nothing left pointing at it.  Whatever adds that cache
            // has to collect the paths here, before this delete, rather than trusting the cascade.
            if (c.prepared_exec("DELETE FROM conversations WHERE dm = ?", account) > 0)
                removed.push_back(id);
        }

        tx.commit();
    }

    for (const auto& id : added)
        _emit_conversation_added(id);
    for (const auto& id : cleared)
        _emit_history_replaced(id);
    for (const auto& id : touched)
        _touch(id);
    for (const auto& id : removed)
        _emit_conversation_removed(id);
    if (order_changed || requests_changed || !removed.empty())
        _emit_lists_replaced();
}

void Client::_sync_all_contacts() {
    std::vector<ConversationId> ids;
    {
        auto c = core.database().conn();
        for (auto sid : c.prepared_results<sqlite::blob_guts<b33>>(
                     "SELECT a.session_id FROM contacts ct JOIN accounts a ON a.id = ct.account"))
            ids.push_back(ConversationId::dm(sid));
    }
    // Collected before syncing rather than while iterating: _sync_contact takes its own connection.
    for (const auto& id : ids)
        _sync_contact(id);
}

void Client::_reconcile_convo_volatile() {
    auto& volatiles = core.configs.convo_info_volatile();

    std::vector<ConversationId> touched;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        for (auto it = volatiles.begin_1to1(); it != volatiles.end(); ++it) {
            const auto& entry = *it;

            auto raw = oxenc::from_hex(entry.session_id);
            if (raw.size() != 33)
                continue;
            b33 sid;
            std::memcpy(sid.data(), raw.data(), sid.size());
            auto id = ConversationId::dm(sid);

            // Read state about a conversation we do not have says nothing worth acting on, and
            // acting on it would be wrong: an entry outlives the conversation it describes -- this
            // config is pruned by age rather than by anything noticing a deletion -- so creating
            // one here would resurrect what another device deleted.  Whatever creates the
            // conversation is reconciled first, and this runs again after it.
            auto convo = find_conversation(c, id);
            if (!convo)
                continue;

            // Session Pro lives here rather than with the rest of what we know about an account,
            // and it is about the account rather than the conversation, so it lands on `accounts`.
            // The two halves are meaningless apart: an expiry with no tag cannot be checked.
            std::optional<std::span<const std::byte>> tag;
            std::optional<int64_t> expiry;
            if (entry.pro_revocation_tag && entry.pro_expiry_at > std::chrono::sys_seconds{}) {
                tag = std::span<const std::byte>{*entry.pro_revocation_tag};
                expiry = epoch_seconds(entry.pro_expiry_at);
            }
            bool pro_changed = c.prepared_exec(
                                       R"(
UPDATE accounts SET pro_revocation_tag = ?2, pro_expiry = ?3
WHERE id = ?1 AND (pro_revocation_tag, pro_expiry) IS NOT (?2, ?3)
)",
                                       identity_id(c, id),
                                       tag,
                                       expiry) > 0;

            // Forwards only.  The config does not enforce this -- it lets a value be written
            // backwards on purpose, so that a client can reset one -- and a conflict between two
            // devices at the same seqno resolves by a tie-break that knows nothing about which
            // value is newer.  Left alone, that would make messages someone has read unread again.
            bool read_changed =
                    c.prepared_exec(
                            R"(
UPDATE conversations
SET last_read = ?2,
    unread_count = (SELECT COUNT(*) FROM messages
                     WHERE conversation = ?1 AND outgoing = 0 AND timestamp > ?2)
WHERE id = ?1 AND last_read < ?2
)",
                            *convo,
                            entry.last_read) > 0;

            // The flag is an ordinary setting, though: someone marking a conversation unread on
            // another device is telling us to, and there is no ordering to preserve.
            bool unread_changed = c.prepared_exec(
                                          "UPDATE conversations SET marked_unread = ?2"
                                          " WHERE id = ?1 AND marked_unread IS NOT ?2",
                                          *convo,
                                          entry.unread ? 1 : 0) > 0;

            if (pro_changed || read_changed || unread_changed)
                touched.push_back(id);
        }

        tx.commit();
    }

    // No deletion pass, and there must not be one: entries here are pruned by age -- thirty days
    // unread, forty-five on push -- so an absent one means only that nothing has been read in it
    // lately.  Treating that as a removal the way Contacts does would destroy conversations for
    // having been quiet.

    for (const auto& id : touched)
        _touch(id);
}

void Client::_sync_all_convo_volatile() {
    std::vector<ConversationId> ids;
    {
        auto c = core.database().conn();
        for (auto sid : c.prepared_results<sqlite::blob_guts<b33>>(
                     "SELECT a.session_id FROM conversations c JOIN accounts a ON a.id = c.dm"))
            ids.push_back(ConversationId::dm(sid));
    }
    for (const auto& id : ids)
        _sync_convo_volatile(id);
}

void Client::_sync_convo_volatile(const ConversationId& id) {
    if (id.type() != ConversationId::Type::dm)
        return;  // Groups and communities need UserGroups first.

    auto c = core.database().conn();
    auto row = c.prepared_maybe_get<int64_t, int>(
            R"(
        SELECT last_read, marked_unread FROM conversations
        WHERE dm = (SELECT id FROM accounts WHERE session_id = ?)
    )",
            id.session_id());
    if (!row)
        return;
    auto [last_read, marked_unread] = *row;

    auto& volatiles = core.configs.convo_info_volatile();

    // Built on the entry that is there, which is what keeps the Pro fields alive: they are set from
    // a proof we verified rather than from any row here, so there is nothing to re-derive them from.
    auto entry = volatiles.get_or_construct_1to1(oxenc::to_hex(id.session_id()));

    // Forwards only here too, and for the same reason as the merge: our value can be the stale one,
    // and publishing it would tell every other device to unread what it has read.
    entry.last_read = std::max(entry.last_read, last_read);
    entry.unread = marked_unread != 0;
    volatiles.set(entry);
}

void Client::_sync_conversation(const ConversationId& id) {
    if (id.type() != ConversationId::Type::dm)
        return;  // Groups and communities land with UserGroups.

    if (!is_note_to_self(id))
        return _sync_contact(id);

    auto c = core.database().conn();
    auto priority = c.prepared_maybe_get<int>(
            R"(
        SELECT priority FROM conversations
        WHERE dm = (SELECT id FROM accounts WHERE session_id = ?)
    )",
            id.session_id());

    // No row means there is no note-to-self conversation, which is what a negative priority says
    // in a config that has no entry to be absent -- see _reveal_note_to_self.
    core.configs.user_profile().set_nts_priority(priority.value_or(-1));
}

void Client::_sync_contact(const ConversationId& id) {
    if (id.type() != ConversationId::Type::dm ||
        std::ranges::equal(id.session_id(), core.globals.session_id()))
        return;

    auto& contacts = core.configs.contacts();
    auto hex = oxenc::to_hex(id.session_id());

    auto c = core.database().conn();
    auto row = c.prepared_maybe_get<
            std::optional<std::string>,   // name
            std::optional<std::string>,   // profile_pic_url
            std::optional<sqlite::blob>,  // profile_pic_key
            int64_t,                      // profile_updated
            int64_t,                      // pro_flags
            std::optional<std::string>,   // nickname
            int,                          // approved
            int,                          // approved_me
            int>(                         // blocked
            R"(
        SELECT a.name, a.profile_pic_url, a.profile_pic_key, a.profile_updated, a.pro_flags,
               ct.nickname, ct.approved, ct.approved_me, ct.blocked
        FROM accounts a JOIN contacts ct ON ct.account = a.id
        WHERE a.session_id = ?
    )",
            id.session_id());

    // No contacts row means this account is not a contact, so the config should not say it is.
    // Presence following the row is what makes removing a contact just "delete the row and sync",
    // rather than a second place that has to remember to erase the entry too.
    if (!row) {
        contacts.erase(hex);
        return;
    }

    auto [name, pic_url, pic_key, profile_updated, pro_flags, nickname, approved, approved_me,
          blocked] = *row;

    auto convo = c.prepared_maybe_get<int, int, int64_t, int, int64_t, int64_t>(
            R"(
        SELECT priority, notifications, mute_until, exp_mode, exp_timer, created
        FROM conversations WHERE dm = (SELECT id FROM accounts WHERE session_id = ?)
    )",
            id.session_id());

    // Built on top of whatever entry is already there, which is also how the delete-before
    // instruction survives this: no row holds it -- it is an instruction about history rather than
    // a property of the contact -- so there is nothing here to re-derive it from, and overwriting
    // the entry wholesale would quietly revoke it.
    auto entry = contacts.get_or_construct(hex);

    entry.set_name(name.value_or(""));
    entry.set_nickname(nickname.value_or(""));
    if (pic_url && pic_key)
        entry.profile_picture = {*pic_url, *pic_key};
    else
        entry.profile_picture.clear();
    entry.profile_updated = as_sys_seconds(profile_updated);
    entry.profile_flags = static_cast<ProProfileFlags>(pro_flags);
    entry.approved = approved != 0;
    entry.approved_me = approved_me != 0;
    entry.blocked = blocked != 0;

    if (convo) {
        auto [priority, notifications, mute_until, exp_mode, exp_timer, created] = *convo;
        entry.priority = priority;
        entry.notifications = static_cast<config::notify_mode>(notifications);
        entry.mute_until = mute_until;
        entry.exp_mode = static_cast<config::expiration_mode>(exp_mode);
        entry.exp_timer = std::chrono::seconds{exp_timer};
        // The earliest anyone knows about wins, so that two devices disagreeing about when a
        // conversation began settle on the earlier rather than alternating.
        entry.created = entry.created > 0 ? std::min(entry.created, created) : created;
    }

    contacts.set(entry);
}

void Client::_reveal_note_to_self(const ConversationId& id) {
    if (id.type() != ConversationId::Type::dm ||
        !std::ranges::equal(id.session_id(), core.globals.session_id()))
        return;

    auto& profile = core.configs.user_profile();
    if (profile.get_nts_priority() >= 0)
        return;

    profile.set_nts_priority(0);

    // Then apply the config as a whole rather than just the priority.  Until now there was no
    // conversation for anything else it holds to attach to -- a disappearing timer set on another
    // device has been waiting with nowhere to go -- and reconciling is what puts all of it in place
    // at once.  It cannot arrive by the usual route, since a local change is not a merge and so
    // reports nothing back to us.
    _reconcile_user_profile();
}

void Client::_reconcile_user_profile() {
    auto& profile = core.configs.user_profile();
    auto me = ConversationId::dm(core.globals.session_id());

    auto name = profile.get_name();
    auto pic = profile.get_profile_pic();
    auto priority = profile.get_nts_priority();
    auto expiry = profile.get_nts_expiry();

    // Note-to-self carries a duration but no mode, because there is only one that means anything
    // when the reader is also the writer: there is no moment at which someone else reads it.
    int exp_mode = expiry && expiry->count() > 0
                         ? static_cast<int>(config::expiration_mode::after_send)
                         : static_cast<int>(config::expiration_mode::none);
    int64_t exp_timer = expiry ? expiry->count() : 0;

    bool profile_changed = false, convo_changed = false, order_changed = false, created = false,
         history_changed = false;

    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        std::optional<std::string> pic_url;
        std::optional<std::span<const std::byte>> pic_key;
        if (!pic.empty()) {
            pic_url = pic.url;
            pic_key = std::span<const std::byte>{pic.key};
        }

        profile_changed =
                c.prepared_exec(
                        R"(
UPDATE accounts SET name = ?2, profile_pic_url = ?3, profile_pic_key = ?4, profile_updated = ?5
WHERE id = ?1
  AND (name, profile_pic_url, profile_pic_key, profile_updated) IS NOT (?2, ?3, ?4, ?5)
)",
                        identity_id(c, me),
                        name ? std::optional<std::string>{*name} : std::nullopt,
                        pic_url,
                        pic_key,
                        epoch_seconds(profile.get_profile_updated())) > 0;

        // The config is what says a conversation exists -- a conversation is not defined by having
        // messages in it, or emptying one would lose it, and reimporting an account would lose every
        // conversation that happened to be empty.  For note to self that statement is the priority
        // itself: negative means there is no such conversation, so no row is made for one.
        //
        // Guarded by find_conversation rather than calling ensure_conversation outright, because
        // that helper bumps last_activity on a row that already exists: unguarded, every config
        // merge would shove note to self back to the top of the list.
        auto convo = find_conversation(c, me);
        if (!convo && priority >= 0) {
            auto row = ensure_conversation(c, me, clock_now_ms());
            convo = row.id;
            created = row.created;
        }

        if (convo) {
            order_changed =
                    c.prepared_exec(
                            "UPDATE conversations SET priority = ?2"
                            " WHERE id = ?1 AND priority IS NOT ?2",
                            *convo,
                            priority) > 0;
            convo_changed =
                    c.prepared_exec(
                            R"(
UPDATE conversations SET exp_mode = ?2, exp_timer = ?3
WHERE id = ?1 AND (exp_mode, exp_timer) IS NOT (?2, ?3)
)",
                            *convo,
                            exp_mode,
                            exp_timer) > 0;

            // Retroactive, and idempotent, for the reasons given in _reconcile_contacts.
            auto delete_before = profile.get_nts_delete_before();
            auto delete_attach_before = profile.get_nts_delete_attach_before();
            if (delete_before > std::chrono::sys_seconds{})
                history_changed = delete_messages_before(c, *convo, sys_ms{delete_before});
            if (delete_attach_before > std::chrono::sys_seconds{})
                history_changed |=
                        delete_attachments_before(c, *convo, sys_ms{delete_attach_before});
        }

        tx.commit();
    }

    if (created)
        _emit_conversation_added(me);
    else if (profile_changed || convo_changed || history_changed)
        _touch(me);
    if (history_changed)
        _emit_history_replaced(me);
    if (order_changed)
        _emit_lists_replaced();
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

// Fills in the attachments of every message in `msgs`.
//
// One query for the whole page rather than one per message: a conversation view re-reads its page
// on every render, so the per-message alternative pays its cost there.  The placeholder list makes
// this a distinct query string per page size, and so one prepared-statement cache entry per limit
// an application actually asks for -- few, since a page size is normally fixed.
static void load_attachments(sqlite::Connection& c, std::vector<Message>& msgs) {
    if (msgs.empty())
        return;

    std::unordered_map<int64_t, Message*> by_id;
    for (auto& m : msgs)
        by_id.emplace(m.id, &m);

    std::string placeholders;
    for (size_t i = 0; i < msgs.size(); i++)
        placeholders += i ? ",?" : "?";

    auto st = c.prepared_st(
            R"(
        SELECT message, idx, content_type, filename, caption, flags, width, height,
               size, url IS NOT NULL, saved_at
        FROM message_attachments WHERE message IN ({}) ORDER BY message, idx
    )"_format(placeholders));

    int n = 1;
    for (const auto& m : msgs)
        st->bind(n++, m.id);

    for (auto&& [message, idx, ctype, fname, caption, flags, width, height, size, uploaded,
                 saved_at] :
         sqlite::IterableStatementWrapper<
                 int64_t,
                 int64_t,
                 std::optional<std::string>,
                 std::optional<std::string>,
                 std::optional<std::string>,
                 int,
                 std::optional<int>,
                 std::optional<int>,
                 std::optional<int64_t>,
                 int,
                 std::optional<int64_t>>{std::move(st)}) {
        auto found = by_id.find(message);
        if (found == by_id.end())
            continue;

        found->second->attachments.push_back(Attachment{
                .index = static_cast<size_t>(idx),
                .content_type = std::move(ctype),
                .filename = std::move(fname),
                .caption = std::move(caption),
                .voice_message = (flags & ATTACHMENT_FLAG_VOICE_MESSAGE) != 0,
                .width = width ? std::optional{static_cast<uint32_t>(*width)} : std::nullopt,
                .height = height ? std::optional{static_cast<uint32_t>(*height)} : std::nullopt,
                .size = size,
                .uploaded = uploaded != 0,
                .saved_at = saved_at ? std::optional{from_epoch_ms(*saved_at)} : std::nullopt});
    }
}

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

    // Done here rather than by each caller so that every path that produces Messages produces whole
    // ones: a Message with its attachments silently missing is worse than no accessor at all.
    load_attachments(c, out);
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
    // Set before the copies below, so both carry it: that is what makes it the identifier every
    // party agrees on, unlike a hash of copies that differ.
    auto msgid = new_msgid();
    content.set_msgid(msgid);
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

    // Note to self is one swarm, not two: sending both copies there would deposit the same message
    // twice, and both would come back.  So there is no separate sync send to have a state for.
    bool to_self = std::ranges::equal(id.session_id(), self);

    bool created, approved;
    int64_t client_id;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = ensure_conversation(c, id, now);
        created = convo.created;

        c.prepared_exec(
                R"(
            INSERT INTO messages
                (conversation, msgid, sender, outgoing, timestamp, body, send_state,
                 sync_send_state)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        )",
                convo.id,
                msgid,
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
        approved = approve_recipient(c, id, self);
        tx.commit();
    }

    if (approved) {
        _sync_contact(id);
        _emit_lists_replaced();
    }
    if (created)
        _emit_conversation_added(id);
    _reveal_note_to_self(id);
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
    _send_ids[core_id] = OutgoingSend{client_id, to_self};

    // send_dm() reports its first status synchronously, i.e. before we knew the id to map it to.
    if (auto stashed = _early_status.extract(core_id)) {
        auto& [status, hash] = stashed.mapped();
        _apply_send_status(client_id, status, false, to_self ? opt_view(hash) : std::nullopt);
    }

    if (!to_self) {
        auto sync_id = core.send_dm(self, synced, now);
        _sync_sends[sync_id] = client_id;
        if (auto stashed = _early_status.extract(sync_id)) {
            auto& [status, hash] = stashed.mapped();
            _apply_send_status(client_id, status, true, opt_view(hash));
        }
    }
}

// -- Attachments ------------------------------------------------------------------------------

// The content type to advertise for a file whose sender did not name one.
//
// Deliberately shallow: this is a display hint a recipient uses to pick a viewer, not something
// any decision depends on, and a platform that has a real UTI database (as every GUI client does)
// should pass `OutgoingAttachment::content_type` rather than rely on this.  Everything unrecognised
// is application/octet-stream, which is what Session's other clients also fall back to.
static std::string infer_content_type(const std::filesystem::path& path) {
    static const std::unordered_map<std::string_view, std::string_view> types{
            {"jpg", "image/jpeg"},
            {"jpeg", "image/jpeg"},
            {"png", "image/png"},
            {"gif", "image/gif"},
            {"webp", "image/webp"},
            {"heic", "image/heic"},
            {"bmp", "image/bmp"},
            {"tiff", "image/tiff"},
            {"svg", "image/svg+xml"},
            {"mp4", "video/mp4"},
            {"mov", "video/quicktime"},
            {"webm", "video/webm"},
            {"mkv", "video/x-matroska"},
            {"avi", "video/x-msvideo"},
            {"mp3", "audio/mpeg"},
            {"m4a", "audio/mp4"},
            {"aac", "audio/aac"},
            {"ogg", "audio/ogg"},
            {"opus", "audio/opus"},
            {"flac", "audio/flac"},
            {"wav", "audio/wav"},
            {"pdf", "application/pdf"},
            {"txt", "text/plain"},
            {"md", "text/markdown"},
            {"csv", "text/csv"},
            {"html", "text/html"},
            {"json", "application/json"},
            {"xml", "application/xml"},
            {"zip", "application/zip"},
            {"gz", "application/gzip"},
            {"bz2", "application/x-bzip2"},
            {"xz", "application/x-xz"},
            {"7z", "application/x-7z-compressed"},
            {"tar", "application/x-tar"},
    };

    auto ext = path.extension().string();
    if (ext.starts_with('.'))
        ext.erase(0, 1);
    for (auto& ch : ext)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

    if (auto found = types.find(ext); found != types.end())
        return std::string{found->second};
    return "application/octet-stream";
}

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
    // files, which nothing knows yet -- that is what the uploads are for -- so the content is
    // rewritten in _finish_attachment_send once they do.  The identifier is not: it belongs to the
    // message rather than to any particular rendering of it, so it is generated here and reused.
    auto msgid = new_msgid();

    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(to_ms(now)));
    content.set_msgid(msgid);
    auto* data = content.mutable_datamessage();
    data->set_body(std::string{body});
    data->set_timestamp(static_cast<uint64_t>(to_ms(now)));

    auto serialised = content.SerializeAsString();
    auto raw = std::span{reinterpret_cast<const std::byte*>(serialised.data()), serialised.size()};

    bool created, approved;
    int64_t client_id;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        auto convo = ensure_conversation(c, id, now);
        created = convo.created;

        c.prepared_exec(
                R"(
            INSERT INTO messages
                (conversation, msgid, sender, outgoing, timestamp, body, send_state,
                 sync_send_state)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        )",
                convo.id,
                msgid,
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
                    a.content_type ? *a.content_type : infer_content_type(a.path),
                    a.filename ? a.filename : std::optional{a.path.filename().string()},
                    a.caption,
                    a.voice_message ? ATTACHMENT_FLAG_VOICE_MESSAGE : 0,
                    a.width ? std::optional<int64_t>{*a.width} : std::nullopt,
                    a.height ? std::optional<int64_t>{*a.height} : std::nullopt);
        }

        approved = approve_recipient(c, id, self);
        tx.commit();
    }

    if (approved) {
        _sync_contact(id);
        _emit_lists_replaced();
    }
    if (created)
        _emit_conversation_added(id);
    _reveal_note_to_self(id);
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
    auto plaintext_size = static_cast<int64_t>(std::filesystem::file_size(path, ec));
    if (ec || !std::filesystem::is_regular_file(path, ec) || ec) {
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

    if (on_upload) {
        // This attachment's own throttle, so that uploads running alongside each other cannot
        // squelch one another.  Only progress passes through it: starting and finishing are things
        // a caller must always hear, and they are reported from elsewhere.
        auto throttle = std::make_shared<update_throttle>(_high_freq_dispatch_interval);
        req.on_progress = [index, on_upload, throttle](int64_t sent, int64_t total) {
            if (throttle->allow())
                on_upload(index, sent, total, std::nullopt);
        };
    }

    req.on_complete =
            [this, client_id, index, on_upload, plaintext_size](
                    std::variant<std::pair<network::file_metadata, cleared_b32>, int16_t> result,
                    bool /*timeout*/) {
                // Delivered on the network's loop; everything below touches the database, which is
                // Core's loop's alone.  Nobody is waiting on a callback here -- this is Client's
                // own continuation -- so a failure has to be turned into the message failing, which
                // is what the application is watching.
                loop.call([this,
                           client_id,
                           index,
                           on_upload,
                           plaintext_size,
                           result = std::move(result)] {
                    try {
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
                        // upload_file always encrypts with the stream scheme, so the url has to say
                        // so: without the fragment a recipient reaches for the legacy scheme and
                        // cannot open the file at all.
                        auto url = network::file_server::generate_download_url(
                                meta.id,
                                core.network()->file_server_config,
                                /*stream_encrypted=*/true);

                        {
                            auto c = core.database().conn();
                            // The file's own size, not the encrypted one the server reports back:
                            // `size` on the pointer means the plaintext length everywhere else in
                            // Session, and for a legacy-encrypted attachment it is what a recipient
                            // trims the padding by, so an encrypted size there would be wrong in a
                            // way that breaks decryption rather than merely misreporting.
                            c.prepared_exec(
                                    "UPDATE message_attachments SET url = ?, key = ?, size = ?"
                                    " WHERE message = ? AND idx = ?",
                                    url,
                                    std::span<const std::byte>{key},
                                    plaintext_size,
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
                    } catch (const std::exception& e) {
                        log::error(
                                cat,
                                "Recording attachment {} of message {} failed: {}",
                                index,
                                client_id,
                                e.what());
                        _fail_attachment_send(client_id);
                    }
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

// Where a download is written until it is known to be whole.  A save that dies partway leaves this
// rather than something that looks like the file the user asked for.
static std::filesystem::path partial_path(const std::filesystem::path& dest) {
    auto p = dest;
    p += ".part";
    return p;
}

void Client::_save_attachment(
        int64_t message_id,
        size_t index,
        std::filesystem::path dest,
        std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_progress,
        failable_function<void()> cb,
        bool notify_sender) {

    std::optional<std::string> url;
    std::vector<std::byte> key, digest;
    std::optional<int64_t> claimed_size;
    {
        auto c = core.database().conn();
        // `key` and `digest` vary in length -- 32 bytes for the stream scheme, 64 for legacy -- so
        // they are read as blob views from a live statement and copied out before it steps.
        auto st = c.prepared_bind(
                "SELECT url, key, digest, size FROM message_attachments WHERE message = ? AND idx"
                " = ?",
                message_id,
                static_cast<int64_t>(index));
        if (!st->executeStep())
            throw std::runtime_error{
                    "Message {} has no attachment {}"_format(message_id, index)};

        auto [u, k, d, sz] = sqlite::get<
                std::optional<std::string>,
                std::optional<sqlite::blob>,
                std::optional<sqlite::blob>,
                std::optional<int64_t>>(*st);
        url = std::move(u);
        if (k)
            key.assign(k->begin(), k->end());
        if (d)
            digest.assign(d->begin(), d->end());
        claimed_size = sz;
    }

    if (!url)
        throw std::runtime_error{
                "Attachment {} of message {} cannot be fetched: its sender gave no url"_format(
                        index, message_id)};

    auto info = network::file_server::parse_download_url(*url);
    if (!info)
        throw std::runtime_error{
                "Attachment {} of message {} cannot be fetched: {} is not a download url"_format(
                        index, message_id, *url)};

    auto net = core.network();
    if (!net)
        throw std::runtime_error{"Cannot fetch an attachment: no network is attached"};

    bool stream = info->wants_stream_decryption;
    if (stream ? key.size() != attachment::ENCRYPT_KEY_SIZE
               : key.size() != attachment::LEGACY_KEY_SIZE)
        throw std::runtime_error{
                "Attachment {} of message {} cannot be decrypted: a {} attachment needs a {}-byte "
                "key and its sender gave {}"_format(
                        index,
                        message_id,
                        stream ? "stream-encrypted" : "legacy",
                        stream ? attachment::ENCRYPT_KEY_SIZE : attachment::LEGACY_KEY_SIZE,
                        key.size())};
    if (!stream && digest.size() != attachment::LEGACY_DIGEST_SIZE)
        throw std::runtime_error{
                "Attachment {} of message {} cannot be authenticated: a legacy attachment needs a "
                "{}-byte digest and its sender gave {}"_format(
                        index, message_id, attachment::LEGACY_DIGEST_SIZE, digest.size())};

    // Shared with the network's thread, where every callback below runs.  The stream case writes as
    // it decrypts and so never holds the file; the legacy case has to accumulate, because its MAC
    // and digest cover the whole ciphertext and neither can be checked until all of it is here.
    struct SaveState {
        std::filesystem::path dest, partial;
        std::ofstream out;
        std::vector<std::byte> buffered;
        std::optional<attachment::Decryptor> decryptor;
        std::optional<std::string> failure;
        int64_t received = 0;
    };
    auto state = std::make_shared<SaveState>();
    state->dest = std::move(dest);
    state->partial = partial_path(state->dest);
    state->out.open(state->partial, std::ios::binary | std::ios::trunc);
    if (!state->out)
        throw std::runtime_error{"Cannot write {}"_format(state->partial.string())};

    if (stream) {
        std::array<std::byte, attachment::ENCRYPT_KEY_SIZE> k;
        std::ranges::copy(key, k.begin());
        state->decryptor.emplace(k, [state](std::span<const std::byte> plain) {
            state->out.write(reinterpret_cast<const char*>(plain.data()), plain.size());
        });
    }

    auto throttle = std::make_shared<update_throttle>(_high_freq_dispatch_interval);
    auto report = [this, on_progress, index](int64_t done, int64_t total, std::optional<int> r) {
        if (on_progress)
            _dispatch_out([on_progress, index, done, total, r] {
                on_progress(index, done, total, r);
            });
    };
    // As uploads do: the 0/0 that says this one has started, before the size is known.
    report(0, 0, std::nullopt);

    network::DownloadRequest req;
    req.download_url = *url;
    req.request_timeout = ATTACHMENT_REQUEST_TIMEOUT;
    req.overall_timeout = ATTACHMENT_OVERALL_TIMEOUT;

    req.on_data = [state, stream, report, throttle](
                          const network::file_metadata& meta, std::span<const std::byte> data) {
        if (state->failure)
            return;
        try {
            state->received += static_cast<int64_t>(data.size());

            // Enforced against bytes actually arriving rather than against anything the sender or
            // the server claimed, so an over-long transfer is cut off rather than accumulated.
            if (state->received > static_cast<int64_t>(attachment::LEGACY_MAX_ENCRYPTED_SIZE)) {
                state->failure = "attachment is larger than the file server's maximum";
                return;
            }

            if (stream) {
                if (!state->decryptor->update(data))
                    state->failure = "decryption failed";
            } else
                state->buffered.insert(state->buffered.end(), data.begin(), data.end());

            if (throttle->allow())
                report(state->received, meta.size, std::nullopt);
        } catch (const std::exception& e) {
            state->failure = e.what();
        }
    };

    req.on_complete = [this,
                       state,
                       stream,
                       report,
                       message_id,
                       index,
                       notify_sender,
                       cb = std::move(cb),
                       key = std::move(key),
                       digest = std::move(digest),
                       claimed_size](
                              std::variant<network::file_metadata, int16_t> result, bool timeout) {
        auto fail = [&](std::string why, int code) {
            state->out.close();
            std::error_code ec;
            std::filesystem::remove(state->partial, ec);
            report(0, 0, code);
            _report(cb, std::optional{std::move(why)});
        };

        if (auto* err = std::get_if<int16_t>(&result))
            return fail(
                    timeout ? "attachment download timed out"s
                            : "attachment download failed with status {}"_format(*err),
                    *err);

        if (state->failure)
            return fail(std::move(*state->failure), ATTACHMENT_UNREADABLE);

        try {
            if (stream) {
                if (!state->decryptor->finalize())
                    throw std::runtime_error{"attachment ended mid-stream"};
            } else {
                std::array<std::byte, attachment::LEGACY_KEY_SIZE> k;
                std::array<std::byte, attachment::LEGACY_DIGEST_SIZE> d;
                std::ranges::copy(key, k.begin());
                std::ranges::copy(digest, d.begin());
                auto plain = attachment::legacy_decrypt(
                        state->buffered,
                        k,
                        d,
                        claimed_size ? static_cast<size_t>(*claimed_size) : 0);
                state->out.write(reinterpret_cast<const char*>(plain.data()), plain.size());
            }

            state->out.close();
            if (!state->out)
                throw std::runtime_error{"writing {} failed"_format(state->partial.string())};

            // Only now does it get the name the caller asked for.
            std::filesystem::rename(state->partial, state->dest);
        } catch (const std::exception& e) {
            return fail(e.what(), ATTACHMENT_UNREADABLE);
        }

        report(state->received, state->received, 0);
        _report(cb, std::optional<std::string>{});

        // Both of these say the same thing -- that the recipient now has the file -- one to
        // ourselves and one to the sender, and neither is true until it is on disk under its final
        // name, which is why they are here rather than anywhere earlier.  Recording it does not
        // depend on telling them: a caller who saved privately still gets to see that they did.
        loop.call([this, message_id, index, notify_sender] {
            _record_saved(message_id, index, clock_now_ms());
            if (notify_sender)
                _notify_media_saved(message_id, index);
        });
    };

    net->download(std::move(req));
}

void Client::_on_media_saved(
        std::span<const std::byte, 33> sender,
        const SessionProtos::DataExtractionNotification& note,
        sys_ms when) {

    // Both halves of the reference are required.  The timestamp alone cannot identify a message --
    // several sent in the same millisecond share one, which is what msgId exists to fix -- and
    // msgId alone is far too small to be an identifier.  A notification carrying only the
    // deprecated `timestamp` field says nothing usable: the three other clients disagree about
    // what they put in it, so it is not read at all.
    if (!note.has_msgtimestamp() || !note.has_msgid()) {
        log::debug(cat, "Ignoring a media-saved notification that names no message");
        return;
    }

    // Ours to have been saved: they can only have saved something we sent them, so the message
    // must be one of ours, in the conversation with them.  Matching on sender as well as
    // conversation stops a peer claiming anything about a message they were not sent.
    auto convo_id = ConversationId::dm(sender);
    std::optional<int64_t> message_id;
    {
        auto c = core.database().conn();
        auto convo = find_conversation(c, convo_id);
        if (!convo)
            return;

        message_id = c.prepared_maybe_get<int64_t>(
                R"(
            SELECT id FROM messages
            WHERE conversation = ? AND timestamp = ? AND msgid = ? AND outgoing = 1
        )",
                *convo,
                static_cast<int64_t>(note.msgtimestamp()),
                static_cast<MsgId>(note.msgid()));
    }

    if (!message_id) {
        log::debug(cat, "A media-saved notification named a message we do not have");
        return;
    }

    // -1 means they saved all of the message's attachments together, which is what saving from a
    // gallery view does; anything else names one by position.  An absent index is neither, and is
    // not read as "the first one".
    std::optional<size_t> index;
    if (note.has_attindex()) {
        if (note.attindex() >= 0)
            index = static_cast<size_t>(note.attindex());
        else if (note.attindex() != -1)
            return;
    } else
        return;

    // When they sent the notification, which is when they saved it -- *not* msgTimestamp, which
    // identifies the message being talked about and may be days older.  Their clock rather than
    // ours, and unauthenticated, but the alternative is our receive time, which is wrong by however
    // long the notification sat in the swarm.
    _record_saved(*message_id, index, when);
}

void Client::_record_saved(int64_t message_id, std::optional<size_t> index, sys_ms when) {
    std::optional<ConversationId> convo_id;
    {
        auto c = core.database().conn();

        // An unset index means every attachment of the message, which is what a peer saving from a
        // gallery view reports.  Later saves overwrite earlier ones: what an application asks of
        // this is "is there any point offering save again", not a history.
        auto changed = index ? c.prepared_exec(
                                       "UPDATE message_attachments SET saved_at = ?"
                                       " WHERE message = ? AND idx = ?",
                                       to_ms(when),
                                       message_id,
                                       static_cast<int64_t>(*index))
                             : c.prepared_exec(
                                       "UPDATE message_attachments SET saved_at = ?"
                                       " WHERE message = ?",
                                       to_ms(when),
                                       message_id);
        if (changed == 0)
            return;

        auto convo = c.prepared_maybe_get<int64_t>(
                "SELECT conversation FROM messages WHERE id = ?", message_id);
        if (!convo)
            return;
        convo_id = conversation_id_at(c, *convo);
    }

    _emit_message(false, *convo_id, message_id);
}

void Client::_notify_media_saved(int64_t message_id, size_t index) {
    std::optional<ConversationId> convo_id;
    int64_t timestamp = 0;
    std::optional<MsgId> msgid;
    {
        auto c = core.database().conn();
        auto row = c.prepared_maybe_get<int64_t, int, int64_t, std::optional<MsgId>>(
                "SELECT conversation, outgoing, timestamp, msgid FROM messages WHERE id = ?",
                message_id);
        if (!row)
            return;
        auto [convo_row, outgoing, ts, id] = *row;

        // Saving from a message we sent notifies nobody: the person who would be told is us.  That
        // covers a note to self as well, which is outgoing.
        if (outgoing)
            return;

        convo_id = conversation_id_at(c, convo_row);
        timestamp = ts;
        msgid = id;
    }

    if (convo_id->type() != ConversationId::Type::dm)
        return;

    SessionProtos::Content content;
    auto now = clock_now_ms();
    content.set_sigtimestamp(static_cast<uint64_t>(to_ms(now)));
    content.set_msgid(new_msgid());

    auto* note = content.mutable_dataextractionnotification();
    note->set_type(SessionProtos::DataExtractionNotification::MEDIA_SAVED);
    note->set_msgtimestamp(static_cast<uint64_t>(timestamp));
    // Deliberately not set when the message we saved from carries none: the pair is what identifies
    // a message, and half of it is not a weaker match but an ambiguous one.
    if (msgid)
        note->set_msgid(*msgid);
    note->set_attindex(static_cast<int32_t>(index));

    log::debug(
            cat, "Telling the sender we saved attachment {} of message {}", index, message_id);

    // Registered rather than fired blind: Core reports on every send, and a status for an id nobody
    // claims would sit in _early_status for the life of the process.
    _quiet_sends.insert(core.send_dm(convo_id->session_id(), content, now));
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

        auto row = c.prepared_maybe_get<int64_t, std::string, int64_t, std::optional<MsgId>>(
                "SELECT conversation, body, timestamp, msgid FROM messages WHERE id = ?",
                client_id);
        if (!row) {
            log::warning(cat, "Cannot finish message {}: it is gone", client_id);
            return;
        }
        auto [convo_row, msg_body, msg_ts, msg_id] = *row;
        convo_id = conversation_id_at(c, convo_row);
        body = std::move(msg_body);
        timestamp = msg_ts;

        content.set_sigtimestamp(static_cast<uint64_t>(timestamp));
        // The one the row was stored with, not a fresh one: rebuilding the content does not make
        // this a different message, and a new identifier here would leave the copy we already
        // showed the user and the copy we send disagreeing about which message they are.
        if (msg_id)
            content.set_msgid(*msg_id);
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
                const auto* end = fid.data() + fid.size();
                if (auto [stop, ec] = std::from_chars(fid.data(), end, legacy_id);
                    ec != std::errc{} || stop != end)
                    legacy_id = 0;
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

    // What we store is the sync copy, as the plain send does: it is what the copy coming back off
    // our own swarm is recognised as, and the provisional content written before the uploads
    // describes something nobody will ever send.
    auto serialised = synced.SerializeAsString();
    auto raw = std::span{reinterpret_cast<const std::byte*>(serialised.data()), serialised.size()};

    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        c.prepared_exec(
                "UPDATE messages SET send_state = ?, sync_send_state = ? WHERE id = ?",
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

// Records what an arriving message says about the files it carries.  Nothing is fetched here: an
// AttachmentPointer is a url and a key, and whether to spend bandwidth on it is the application's
// decision, made later through save_attachment.
//
// Everything the sender listed gets a row, including a pointer too malformed to ever fetch.  The
// alternative -- dropping the unusable ones -- would make a message of three files look like a
// message of two, which is a worse lie than a row that cannot be saved: the count and the ordering
// are what a reader is being shown, and they should match what was actually sent.
static void store_incoming_attachments(
        sqlite::Connection& c, int64_t message_id, const SessionProtos::DataMessage& data) {
    for (int i = 0; i < data.attachments_size(); i++) {
        const auto& ptr = data.attachments(i);

        // The key is 32 bytes for the stream scheme and 64 for the legacy one; anything else cannot
        // decrypt, but is still stored so the attachment is at least visible.
        std::optional<std::span<const std::byte>> key;
        if (ptr.has_key())
            key = to_span(ptr.key());

        std::optional<std::span<const std::byte>> digest;
        if (ptr.has_digest())
            digest = to_span(ptr.digest());

        c.prepared_exec(
                R"(
            INSERT INTO message_attachments
                (message, idx, url, key, digest, size, content_type, filename, caption, flags,
                 width, height)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )",
                message_id,
                static_cast<int64_t>(i),
                ptr.has_url() ? std::optional{ptr.url()} : std::nullopt,
                key,
                digest,
                ptr.has_size() ? std::optional<int64_t>{ptr.size()} : std::nullopt,
                ptr.has_contenttype() ? std::optional{ptr.contenttype()} : std::nullopt,
                ptr.has_filename() ? std::optional{ptr.filename()} : std::nullopt,
                ptr.has_caption() ? std::optional{ptr.caption()} : std::nullopt,
                static_cast<int>(ptr.flags()),
                ptr.has_width() ? std::optional<int64_t>{ptr.width()} : std::nullopt,
                ptr.has_height() ? std::optional<int64_t>{ptr.height()} : std::nullopt);
    }
}

void Client::_on_message_received(core::ReceivedMessage&& msg) {
    SessionProtos::Content content;
    if (!content.ParseFromArray(msg.content.data(), static_cast<int>(msg.content.size()))) {
        log::warning(cat, "Dropping message {}: Content protobuf did not parse", msg.hash);
        return;
    }

    // Someone telling us they saved a file we sent them.  Not history -- it changes an attachment
    // we already have rather than adding anything -- so it is handled here and goes no further.
    if (content.has_dataextractionnotification()) {
        const auto& note = content.dataextractionnotification();
        if (note.type() == SessionProtos::DataExtractionNotification::MEDIA_SAVED)
            _on_media_saved(
                    msg.sender_session_id,
                    note,
                    content.has_sigtimestamp()
                            ? from_epoch_ms(static_cast<int64_t>(content.sigtimestamp()))
                            : msg.timestamp);
        return;
    }

    // Receipts, typing indicators and call signalling are not conversation history; ignore them
    // rather than materialising an empty conversation for a stranger who is merely typing.
    if (!content.has_datamessage())
        return;
    const auto& data = content.datamessage();

    // A message of nothing but files is an ordinary message here: what makes something not history
    // is having no content of either kind, which is what the callbacks above are.
    if (data.body().empty() && data.attachments_size() == 0)
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

    auto msgid = msgid_of(content);

    bool created = false, inserted = false, renamed = false, contact_changed = false,
         approved_them = false;
    int64_t client_id = 0;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};

        // A blocked account is refused here rather than filtered when drawing, so that nothing it
        // sends becomes history, an unread count or a notification.  Only what *they* sent: our own
        // copy of a conversation we later blocked is still ours.
        if (!outgoing && c.prepared_get<int64_t>(
                                 R"(
            SELECT count(*) FROM contacts ct JOIN accounts a ON a.id = ct.account
            WHERE a.session_id = ? AND ct.blocked
        )",
                                 msg.sender_session_id) > 0)
            return;

        auto convo = ensure_conversation(c, convo_id, ts);
        created = convo.created;
        auto sender = account_id(c, msg.sender_session_id);

        // Approval is recorded by messages flowing rather than by anyone setting it: sending to
        // someone approves them, and receiving from someone means they approved us -- you cannot
        // write to an account you have not accepted.  So the two flags are a side effect here, and
        // an unapproved contact with a message in it *is* a message request.
        //
        // `convo_with` and not the sender: a copy of our own outgoing message, arriving from our
        // own swarm, is us approving whoever it was addressed to.
        //
        // Note to self is left alone -- we are not our own contact, and our own entry has no
        // business in the Contacts config.
        if (!std::ranges::equal(convo_with, core.globals.session_id())) {
            auto with = account_id(c, convo_with);
            auto made = ensure_contact(c, with, outgoing);
            auto flagged = c.prepared_exec(
                                   outgoing ? "UPDATE contacts SET approved = 1"
                                              " WHERE account = ? AND NOT approved"
                                            : "UPDATE contacts SET approved_me = 1"
                                              " WHERE account = ? AND NOT approved_me",
                                   with) > 0;
            contact_changed = made || flagged;

            // Only our own approval moves a conversation between the lists.  Learning that *they*
            // approved *us* changes what we know about them and nothing about where they belong,
            // and a request appearing for the first time is reported as the conversation it is.
            approved_them = outgoing && contact_changed;
        }

        // Delivery is at-least-once -- the swarm cursor advances per batch, so a crash mid-batch
        // re-delivers it -- and either unique index is enough to recognise the redelivery.
        //
        // The msgid index is what also catches our own message coming back off our own swarm, which
        // the swarm hash cannot: that copy is stored before it has one.  A sender that set no msgid
        // leaves NULL there, and SQLite treats NULLs as distinct, so those fall back to the swarm
        // hash alone -- enough for a redelivery, not enough for a sender who stored twice.
        inserted = c.prepared_exec(
                           R"(
            INSERT OR IGNORE INTO messages
                (conversation, msgid, swarm_hash, sender, outgoing, timestamp, body,
                 send_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        )",
                           convo.id,
                           msgid,
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

            store_incoming_attachments(c, client_id, data);

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
                UPDATE accounts SET name = ?1
                WHERE id = ?2 AND name IS NOT ?1
            )",
                              name,
                              sender) > 0;

        tx.commit();
    }

    if (contact_changed || renamed)
        _sync_contact(convo_id);
    if (created)
        _emit_conversation_added(convo_id);
    if (inserted) {
        _reveal_note_to_self(convo_id);
        _emit_message(true, convo_id, client_id);
    }
    if (inserted || renamed)
        _touch(convo_id);

    // Approval moves a conversation between the two lists, so both changed and neither changed in a
    // way that naming one row would describe.
    if (approved_them)
        _emit_lists_replaced();
}

void Client::_on_send_status(
        int64_t core_id,
        core::MessageSendStatus status,
        std::optional<std::string_view> swarm_hash) {
    if (auto quiet = _quiet_sends.find(core_id); quiet != _quiet_sends.end()) {
        if (is_terminal(status)) {
            _quiet_sends.erase(quiet);
            if (status != core::MessageSendStatus::success)
                log::debug(
                        cat,
                        "A send nobody is waiting on failed with status {}",
                        static_cast<int>(status));
        }
        return;
    }

    if (auto sync = _sync_sends.find(core_id); sync != _sync_sends.end()) {
        log::debug(
                cat, "sync copy of send {} reached status {}", core_id, static_cast<int>(status));
        auto client_id = sync->second;
        if (is_terminal(status))
            _sync_sends.erase(sync);
        _apply_send_status(client_id, status, true, swarm_hash);
        return;
    }

    auto it = _send_ids.find(core_id);
    if (it == _send_ids.end()) {
        // Fired from inside send_dm(), before it returned us the id to map.  send_message() drains
        // this as soon as it has the mapping.
        _early_status.insert_or_assign(
                core_id,
                EarlyStatus{
                        status,
                        swarm_hash ? std::optional{std::string{*swarm_hash}} : std::nullopt});
        return;
    }

    auto [client_id, own_swarm] = it->second;
    if (is_terminal(status))
        _send_ids.erase(it);
    _apply_send_status(client_id, status, false, own_swarm ? swarm_hash : std::nullopt);
}

void Client::_apply_send_status(
        int64_t client_id,
        core::MessageSendStatus status,
        bool sync,
        std::optional<std::string_view> swarm_hash) {
    auto state = state_for(status);
    std::optional<ConversationId> convo;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        // The two sends own one column each, so a status for one never disturbs the other.
        auto column = sync ? "sync_send_state"sv : "send_state"sv;
        bool changed =
                c.prepared_exec(
                        "UPDATE messages SET {0} = ?1 WHERE id = ?2 AND {0} IS NOT ?1"_format(
                                column),
                        static_cast<int>(state),
                        client_id) > 0;

        // Set once and never revised: the hash is what a redelivery of this same message off our
        // swarm dedupes against, so pointing it at a later store would strand the row it came from.
        if (swarm_hash)
            changed |= c.prepared_exec(
                               "UPDATE messages SET swarm_hash = ? WHERE id = ? AND swarm_hash IS "
                               "NULL",
                               *swarm_hash,
                               client_id) > 0;

        if (changed) {
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
