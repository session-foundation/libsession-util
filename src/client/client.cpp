#include <SQLiteCpp/Transaction.h>
#include <SessionProtos.pb.h>

#include <oxen/log.hpp>
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

struct ConvoRow {
    int64_t id;
    bool created;
};

// Creates the conversation row if it is missing and moves last_activity forward to `activity` if
// that is newer, returning its row id.  Must be called inside the caller's transaction along with
// whatever change prompted it.
static ConvoRow ensure_conversation(
        sqlite::Connection& c, const ConversationId& id, sys_ms activity) {
    auto key = id.to_string();
    auto ms = to_ms(activity);

    // A DM's peer gets an accounts row up front so the conversation can resolve a display name
    // even before any message arrives.
    std::optional<int64_t> peer;
    if (id.type() == ConversationId::Type::dm)
        peer = account_id(c, id.session_id());

    bool created = c.prepared_exec(
                           "INSERT OR IGNORE INTO conversations"
                           " (key, type, peer, created, last_activity) VALUES (?, ?, ?, ?, ?)",
                           key,
                           static_cast<int>(id.type()),
                           peer,
                           ms,
                           ms) > 0;
    if (!created)
        c.prepared_exec(
                "UPDATE conversations SET last_activity = ? WHERE key = ? AND last_activity < ?",
                ms,
                key,
                ms);

    return {c.prepared_get<int64_t>("SELECT id FROM conversations WHERE key = ?", key), created};
}

// Returns the conversation row id, or nullopt if we have no such conversation.
static std::optional<int64_t> find_conversation(sqlite::Connection& c, const ConversationId& id) {
    auto key = id.to_string();
    return c.prepared_maybe_get<int64_t>("SELECT id FROM conversations WHERE key = ?", key);
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
            "UPDATE messages SET send_state = ? WHERE send_state IN (?, ?)",
            static_cast<int>(SendState::interrupted),
            static_cast<int>(SendState::pending),
            static_cast<int>(SendState::sending));
}

// -- Change notification ----------------------------------------------------------------------

Subscription Client::subscribe(std::function<void(const Change&)> handler) {
    auto id = _signals->next_id++;
    _signals->handlers.emplace(id, std::move(handler));
    return Subscription{_signals, id};
}

void Client::_emit(const Change& change) {
    // Iterate over a copy of the handler list: a handler is allowed to subscribe or unsubscribe
    // (including its own subscription) from inside the callback.
    std::vector<std::function<void(const Change&)>> handlers;
    handlers.reserve(_signals->handlers.size());
    for (const auto& [id, h] : _signals->handlers)
        handlers.push_back(h);

    for (const auto& h : handlers) {
        try {
            h(change);
        } catch (const std::exception& e) {
            log::error(cat, "client change handler threw: {}", e.what());
        }
    }
}

// -- Conversations ----------------------------------------------------------------------------

static constexpr auto CONVO_COLUMNS =
        "SELECT c.key, coalesce(a.display_name, ''), c.last_activity,"
        " coalesce((SELECT m.body FROM messages m WHERE m.conversation = c.id"
        "            ORDER BY m.timestamp DESC, m.id DESC LIMIT 1), ''),"
        " (SELECT COUNT(*) FROM messages m WHERE m.conversation = c.id"
        "   AND m.outgoing = 0 AND m.timestamp > c.last_read)"
        " FROM conversations c LEFT JOIN accounts a ON a.id = c.peer"sv;

template <typename... Bind>
static std::vector<Conversation> query_conversations(
        sqlite::Connection& c, const std::string& query, const Bind&... bind) {
    std::vector<Conversation> out;
    for (auto [key, name, activity, preview, unread] :
         c.prepared_results<std::string, std::string, int64_t, std::string, int>(query, bind...))
        out.push_back(
                Conversation{
                        .id = ConversationId::parse(key),
                        .display_name = std::move(name),
                        .last_message = std::move(preview),
                        .last_activity = from_epoch_ms(activity),
                        .unread = unread});
    return out;
}

std::vector<Conversation> Client::conversations() {
    auto c = core.database().conn();
    return query_conversations(c, "{} ORDER BY c.last_activity DESC, c.id"_format(CONVO_COLUMNS));
}

std::optional<Conversation> Client::conversation(const ConversationId& id) {
    auto c = core.database().conn();
    // `key` must outlive the query: string binds go through sqlite3_bind_*_nocopy, so binding a
    // temporary here would leave the statement pointing at freed memory when it steps.
    auto key = id.to_string();
    auto found = query_conversations(c, "{} WHERE c.key = ?"_format(CONVO_COLUMNS), key);
    if (found.empty())
        return std::nullopt;
    return std::move(found.front());
}

Conversation Client::create_conversation(const ConversationId& id) {
    bool created;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        created = ensure_conversation(c, id, clock_now_ms()).created;
        tx.commit();
    }
    if (created)
        _emit({ChangeType::conversation_added, id, std::nullopt});
    return *conversation(id);
}

void Client::mark_read(const ConversationId& id, std::optional<sys_ms> up_to) {
    auto key = id.to_string();
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
                    "SELECT max(timestamp) FROM messages"
                    " WHERE conversation = ? AND outgoing = 0",
                    *convo);
            if (!newest)
                return;
            target = *newest;
        }

        changed = c.prepared_exec(
                "UPDATE conversations SET last_read = ?1 WHERE id = ?2 AND last_read < ?1",
                target,
                *convo);
        tx.commit();
    }
    if (changed > 0)
        _emit({ChangeType::conversation_updated, id, std::nullopt});
}

// -- Messages ---------------------------------------------------------------------------------

static constexpr auto MESSAGE_COLUMNS =
        "SELECT m.id, c.key, m.swarm_hash, a.session_id, m.outgoing, m.timestamp, m.body,"
        " m.send_state"
        " FROM messages m"
        " JOIN conversations c ON c.id = m.conversation"
        " JOIN accounts a ON a.id = m.sender"sv;

template <typename... Bind>
static std::vector<Message> query_messages(
        sqlite::Connection& c, const std::string& query, const Bind&... bind) {
    std::vector<Message> out;
    for (auto [id, key, swarm_hash, sender, outgoing, ts, body, send_state] :
         c.prepared_results<
                 int64_t,
                 std::string,
                 std::optional<std::string>,
                 sqlite::blob_guts<b33>,
                 int,
                 int64_t,
                 std::string,
                 std::optional<int>>(query, bind...))
        out.push_back(
                Message{.id = id,
                        .conversation = ConversationId::parse(key),
                        .sender = sender,
                        .outgoing = outgoing != 0,
                        .timestamp = from_epoch_ms(ts),
                        .body = std::move(body),
                        .send_state = send_state
                                            ? std::optional{static_cast<SendState>(*send_state)}
                                            : std::nullopt,
                        .hash = std::move(swarm_hash)});
    return out;
}

std::vector<Message> Client::messages(
        const ConversationId& id, int limit, std::optional<MessageCursor> before) {
    auto c = core.database().conn();
    auto convo = find_conversation(c, id);
    if (!convo)
        return {};

    if (!before)
        return query_messages(
                c,
                "{} WHERE m.conversation = ? ORDER BY m.timestamp DESC, m.id DESC LIMIT ?"_format(
                        MESSAGE_COLUMNS),
                *convo,
                limit);

    // Strictly-older-than comparison on (timestamp, id), spelled out rather than as an SQL row
    // value so this does not depend on the SQLite version's row-value support.
    return query_messages(
            c,
            "{} WHERE m.conversation = ?"
            " AND (m.timestamp < ?2 OR (m.timestamp = ?2 AND m.id < ?3))"
            " ORDER BY m.timestamp DESC, m.id DESC LIMIT ?4"_format(MESSAGE_COLUMNS),
            *convo,
            to_ms(before->timestamp),
            before->id,
            limit);
}

std::optional<Message> Client::message(int64_t id) {
    auto c = core.database().conn();
    auto found = query_messages(c, "{} WHERE m.id = ?"_format(MESSAGE_COLUMNS), id);
    if (found.empty())
        return std::nullopt;
    return std::move(found.front());
}

int64_t Client::send_message(const ConversationId& id, std::string_view body) {
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
                "INSERT INTO messages"
                " (conversation, content_hash, sender, outgoing, timestamp, body, send_state)"
                " VALUES (?, ?, ?, 1, ?, ?, ?)",
                convo.id,
                cid,
                account_id(c, self),
                to_ms(now),
                body,
                static_cast<int>(SendState::pending));
        client_id = c.sql.getLastInsertRowid();

        c.prepared_exec(
                "INSERT INTO message_content (message, content) VALUES (?, ?)", client_id, raw);
        tx.commit();
    }

    if (created)
        _emit({ChangeType::conversation_added, id, std::nullopt});
    _emit({ChangeType::new_message, id, client_id});
    _emit({ChangeType::conversation_updated, id, std::nullopt});

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

    auto convo_id = ConversationId::dm(msg.sender_session_id);

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

        auto convo = ensure_conversation(c, convo_id, ts);
        created = convo.created;
        auto sender = account_id(c, msg.sender_session_id);

        // Delivery is at-least-once -- the swarm cursor advances per batch, so a crash mid-batch
        // re-delivers it -- and either unique index is enough to recognise the redelivery.
        inserted = c.prepared_exec(
                           "INSERT OR IGNORE INTO messages"
                           " (conversation, content_hash, swarm_hash, sender, outgoing, timestamp,"
                           "  body)"
                           " VALUES (?, ?, ?, ?, 0, ?, ?)",
                           convo.id,
                           cid,
                           msg.hash,
                           sender,
                           to_ms(ts),
                           data.body()) > 0;
        if (inserted) {
            client_id = c.sql.getLastInsertRowid();
            c.prepared_exec(
                    "INSERT INTO message_content (message, content) VALUES (?, ?)",
                    client_id,
                    std::span<const std::byte>{msg.content});
        }

        // `IS NOT` rather than `!=`: the column is NULL until a name is known, and `NULL != 'x'`
        // is NULL, so `!=` would never fire for the first name we learn.
        if (!name.empty())
            renamed = c.prepared_exec(
                              "UPDATE accounts SET display_name = ?1"
                              " WHERE id = ?2 AND display_name IS NOT ?1",
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
    std::optional<std::string> convo;
    {
        auto c = core.database().conn();
        SQLite::Transaction tx{c.sql};
        if (c.prepared_exec(
                    "UPDATE messages SET send_state = ? WHERE id = ? AND send_state IS NOT ?",
                    static_cast<int>(state),
                    client_id,
                    static_cast<int>(state)) > 0)
            convo = c.prepared_maybe_get<std::string>(
                    "SELECT c.key FROM messages m JOIN conversations c ON c.id = m.conversation"
                    " WHERE m.id = ?",
                    client_id);
        tx.commit();
    }

    if (convo)
        _emit({ChangeType::message_updated, ConversationId::parse(*convo), client_id});
}

}  // namespace session::client
