#pragma once

#include <filesystem>
#include <optional>
#include <session/client/conversation_id.hpp>
#include <session/client/signals.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/util.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "client/schema/schema_registry.hpp"

/// `session::client::Client` is the conversation-level data model of a Session client: the
/// conversation list, message history, unread state and drafts, built on top of a `core::Core`
/// which owns the synced account state (keys, configs, polling, decryption).
///
/// Client owns a Core rather than being part of one.  The consequence that matters is the one the
/// compiler enforces: Core has no dependency on Client, and builds, tests and runs with none of
/// this in existence.  A bot that wants raw protocol events constructs a bare Core; an application
/// that wants conversations constructs a Client and reaches through `client.core` for the account
/// state.
///
///     session::client::Client client{
///         std::filesystem::path{"/path/to/session.db"},
///         session::sqlite::argon2id_password{"correct horse battery staple"}};
///
///     auto sub = client.subscribe([&](const auto& change) { redraw(change.conversation); });
///
///     for (const auto& convo : client.conversations())
///         std::cout << convo.name_or_id() << ": " << convo.unread << " unread\n";
///
/// Client shares Core's database — the same file and the same connection pool, not a second
/// database — so a write from a Client handler joins whatever transaction Core already has open on
/// that thread.
namespace session::client {

using namespace std::literals;

/// Delivery state of an outgoing message.  Incoming messages have no send state.
enum class SendState : int {
    /// Queued locally; Core has not yet been able to dispatch it (typically waiting on a PFS key
    /// fetch for the recipient).
    pending = 0,

    /// Handed to the swarm; awaiting confirmation.
    sending = 1,

    /// Accepted by a swarm node.
    sent = 2,

    /// Terminal failure: the swarm rejected it, there was no network, or encryption failed.
    failed = 3,

    /// The application exited while this send was in flight, so its outcome is unknown — it may or
    /// may not have reached the swarm.  Set at startup for anything left in pending or sending,
    /// because Core's in-flight send queue does not survive a restart.
    interrupted = 4,
};

/// A position in a conversation's message history, used to page backwards.  Ordering is by
/// timestamp then message id, so this is a stable cursor even when several messages share a
/// timestamp.
struct MessageCursor {
    sys_ms timestamp;
    int64_t id;
    std::strong_ordering operator<=>(const MessageCursor&) const = default;
};

struct Message {
    /// Client-assigned, database-local message id.  Stable for the life of the message; not the
    /// swarm hash and not Core's send id.
    int64_t id;

    ConversationId conversation;

    /// 0x05-prefixed session ID of the sender; our own account ID for outgoing messages.
    b33 sender;

    bool outgoing;

    /// The message's authenticated timestamp (the Content `sigTimestamp`), which is what history
    /// is ordered by — not the swarm's upload time.
    sys_ms timestamp;

    /// The message body.  Empty for a message that carries no text (e.g. attachments only).
    std::string body;

    /// Set for outgoing messages only.
    std::optional<SendState> send_state;

    /// Swarm-assigned hash; unset for an outgoing message that has not been stored yet.
    std::optional<std::string> hash;

    MessageCursor cursor() const { return {timestamp, id}; }
};

struct Conversation {
    ConversationId id;

    /// Best known display name, or empty if none is known yet.  For DMs this currently comes from
    /// the `LokiProfile` attached to received messages; once Core carries the Contacts config it
    /// will prefer the contact's name.  Empty is normal and expected — the caller decides how to
    /// render an unnamed conversation.
    std::string display_name;

    /// Body of the most recent message, for a conversation-list preview.  Empty if the
    /// conversation has no messages or the latest carries no text.
    std::string last_message;

    /// Timestamp of the most recent message, or the conversation's creation time if it has none.
    sys_ms last_activity;

    /// Count of incoming messages newer than the read watermark.
    int unread = 0;

    /// True for the conversation with our own account — Session's "Note to Self".  It is an
    /// ordinary DM rather than a kind of its own, so this is the only thing distinguishing it, and
    /// it is reported here so that displaying it differently does not require the caller to know
    /// our session ID or to compare it themselves.  What to call it is still the caller's
    /// decision: `display_name` is whatever our own profile says, not a localised label.
    bool note_to_self = false;

    /// The display name if known, otherwise the conversation's string id — a reasonable default
    /// for a caller that has no better fallback of its own.
    std::string name_or_id() const { return display_name.empty() ? id.to_string() : display_name; }
};

class Client {
  public:
    /// Constructs a Client and, internally, the Core it sits on.  Takes exactly the options
    /// `core::Core` takes (database encryption, predefined_seed, callbacks, …) and forwards them.
    ///
    /// Two of the Core callbacks are intercepted: `message_received` and `message_send_status`.
    /// Client handles those to maintain its own tables and then invokes the application's handler
    /// for the same event, if one was supplied, so passing `core::callbacks` here still works as
    /// it does for a bare Core.  Applications building on Client should not need either of them —
    /// subscribe() reports what changed in terms of conversations instead.
    template <core::CoreOption... Opts>
    explicit Client(std::filesystem::path db_path, Opts&&... opts) :
            core{std::move(db_path),
                 // Must precede any caller-supplied callbacks: Core takes the first instance in
                 // the pack, so ours (which chains to theirs) has to be found first.
                 _intercept_callbacks(
                         core::detail::maybe_instance<core::callbacks>(std::forward<Opts>(opts)...)
                                 .value_or(core::callbacks{})),
                 core::schema_extension{"client", schema::MIGRATIONS, schema::FULL_SCHEMA},
                 std::forward<Opts>(opts)...} {
        _init();
    }

    /// The account state this Client is built on: keys, device group, configs, polling.  A
    /// Client-based application uses this for everything below the conversation layer.
    core::Core core;

    // -- Conversations and messages ---------------------------------------------------------------
    //
    // Each of these comes in two forms, and neither touches the database on the calling thread:
    // both hand the work to Core's event loop, which is the only thread that ever touches it.  That
    // is not a stylistic choice -- the connection pool is not safe to use from two threads at once,
    // and reading from one while Core's poll thread writes deadlocks rather than merely racing.
    //
    // The blocking form waits for the loop and returns the result, which is what a single-threaded
    // program or a worker thread wants; it costs nothing when the caller is already on the loop,
    // since the job then runs inline.  The callback form returns immediately and invokes `cb` on
    // the loop thread, which is what a UI thread wants -- it must not block on the loop, and it has
    // to marshal the result back to itself anyway.
    //
    // Argument validation happens on the calling thread, before anything is dispatched, so misuse
    // still throws where the mistake is.  In the callback form a later failure (a disk error, say)
    // is logged rather than thrown, since by then there is no caller stack to reach.

    /// All conversations, most recently active first.
    ///
    /// Currently that means every conversation.  Once message requests exist this returns only
    /// approved ones, with the rest reached through their own accessor.
    std::vector<Conversation> conversations();
    void conversations(std::function<void(std::vector<Conversation>)> cb);

    /// A single conversation, or nullopt if it does not exist locally.
    std::optional<Conversation> conversation(const ConversationId& id);
    void conversation(
            const ConversationId& id, std::function<void(std::optional<Conversation>)> cb);

    /// Creates the conversation if it does not exist and returns it.  Sending to a conversation
    /// does this implicitly; this is for opening an empty conversation with someone first.
    Conversation create_conversation(const ConversationId& id);
    void create_conversation(const ConversationId& id, std::function<void(Conversation)> cb);

    /// True if `id` is the conversation with our own account — Session's "Note to Self".  Same
    /// answer as `Conversation::note_to_self`, for a caller holding only an id.
    ///
    /// Unlike the accessors around it this touches no database and is not dispatched onto Core's
    /// loop: it compares against our session ID, which is fixed once the account exists.  So it is
    /// callable from any thread, including a render loop, and does not need a callback form.
    ///
    /// @throws core::no_account if no account has been created or restored yet.
    bool is_note_to_self(const ConversationId& id);

    /// Marks incoming messages up to and including `up_to` as read, moving the unread watermark
    /// forward.  Passing nullopt marks everything currently stored as read — which is not the same
    /// as parking the watermark at infinity: a message that arrives afterwards is still unread,
    /// even if its timestamp is older than the one we just read to.
    ///
    /// Never moves the watermark backwards.
    void mark_read(const ConversationId& id, std::optional<sys_ms> up_to = std::nullopt);
    void mark_read(const ConversationId& id, std::function<void()> cb);
    void mark_read(const ConversationId& id, std::optional<sys_ms> up_to, std::function<void()> cb);

    /// A window of a conversation's history, newest first.  Pass the `cursor()` of the last
    /// message of a page as `before` to fetch the next (older) page; the message at the cursor is
    /// not repeated.
    std::vector<Message> messages(
            const ConversationId& id,
            int limit = 50,
            std::optional<MessageCursor> before = std::nullopt);
    void messages(const ConversationId& id, std::function<void(std::vector<Message>)> cb);
    void messages(
            const ConversationId& id, int limit, std::function<void(std::vector<Message>)> cb);
    void messages(
            const ConversationId& id,
            int limit,
            std::optional<MessageCursor> before,
            std::function<void(std::vector<Message>)> cb);

    /// A single message by its Client-assigned id, or nullopt if it does not exist.
    std::optional<Message> message(int64_t id);
    void message(int64_t id, std::function<void(std::optional<Message>)> cb);

    /// Sends a text message, storing it immediately and dispatching it via Core.
    ///
    /// Yields the Client message id of the stored row, which is what subsequent
    /// ChangeType::message_updated signals carry as delivery progresses.  Creates the conversation
    /// if it does not already exist.
    ///
    /// @throws std::invalid_argument if the conversation is not a DM (groups and communities are
    /// not implemented yet); thrown on the calling thread, before anything is dispatched.
    int64_t send_message(const ConversationId& id, std::string_view body);
    void send_message(
            const ConversationId& id, std::string_view body, std::function<void(int64_t)> cb);

    // -- Change notification ------------------------------------------------------------------

    /// Registers a handler to be called whenever stored state changes, and returns an RAII handle
    /// that keeps the registration alive.  Any number of handlers may be registered
    /// independently; each gets every change.
    ///
    /// Handlers must not throw — an escaping exception is caught and logged, exactly as Core does
    /// with its own callbacks, because there is nothing useful a data model can do about a broken
    /// listener.
    ///
    /// Handlers fire on whichever thread produced the change: the caller's thread for a change it
    /// made itself (send_message, mark_read), and Core's polling thread for received messages.  An
    /// application with its own event loop should marshal onto it rather than touching UI state
    /// directly.
    ///
    /// The change is always emitted *after* the state is committed, so a handler that reads back
    /// through the Client sees the new state.
    [[nodiscard]] Subscription subscribe(std::function<void(const Change&)> handler);

  private:
    // Declared before `core` so that they are constructed before it and destroyed after it: Core's
    // callbacks capture `this` and may fire for as long as Core is alive.
    std::shared_ptr<detail::SignalRegistry> _signals = std::make_shared<detail::SignalRegistry>();

    // Core's send ids are per-process (its counter restarts at 1 on every run), so this mapping
    // must not be persisted or a stale row would capture a later run's status updates.
    std::unordered_map<int64_t, int64_t> _send_ids;  // core send id -> client message id

    // Status updates that arrived from send_dm() before it returned, i.e. before we knew the core
    // send id to map.  Drained by send_message() once the mapping is registered.
    std::unordered_map<int64_t, core::MessageSendStatus> _early_status;

    // The actual work, all of it assuming it is already on the loop thread.  The public methods
    // above are dispatches onto that thread and nothing else; these are where the database is
    // touched, and are also what Client's own handlers call, since those already run there.
    std::vector<Conversation> _conversations();
    std::optional<Conversation> _conversation(const ConversationId& id);
    Conversation _create_conversation(const ConversationId& id);
    void _mark_read(const ConversationId& id, std::optional<sys_ms> up_to);
    std::vector<Message> _messages(
            const ConversationId& id, int limit, std::optional<MessageCursor> before);
    std::optional<Message> _message(int64_t id);
    int64_t _send_message(const ConversationId& id, std::string_view body);

    // Runs `work` on the loop thread, logging rather than propagating anything it throws: an
    // exception escaping there has no caller to reach and would take the loop with it.
    void _dispatch(std::function<void()> work);
    void _require_dm(const ConversationId& id);

    core::callbacks _intercept_callbacks(core::callbacks app);
    void _init();

    void _on_message_received(core::ReceivedMessage&& msg);
    void _on_send_status(int64_t core_id, core::MessageSendStatus status);
    void _apply_send_status(int64_t client_id, core::MessageSendStatus status);

    void _emit(const Change& change);
};

}  // namespace session::client
