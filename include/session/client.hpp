#pragma once

#include <filesystem>
#include <optional>
#include <session/client/conversation_id.hpp>
#include <session/client/signals.hpp>
#include <session/client/types.hpp>
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
///     session::client::Client client{
///         std::filesystem::path{"/path/to/session.db"},
///         session::client::callbacks{
///             .conversation_updated = [&](const auto& convo) { redraw(convo); },
///             .message_added = [&](const auto& id, const auto& msg) { append(id, msg); },
///         }};
///
///     for (const auto& convo : client.conversations())
///         std::cout << convo.name_or_id() << ": " << convo.unread << " unread\n";
///
/// Client shares Core's database — the same file and the same connection pool, not a second
/// database — so a write from a Client handler joins whatever transaction Core already has open on
/// that thread.
namespace oxen::quic {
class JobQueue;
}

namespace session::client {

using namespace std::literals;

class Client {
  public:
    /// Constructs a Client and, internally, the Core it sits on.  Takes exactly the options
    /// `core::Core` takes (database encryption, predefined_seed, callbacks, …) and forwards them.
    ///
    /// Two of the Core callbacks are intercepted: `message_received` and `message_send_status`.
    /// Client handles those to maintain its own tables and then invokes the application's handler
    /// for the same event, if one was supplied, so passing `core::callbacks` here still works as
    /// it does for a bare Core.  Applications building on Client should not need either of them —
    /// `client::callbacks` reports what changed in terms of conversations instead.
    template <core::CoreOption... Opts>
    explicit Client(std::filesystem::path db_path, Opts&&... opts) :
            Client{std::move(db_path), callbacks{}, std::forward<Opts>(opts)...} {}

    /// As above, additionally taking the change notifications to deliver.  They are fixed for the
    /// life of the Client, exactly as core::callbacks are, and are the only way an application is
    /// told anything -- see `callbacks`, and read the startup ordering note there before using it.
    template <core::CoreOption... Opts>
    explicit Client(std::filesystem::path db_path, callbacks cbs, Opts&&... opts) :
            _cbs{std::move(cbs)},
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
    /// False rather than throwing when there is no account yet: with no identity, nothing can be a
    /// conversation with ourselves.
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

    /// Sets a conversation's pinning: 0 unpinned, positive pinned with higher values first,
    /// negative hidden.  The value is the one the Contacts and UserGroups configs carry, so this is
    /// also where a config update from another device lands once that reconciliation exists.
    ///
    /// Reported to subscribers as `conversation_list_replaced`, not as an update to the one
    /// conversation, because hiding removes a conversation from the list and unhiding returns it —
    /// so what changed is the list, not a row in it.
    void set_priority(const ConversationId& id, int priority);
    void set_priority(const ConversationId& id, int priority, std::function<void()> cb);

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
    //
    // Handlers are given at construction; there is no way to add or remove one afterwards.  See
    // `callbacks` for what each reports, and note in particular that the initial conversation list
    // must be taken *after* construction, never gathered before it:
    //
    //     Client client{path, std::move(cbs)};    // 1. notifications start here
    //     auto convos = client.conversations();   // 2. install as the starting point
    //
    // Anything arriving between 1 and 2 is applied on top of the snapshot and lands on the right
    // answer, because each handler carries the whole of the new state rather than a delta, so
    // applying one twice changes nothing.

  private:
    // Declared above `core`, which is declared last: see the note there.
    callbacks _cbs;

    // Core's send ids are per-process (its counter restarts at 1 on every run), so this mapping
    // must not be persisted or a stale row would capture a later run's status updates.
    std::unordered_map<int64_t, int64_t> _send_ids;  // core send id -> client message id

    // Status updates that arrived from send_dm() before it returned, i.e. before we knew the core
    // send id to map.  Drained by send_message() once the mapping is registered.
    std::unordered_map<int64_t, core::MessageSendStatus> _early_status;

    // The actual work, all of it assuming it is already on the loop thread.  The public methods
    // above are dispatches onto that thread and nothing else; these are where the database is
    // touched, and are also what Client's own handlers call, since those already run there.
    std::span<const std::byte> _self_or_none();
    std::vector<Conversation> _conversations();
    std::optional<Conversation> _conversation(const ConversationId& id);
    Conversation _create_conversation(const ConversationId& id);
    void _mark_read(const ConversationId& id, std::optional<sys_ms> up_to);
    void _set_priority(const ConversationId& id, int priority);
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

    // Runs `invoke` against the application's handlers, swallowing and logging anything it throws:
    // a broken listener is not something a data model can do anything about.
    void _emit(const std::function<void(const callbacks&)>& invoke);

    void _emit_conversation_added(const ConversationId& id);
    void _emit_list_replaced();
    void _emit_message(bool added, const ConversationId& id, int64_t message_id);

    // Conversations whose settled state still has to be reported.  A conversation is marked here
    // rather than reported immediately so that a poll delivering fifty messages to one conversation
    // reports it once; `_flush_pending` is scheduled on the loop and runs when the work that
    // dirtied them is finished.
    std::vector<ConversationId> _dirty;
    bool _flush_scheduled = false;
    void _touch(const ConversationId& id);
    void _flush_pending();

  public:
    /// The account state this Client is built on: keys, device group, configs, polling.  A
    /// Client-based application uses this for everything below the conversation layer.
    ///
    /// Declared last, which is load-bearing rather than stylistic: members are destroyed in reverse
    /// declaration order, so this is destroyed *first*.  Core's callbacks and loop jobs capture
    /// `this` and reach the members above -- the signal registry, the send-id map, the pending
    /// flush -- and Core's polling thread can be part-way through delivering one when a Client is
    /// destroyed.  `quic::Loop::~Loop()` joins that thread, so once this member is gone no callback
    /// can fire, and everything destroyed after it is unreachable by definition.
    ///
    /// Put anything a Core callback touches *above* this, never below.
    core::Core core;

  private:
    // Client's own queue on Core's loop, rather than the loop's shared one, so that work deferred
    // here is *cancelled* if the Client is destroyed with it still outstanding.  Running it instead
    // would mean reporting a change to the subscribers of a Client that is going away, against a
    // Core whose database is already being torn down.
    //
    // Declared after `core` -- the one thing that belongs below it -- because a JobQueue needs its
    // loop alive in order to stop, so it has to be destroyed while Core still exists.
    struct JobsDeleter {
        void operator()(oxen::quic::JobQueue*) const;
    };
    std::unique_ptr<oxen::quic::JobQueue, JobsDeleter> _jobs;
};

}  // namespace session::client
