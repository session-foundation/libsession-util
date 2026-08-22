#pragma once

#include <oxen/quic/loop.hpp>

#include <filesystem>
#include <optional>
#include <session/client/attachment.hpp>
#include <session/client/callbacks.hpp>
#include <session/client/conversation.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/message.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/util.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
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
/// Client is where interpretation lives.  Core hands up an authenticated sender and a span of
/// decrypted bytes; everything after that is here — parsing the payload, deciding which
/// conversation it belongs to, whether it is one of ours, what it does to unread state and to the
/// order of the list.  Composing outbound messages is the same job in reverse, which is why setting
/// and clearing protocol fields such as `syncTarget` happens at this layer and not below it.
///
/// The rule, in one line: if a question can be answered without reading what a message *says*, it
/// belongs in Core; if answering it means interpreting the payload, it belongs here.
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

// Forward declared rather than included: the generated protobuf headers are large and this one is
// public.  Only referenced by private members below.
namespace SessionProtos {
class Content;
class DataExtractionNotification;
}

namespace session::client {

using namespace std::literals;

class Client {
    friend class session::TestHelper;  // for unit tests

    // A conversation *is* part of Client's interface, split off rather than added to: what these
    // call is the same private machinery the methods here do.
    friend class Conversation;
    friend class DM;

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

    /// As below, additionally taking the dispatcher every handler is delivered through.  See
    /// `dispatcher`; without one, handlers run on Core's event loop.
    template <core::CoreOption... Opts>
    explicit Client(
            std::filesystem::path db_path, callbacks cbs, dispatcher dispatch, Opts&&... opts) :
            Client{std::move(db_path), std::move(cbs), std::forward<Opts>(opts)...} {
        set_dispatcher(std::move(dispatch));
    }

    /// As above, additionally taking the change notifications to deliver.  They are fixed for the
    /// life of the Client, exactly as core::callbacks are, and are the only way an application is
    /// told anything -- see `callbacks`, and read the startup ordering note there before using it.
    template <core::CoreOption... Opts>
    explicit Client(std::filesystem::path db_path, callbacks cbs, Opts&&... opts) :
            _cbs{std::make_shared<callbacks>(std::move(cbs))},
            core{std::move(db_path),
                 _core_callbacks(),
                 core::schema_extension{"client", schema::MIGRATIONS, schema::FULL_SCHEMA},
                 std::forward<Opts>(opts)...} {
        static_assert(
                (!std::same_as<std::remove_cvref_t<Opts>, core::callbacks> && ...),
                "A Client's Core callbacks are its own wiring and cannot be supplied: what an "
                "application is told is client::callbacks, passed as this constructor's `cbs`.");
        _init();
    }

    // -- Conversations and messages ---------------------------------------------------------------
    //
    // None of these touches the database on the calling thread: they hand the work to Core's event
    // loop, which is the only thread that ever touches it.  That is not a stylistic choice -- the
    // connection pool is not safe to use from two threads at once, and reading from one while
    // Core's poll thread writes deadlocks rather than merely racing.
    //
    // Each returns immediately and invokes `cb` when the work is done -- through the dispatcher if
    // one was given, so on the application's own thread.  A caller that would rather block on the
    // answer than be handed it passes `wait` in place of the handler and takes the return value.
    //
    // **Every `cb` is invoked exactly once**, unless the Client is destroyed before its work runs.
    // That is what its leading `error` argument is for: unset when the call succeeded, and
    // otherwise carrying what went wrong, so that a caller is never left waiting on an answer that
    // will not come.  The other arguments then mean only what they always meant -- an unset
    // `std::optional<Conversation>` says the conversation does not exist, and never that we could
    // not find out.
    //
    // The message is the thrown exception's, which is generally SQLite's, and is passed along as-is
    // rather than reduced to a category of our invention: what went wrong is worth more in a log or
    // a bug report than an enumeration that discarded it.
    //
    // Argument validation happens on the calling thread, before anything is dispatched, so misuse
    // still throws where the mistake is, rather than arriving later as an error argument.

    /// The conversation list: pinned first, then most recently active.
    ///
    /// Message requests are not in it — see `message_requests()` — and neither are hidden
    /// conversations.
    void conversations(failable_function<void(std::vector<AnyConversation>)> cb);
    std::vector<AnyConversation> conversations(wait_t);

    /// The message requests: accounts that have written to us and that we have never written to,
    /// most recently active first.
    ///
    /// Disjoint from `conversations()`, and the same objects otherwise — a request has history, a
    /// name and an unread count, and `Conversation::request` is true on every one of these.  It
    /// stops being a request when we answer it, since writing to someone is what approving them
    /// is; there is no separate accept, and no way back short of deleting the contact.
    void message_requests(failable_function<void(std::vector<AnyConversation>)> cb);
    std::vector<AnyConversation> message_requests(wait_t);

    /// One conversation, or nullopt if we have no such conversation.
    ///
    /// What you get back carries the operations as well as the values — see `Conversation` — so
    /// this is how a caller holding only an id reaches everything that can be done to it.
    ///
    ///     client.conversation(id, [](auto err, auto convo) {
    ///         if (convo) convo->mark_read(cb);
    ///     });
    ///
    /// `dm()` is the same question asked of a kind you already know, so that what comes back is a
    /// `DM` and needs no narrowing.
    ///
    /// @throws std::invalid_argument, from `dm()`, if the id is not a one-to-one conversation.
    void conversation(
            const ConversationId& id, failable_function<void(std::optional<AnyConversation>)> cb);
    void dm(const ConversationId& id, failable_function<void(std::optional<DM>)> cb);
    std::optional<AnyConversation> conversation(const ConversationId& id, wait_t);
    std::optional<DM> dm(const ConversationId& id, wait_t);

    /// The conversation with someone, made if it was not there already — "open a chat with this
    /// account", which is the one thing `conversation()` cannot express.
    ///
    /// Cannot answer "no such conversation": that is the difference from `dm()`, and it is why the
    /// waiting form hands back a `DM` rather than an optional.  Opening one that already exists
    /// changes nothing and simply gives it to you.
    ///
    /// The handler form still carries an optional, because a call that has been dispatched can
    /// still fail — a disk error — and has nowhere to throw.  It is unset only when `error` is set,
    /// never because the conversation was missing.
    ///
    /// Only DMs so far, and so only this one; groups and communities are joined and created rather
    /// than opened, and will say so in their own words when they arrive.
    ///
    /// @throws std::invalid_argument if the id is not a one-to-one conversation.
    void open_dm(const ConversationId& id, failable_function<void(std::optional<DM>)> cb);
    DM open_dm(const ConversationId& id, wait_t);

    /// True if this is our own account's session ID.
    ///
    /// Touches no database and is not dispatched, so it is callable from any thread: it compares
    /// against our own ID, which is fixed once the account exists.  False rather than throwing when
    /// there is no account yet — with no identity, nothing can be us.
    bool is_me(std::span<const std::byte, 33> session_id);

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

    /// A single message by its Client-assigned id, or nullopt if it does not exist.
    void message(int64_t id, failable_function<void(std::optional<Message>)> cb);
    std::optional<Message> message(int64_t id, wait_t);

    /// Blocks or unblocks an account named by id.
    ///
    /// The same operation as `DM::set_blocked`, and forwards to it; it is here as well because
    /// blocking is a fact about a *relationship* rather than about a conversation, and there is not
    /// always a conversation to hang it off — blocking someone whose name you found in a group has
    /// nothing to open first, and opening one would be the wrong thing to do about it.
    ///
    /// @throws std::invalid_argument if the id is not a one-to-one conversation, or is our own.
    void set_blocked(const ConversationId& id, bool blocked, failable_function<void()> cb);
    void set_blocked(const ConversationId& id, bool blocked, wait_t);

    /// Sends to a conversation named by id, creating it if it does not exist.
    ///
    /// The same operation as `Conversation::send_message`, and forwards to it; it is here as well
    /// because this is the one thing that cannot require a conversation to already exist — messaging
    /// an account you have never spoken to is how the conversation begins.  With one in hand, send
    /// through it and skip the lookup.
    ///
    /// See `Conversation::send_message` for what the arguments mean and what `on_upload` reports.
    ///
    /// @throws std::invalid_argument if the conversation is not a DM (groups and communities are
    /// not implemented yet), or if an attachment cannot be read; thrown on the calling thread,
    /// before anything is stored or dispatched.
    void send_message(
            const ConversationId& id,
            std::string_view body,
            failable_function<void(int64_t message_id)> cb);
    void send_message(
            const ConversationId& id,
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            Conversation::upload_progress on_upload,
            failable_function<void(int64_t message_id)> cb);
    int64_t send_message(const ConversationId& id, std::string_view body, wait_t);
    int64_t send_message(
            const ConversationId& id,
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            Conversation::upload_progress on_upload,
            wait_t);
    int64_t send_message(
            const ConversationId& id,
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            wait_t);


    /// Sends a failed message again, resuming rather than restarting: attachments that already
    /// reached the file server are left alone and only the ones that did not are uploaded, because
    /// what each upload achieved is recorded against the message.  A message whose files all got
    /// up but whose send failed is simply dispatched again, uploading nothing.
    ///
    /// Returns false, having done nothing, if the message cannot be retried: it does not exist, it
    /// is not one of ours, it is not in a failed state, or it is SendState::unsendable — that last
    /// being the one an application should offer deletion for rather than a retry, since what it
    /// needs is gone rather than merely unreachable.
    ///
    /// `on_upload` reports as it does for send_message, indexed the same way, so a display built
    /// for the original send works unchanged for the retry.  Note that a retry is where a file
    /// that has since been deleted is discovered: an attachment that has gone moves the message to
    /// SendState::unsendable, which is terminal.
    void retry_send(
            int64_t message_id,
            std::function<
                    void(size_t index, int64_t sent, int64_t total, std::optional<int> result)>
                    on_upload,
            failable_function<void(bool started)> cb);
    bool retry_send(
            int64_t message_id, Conversation::upload_progress on_upload, wait_t);
    bool retry_send(int64_t message_id, wait_t);

    /// Deletes one message from this device: its body, its decrypted content and everything it
    /// recorded about its attachments go, and what is left says only that someone said something
    /// here and when.
    ///
    /// The row stays, marked `Deletion::here`, and this is not squeamishness about the data.  The
    /// swarm still holds the message, and the swarm hash on that row is the only thing that
    /// recognises it if it is delivered again -- which a storage server makes likely rather than
    /// hypothetical, since it stops honouring a `last_hash` once that has expired and answers the
    /// next poll with the whole retention window.  Delete the row and the message comes back
    /// looking new.
    ///
    /// Files are not touched.  An attachment's path names a file the user chose -- one they picked
    /// to send, or a place they asked a download to be put -- so it is theirs in both directions and
    /// nothing here has ever unlinked one.  The rows that described the attachments do go.
    ///
    /// Deleting an unread incoming message makes it read, since there is no longer anything to
    /// read; the conversation's unread count follows.
    ///
    /// This is the whole of "delete for me": nothing is sent, so nothing tells the other side or
    /// our own other devices.  A message deleted here can still be deleted everywhere afterwards,
    /// which is why how far it went is recorded rather than merely that it happened.
    ///
    /// Returns false, having done nothing, if there is no such message.  Deleting one already
    /// deleted here is not an error and changes nothing.
    void delete_message(int64_t message_id, failable_function<void(bool deleted)> cb);
    bool delete_message(int64_t message_id, wait_t);

    /// Removes one deleted message's leftover row.  The conversation-wide form, and the reason a
    /// deletion leaves a row at all — including how this can bring a message back — are on
    /// `Conversation::purge_deleted`.
    ///
    /// Returns false, having done nothing, if the message does not exist or has not been deleted.
    /// Refusing a live message is the point rather than a nicety: this is the one operation here
    /// that removes history outright, and it is only ever entitled to remove what a deletion left.
    void purge_deleted_message(int64_t message_id, failable_function<void(bool removed)> cb);
    bool purge_deleted_message(int64_t message_id, wait_t);

    /// The message as it arrived on the wire, rendered as indented text: one line per field that is
    /// set, named, with nested messages beneath their field and enums by name.
    ///
    /// For seeing what a client actually sent, which nothing else here answers.  A message is
    /// stored twice — as the columns this schema models, and as the whole decrypted `Content` it
    /// came in — and everything else reads the first of those.
    ///
    /// Rendered here rather than handed over as bytes, because the wire format is this layer's to
    /// interpret: nothing above Client parses a protobuf, and the generated headers are kept out of
    /// the public ones deliberately.
    ///
    /// Deliberately not a field on `Message`: this is asked for one message at a time by someone
    /// looking, and putting it on the row would drag the whole wire form through the query that
    /// draws a conversation.
    ///
    /// Returns nullopt when there is nothing to show — which is not an error, and covers three
    /// cases a viewer is free to render alike: a message composed here that was never given a
    /// stored wire form, one whose content has been deleted, and one whose content some later
    /// pruning removed.  Also nullopt if the stored bytes no longer parse, which is corruption
    /// rather than absence and is logged as such.
    void message_debug(
            int64_t message_id, failable_function<void(std::optional<std::string>)> cb);
    std::optional<std::string> message_debug(int64_t message_id, wait_t);

    /// Fetches one of a message's attachments and writes it to `dest`, decrypting it on the way.
    ///
    /// Nothing is downloaded until this is called.  An arriving message records where its files are
    /// and what they are called, and stops there: whether a file is worth the bandwidth is the
    /// application's decision, and on a metered connection it is the user's.
    ///
    /// `dest` is where the caller *asked* for it, and is not remembered.  Where a file went is the
    /// application's business — it chose the location and can move it afterwards — so nothing here
    /// would stay true.  Saving the same attachment twice to two places is therefore fine and means
    /// what it says.  The file is written whole or not at all: it lands at a temporary name beside
    /// `dest` and is renamed only once it has been decrypted and verified, so an interrupted save
    /// leaves no half-file that looks finished.
    ///
    /// **`cb` reports where it actually went**, which is not always `dest`.  Whether `dest` was free
    /// is something the caller decided when it asked its user; the rename happens when the download
    /// finishes, which may be minutes later, and anything that has appeared there in between is a
    /// file nobody agreed to lose.  So by default the finished file takes the next free `name (2)`
    /// instead — before the extension, since only that still opens on a double-click.
    ///
    /// A caller whose user has *already* been shown what is there and said replace it passes
    /// `replace` and gets `dest` whatever has happened since.  That is not the same decision and
    /// must not be guessed at: renaming an approved overwrite would leave the file it was meant to
    /// replace sitting there, which discards the answer the user gave rather than protecting a
    /// stranger's file.
    ///
    /// `on_progress` reports as `send_message`'s `on_upload` does and is indexed the same way, so
    /// a display built for sending works unchanged in the other direction: `result` unset means
    /// under way with `done`/`total` in encrypted bytes, `result == 0` means written and verified,
    /// and anything else is the failure's status code.
    ///
    /// `notify_sender` tells the person who sent it that we saved their file, which is what
    /// Session's other clients do and so what a recipient expects.  Passing false keeps this
    /// particular save to ourselves.  Only ever sent for a message we received: saving from our own
    /// message notifies nobody, and neither does a failed save.
    ///
    /// The account's own preference — `UserProfile::get_notify_media_saved`, which follows it
    /// between devices — can refuse the notification but cannot require one.  So a client that has
    /// not grown a setting for this still honours one made elsewhere, and a caller that passes
    /// false is not overruled.
    ///
    /// Which of Session's two attachment encryptions applies is read from the url, so a caller
    /// neither chooses nor needs to know: current clients still send the legacy scheme, and files we
    /// send use the stream one.
    ///
    /// The error a failure reports is worth showing rather than a generic one: an attachment that
    /// the file server no longer holds, one whose sender described it wrongly, and one that failed
    /// to authenticate are different problems, and only the first is worth retrying.
    ///
    /// @throws std::invalid_argument if `dest` names a directory or its parent does not exist;
    /// thrown on the calling thread, before anything is fetched.
    void save_attachment(
            int64_t message_id,
            size_t index,
            std::filesystem::path dest,
            std::function<
                    void(size_t index, int64_t done, int64_t total, std::optional<int> result)>
                    on_progress,
            failable_function<void(std::filesystem::path saved_to)> cb,
            bool notify_sender = true,
            bool replace = false);

    /// Sets, replaces or removes the dispatcher every handler is delivered through, which a caller
    /// whose loop does not exist yet when the Client is built needs: an application typically opens
    /// its database, constructs this, and only then creates the window that owns the loop.
    ///
    /// Safe to call while Core is running and from any thread.  A handler already on its way either
    /// goes to the old dispatcher or the new one; there is no flush and none is needed, since
    /// passing nullptr simply means what no dispatcher has always meant -- handlers run on Core's
    /// event loop.  An application shutting its loop down therefore has the choice of unsetting
    /// this or having its own dispatcher run the work inline once posting stops arriving anywhere.
    void set_dispatcher(dispatcher d);

    /// How often a handler that reports continuously — such as attachment upload progress — is
    /// allowed to fire, per thing being reported on.  Defaults to 100ms; zero lets every update
    /// through.
    ///
    /// A transfer reports far faster than a display can use, and with a dispatcher each of those
    /// reports is a job handed to the application's loop, which for some toolkits means a repaint.
    /// Squelching the ones in between costs nothing, because each update supersedes the last.
    /// Whatever a caller must not miss — an upload starting, finishing, or failing — is reported
    /// outside this and is never squelched.
    ///
    /// Safe to call while Core is running and from any thread; it applies to transfers begun after
    /// it takes effect.
    void set_high_freq_dispatch_interval(std::chrono::milliseconds interval);

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
    // Shared rather than held, so that a handler queued to another thread stays valid if the
    // Client is destroyed before it runs.
    std::shared_ptr<callbacks> _cbs;

    // Read and written only on the loop, which is what set_dispatcher hops onto rather than
    // synchronising.  Unset means run on the loop.
    dispatcher _dispatcher;

    // As above, and for the same reason.
    std::chrono::milliseconds _high_freq_dispatch_interval{100};

    // Core's send ids are per-process (its counter restarts at 1 on every run), so this mapping
    // must not be persisted or a stale row would capture a later run's status updates.
    struct OutgoingSend {
        int64_t client_id;
        // A note to self goes to our own swarm, so its swarm hash is one we can act on later; a
        // send to someone else deposits on their swarm, and that hash is theirs to expire.
        bool own_swarm;
    };
    std::unordered_map<int64_t, OutgoingSend> _send_ids;  // core send id -> the send it belongs to

    // Status updates that arrived from send_dm() before it returned, i.e. before we knew the core
    // send id to map.  Drained by send_message() once the mapping is registered.
    struct EarlyStatus {
        core::MessageSendStatus status;
        std::optional<std::string> swarm_hash;
    };
    std::unordered_map<int64_t, EarlyStatus> _early_status;

    // Core send ids belonging to the copy of an outgoing message deposited in our own swarm.  Their
    // delivery status is deliberately not reported: what the application waits on is the copy going
    // to the recipient, and a sync copy that fails costs an entry on our other devices rather than
    // the message itself.  Tracked rather than merely unregistered so that a late status does not
    // accumulate in _early_status forever.
    std::unordered_map<int64_t, int64_t> _sync_sends;  // core send id -> client message id

    // Sends whose outcome nobody is waiting for -- the media-saved notification is the only one so
    // far.  Tracked rather than left unregistered so that their statuses are dropped as they
    // arrive, instead of accumulating in _early_status against ids that will never be claimed.
    std::unordered_set<int64_t> _quiet_sends;

    // The actual work, all of it assuming it is already on the loop thread.  The public methods
    // above are dispatches onto that thread and nothing else; these are where the database is
    // touched, and are also what Client's own handlers call, since those already run there.
    //
    std::span<const std::byte> _self_or_none();
    std::vector<AnyConversation> _conversations();
    std::vector<AnyConversation> _message_requests();
    std::optional<AnyConversation> _conversation(const ConversationId& id);
    AnyConversation _create_conversation(const ConversationId& id);
    void _mark_read(const ConversationId& id, std::optional<sys_ms> up_to);
    void _set_priority(const ConversationId& id, int priority);
    void _set_marked_unread(const ConversationId& id, bool unread);
    void _set_notifications(const ConversationId& id, config::notify_mode mode);
    void _set_mute_until(const ConversationId& id, std::chrono::sys_seconds until);
    void _set_expiry(
            const ConversationId& id, config::expiration_mode mode, std::chrono::seconds timer);
    void _set_nickname(const ConversationId& id, std::string_view nickname);

    // One conversation-row column, updated where it differs and re-derived into the config if it
    // did.  Templated on the value only so the caller need not name the bind type.
    template <typename T>
    void _set_conversation_setting(const ConversationId& id, std::string_view column, T value);
    void _set_blocked(const ConversationId& id, bool blocked);
    void _clear_messages(const ConversationId& id);
    void _delete_conversation(const ConversationId& id, bool keep_messages);
    void _delete_contact(const ConversationId& id);
    bool _delete_message(int64_t message_id, Deletion how_far);
    bool _purge_deleted_message(int64_t message_id);
    size_t _purge_deleted(const ConversationId& id);
    std::optional<std::string> _message_debug(int64_t message_id);
    std::vector<Message> _messages(
            const ConversationId& id,
            int limit,
            std::optional<MessageCursor> before,
            bool include_deleted);
    std::optional<Message> _message(int64_t id);
    int64_t _send_message(const ConversationId& id, std::string_view body);
    int64_t _send_message(
            const ConversationId& id,
            std::string_view body,
            const std::vector<OutgoingAttachment>& attachments,
            std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload);

    // Uploads the message's first attachment that has no url yet and, when there are none left,
    // finishes the send.  Each upload's completion calls this again, so the chain runs one file at
    // a time and resumes wherever it was left -- which is also what a retry does.
    void _upload_next(
            int64_t client_id,
            std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload);

    // Rebuilds the message's content with its now-uploaded attachments named in it, replaces what
    // was stored, and dispatches it.  Rebuilt from the database rather than from what send_message
    // was given, so that this is reachable for a message whose uploads finished in an earlier run.
    void _finish_attachment_send(int64_t client_id);

    // Marks a message as failed because its attachments could not be uploaded, and reports it.
    // `permanent` distinguishes a file that is gone, which no amount of retrying will fix, from a
    // transfer that merely did not work this time.
    void _fail_attachment_send(int64_t client_id, bool permanent = false);

    bool _retry_send(
            int64_t client_id,
            std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_upload);

    // Starts the download behind save_attachment.  Everything after the row lookup happens off the
    // loop, on the network's thread: the file is decrypted and written there, and nothing about it
    // is recorded, so this is the one attachment path that never comes back to the database.
    void _save_attachment(
            int64_t message_id,
            size_t index,
            std::filesystem::path dest,
            std::function<void(size_t, int64_t, int64_t, std::optional<int>)> on_progress,
            failable_function<void(std::filesystem::path saved_to)> cb,
            bool notify_sender,
            bool replace);

    // Tells a message's sender that we saved one of its attachments.  Fire and forget: nothing
    // waits on it and a failure is logged rather than reported, since it is a courtesy to them
    // rather than part of what the caller asked for.
    void _notify_media_saved(int64_t message_id, size_t index);

    // Whether *we* are the recipient of a message, which is what makes our own save of one of its
    // attachments worth recording.  True for anything incoming, and for a note to self, where the
    // message is outgoing but the recipient is still us.
    bool _saved_by_recipient(int64_t message_id);

    // Records that the recipient of a message saved one of its attachments: us, for one we
    // received, and them for one we sent.  An unset `index` means all of the message's
    // attachments, which is what a peer saving several at once reports.
    //
    // Told rather than deciding: this is reached both by our own save and by a peer's notification,
    // and only the caller knows which of those it is -- for a message we sent, our save is not the
    // recipient's and theirs is.
    void _record_saved(int64_t message_id, std::optional<size_t> index, sys_ms when);

    // A peer telling us they saved a file we sent them.  `when` is the notification's own
    // timestamp -- when they saved it -- rather than the timestamp identifying which message it is
    // about, which is generally older.
    void _on_media_saved(
            std::span<const std::byte, 33> sender,
            const SessionProtos::DataExtractionNotification& note,
            sys_ms when);

    // Hands a stored message to Core: the recipient's copy and, unless it is a note to self, the
    // copy for our own swarm.  Shared by the plain and attachment-carrying sends.
    void _dispatch_sends(
            int64_t client_id,
            const ConversationId& id,
            const SessionProtos::Content& content,
            const SessionProtos::Content& synced,
            sys_ms now,
            bool to_self);

    // Runs `work` on the loop thread, logging rather than propagating anything it throws: an
    // exception escaping there has no caller to reach and would take the loop with it.
    void _dispatch(std::function<void()> work);

    void _require_dm(std::string_view op, const ConversationId& id);
    void _require_contact(std::string_view op, const ConversationId& id);
    void _require_readable(const std::vector<OutgoingAttachment>& attachments);

    core::callbacks _core_callbacks();
    void _init();

    void _on_message_received(core::ReceivedMessage&& msg);
    void _on_send_status(
            int64_t core_id,
            core::MessageSendStatus status,
            std::optional<std::string_view> swarm_hash);

    // Applies what a config merge changed to the tables that answer queries about it.
    //
    // Every one of these compares against what we already hold and writes only where they differ,
    // rather than trusting the notification to say what moved.  That is what makes them
    // self-correcting: the config cannot describe how far behind our tables are -- a merge can
    // cross several updates at once, and a crash between merging and reconciling leaves them behind
    // by an amount nothing recorded -- so anything a previous pass missed is picked up by the next.
    void _on_configs_changed(std::span<const config::Namespace> changed);

    // Reconciles every config, whether or not anything reported a change.
    //
    // A change notification only arrives for state that changes *after* someone is listening, which
    // leaves three ways for the tables to fall behind with nothing to announce it: a config merged
    // by a version that did not yet know how to reconcile it, a crash between merging and
    // reconciling, and a dump restored from an older state.  In each the database is behind by an
    // amount nothing recorded, and no further notification is owed -- a contact list that has
    // stopped changing would stay unreconciled indefinitely.
    //
    // Safe to run when nothing has changed, because reconciliation compares rather than replays: it
    // costs a pass over the configs and writes nothing.
    void _reconcile_all();

    // Records that a note-to-self conversation now exists, by moving its priority off hidden.
    //
    // For a contact, the presence of an entry in the Contacts config is what says the conversation
    // exists, and priority separately says whether it is shown.  Note to self has no such entry to
    // be present or absent: UserProfile exists from the moment the account does, because it holds
    // the account's own name.  So priority does both jobs there, and a negative value is the only
    // way that config can express "there is no note-to-self conversation" -- which is why a new
    // account writes one, and why putting a message in it has to write the value back.
    //
    // Does nothing if it is already visible, so a pin the user chose is left alone.
    void _reveal_note_to_self(const ConversationId& id);

    // Everything the Contacts config says about the people we know.
    //
    // Each entry projects onto three tables, because it carries three different kinds of fact: who
    // someone is goes on `accounts` (which anyone we have merely *seen* also has), the relationship
    // goes on `contacts`, and how the conversation with them behaves goes on `conversations`.
    //
    // Whose name wins is decided by `profile_updated`, not by which source spoke last: the config's
    // name is applied only when its stamp is at least as new as the one we already hold, so a
    // profile observed on a message that arrived out of order cannot overwrite a newer one.
    void _reconcile_contacts();

    // Re-derives every contact we hold into the Contacts config.
    //
    // A no-op wherever the config already agrees, because assigning a config field its existing
    // value does not dirty it -- so this only writes where the config was actually missing
    // something.  That is what makes it safe to run before the deletion pass, and why it has to be:
    // creating a contact commits the row and updates the config in memory, but the *dump* happens
    // later, so a crash in between leaves a row that the config has never heard of.  Reconciled
    // inward first, that row looks like a contact deleted elsewhere and is destroyed along with its
    // history.  Derived outward first, it is simply published.
    void _sync_all_contacts();

    // Writes what our tables say about one account back into the Contacts config.
    //
    // Re-derived from the rows rather than applied alongside each change, so the mapping lives in
    // one place and cannot drift from the tables it describes: a caller has to remember to call
    // this, but it cannot remember to call it *wrongly*.  Idempotent -- assigning a config field its
    // existing value does not dirty it -- so it is safe to call whenever a row might have moved.
    //
    // Not for our own account: our profile is UserProfile's, and we are not a contact.
    void _sync_contact(const ConversationId& id);

    // As above, for whichever config carries the conversation rather than for a contact
    // specifically.  The dispatch is the point: something that has changed a conversation should
    // not have to know that note to self lives in UserProfile while everybody else lives in
    // Contacts.
    void _sync_conversation(const ConversationId& id);

    // Read state — the watermark and the marked-unread flag — from ConvoInfoVolatile.
    //
    // Deliberately without the deletion pass that Contacts has.  That config is pruned by age
    // rather than by anyone noticing a removal, so an entry absent from it means only that nothing
    // has been read in that conversation lately, and treating absence as a deletion would destroy
    // conversations for having been quiet.
    //
    // Runs after whatever might have created a conversation, because read state about one we do not
    // have is nothing we can apply and nothing we should create a conversation from.
    void _reconcile_convo_volatile();

    // The other direction, for one conversation and for all of them.
    //
    // The watermark only ever moves forwards, in both directions.  The config does not enforce that
    // — it permits a value to be written backwards on purpose — and a conflict between two devices
    // at the same seqno resolves by a tie-break that knows nothing about which value is newer, so
    // without this a stale device would make read messages unread everywhere.
    void _sync_convo_volatile(const ConversationId& id);
    void _sync_all_convo_volatile();

    // Records a delete-before instruction in the config that carries this conversation, so that
    // every device deletes the same history rather than only the one the user was looking at.
    //
    // Never moves the instruction backwards.  Two devices clearing at different moments merge to
    // one value, and the one that destroys more is the one that was asked for.
    void _set_delete_before(const ConversationId& id, sys_ms before);

    // Our own name and picture, and the note-to-self conversation's settings.
    //
    // This one runs the opposite way round to the others: UserProfile is authoritative and the
    // `accounts` row is a projection of it, because the config holds structure the row does not
    // model -- a second picture slot, carrying the same image at a fresh URL, which exists so a
    // linked device that already has those bytes can skip re-downloading them.  Deriving the config
    // back from the row would flatten the two slots and destroy another device's reupload.
    void _reconcile_user_profile();

    // `swarm_hash` is recorded against the message only when it names a copy in our own swarm; the
    // caller passes nullopt for the copy sent to someone else, whose hash is meaningless here.
    void _apply_send_status(
            int64_t client_id,
            core::MessageSendStatus status,
            bool sync,
            std::optional<std::string_view> swarm_hash);

    // Runs `invoke` against the application's handlers, swallowing and logging anything it throws:
    // a broken listener is not something a data model can do anything about.
    void _emit(std::function<void(const callbacks&)> invoke);

    // Hands anything Client says outward to the dispatcher, or runs it here if there is none.
    // Everything the application supplied goes through this: the change notifications, and the
    // handlers given to individual calls.  Only called on the loop, which is what lets the
    // dispatcher itself be an ordinary member.
    void _dispatch_out(std::function<void()> job);

    // Calls `cb` with `args`, on the application's thread, if it gave us one.
    template <typename Cb, typename... A>
    void _report(Cb& cb, A... args) {
        if (!cb)
            return;
        _dispatch_out([cb, args = std::make_tuple(std::move(args)...)]() mutable {
            std::apply(cb, std::move(args));
        });
    }

    // Runs `produce` on the loop and reports what it produced to `cb`, or reports the reason it
    // could not.  This is what makes "`cb` is invoked exactly once" true: the work is database
    // access, which throws on a disk error, and by then the caller's stack is gone -- so the
    // callback they gave us is the only way left to tell them.  Logging it and returning would
    // leave them waiting for an answer that is never coming.
    template <typename Produce, typename Cb>
    void _async(Produce produce, Cb cb) {
        loop.call([this, produce = std::move(produce), cb = std::move(cb)]() mutable {
            using Result = decltype(produce());
            try {
                if constexpr (std::is_void_v<Result>) {
                    produce();
                    _report(cb, std::optional<std::string>{});
                } else
                    _report(cb, std::optional<std::string>{}, produce());
            } catch (const std::exception& e) {
                log_operation_failure(e);
                // Whatever a default value is: the caller is being told not to read it.
                if constexpr (std::is_void_v<Result>)
                    _report(cb, std::optional{std::string{e.what()}});
                else
                    _report(cb, std::optional{std::string{e.what()}}, Result{});
            }
        });
    }

    // Out of line so that the logging category does not have to be reachable from this header.
    static void log_operation_failure(const std::exception& e);

    void _emit_conversation_added(const ConversationId& id);
    void _emit_conversation_removed(const ConversationId& id);
    void _emit_lists_replaced();
    void _emit_history_replaced(const ConversationId& id);
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

    /// Helper reference to Core's event loop, which is where this class does its work.
    oxen::quic::Loop& loop{core.loop()};

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
