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
    // answer than be handed it uses SyncClient.
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

    /// All conversations, most recently active first.
    ///
    /// Currently that means every conversation.  Once message requests exist this returns only
    /// approved ones, with the rest reached through their own accessor.
    void conversations(failable_function<void(std::vector<Conversation>)> cb);

    /// A single conversation, or nullopt if it does not exist locally.
    void conversation(
            const ConversationId& id, failable_function<void(std::optional<Conversation>)> cb);

    /// Creates the conversation if it does not exist and returns it.  Sending to a conversation
    /// does this implicitly; this is for opening an empty conversation with someone first.
    void create_conversation(
            const ConversationId& id, failable_function<void(std::optional<Conversation>)> cb);

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
    void mark_read(const ConversationId& id, failable_function<void()> cb);
    void mark_read(
            const ConversationId& id, std::optional<sys_ms> up_to, failable_function<void()> cb);

    /// Sets a conversation's pinning: 0 unpinned, positive pinned with higher values first,
    /// negative hidden.  The value is the one the Contacts and UserGroups configs carry, so this is
    /// also where a config update from another device lands once that reconciliation exists.
    ///
    /// Reported to subscribers as `conversation_list_replaced`, not as an update to the one
    /// conversation, because hiding removes a conversation from the list and unhiding returns it —
    /// so what changed is the list, not a row in it.
    void set_priority(const ConversationId& id, int priority, failable_function<void()> cb);

    /// A window of a conversation's history, newest first.  Pass the `cursor()` of the last
    /// message of a page as `before` to fetch the next (older) page; the message at the cursor is
    /// not repeated.
    void messages(const ConversationId& id, failable_function<void(std::vector<Message>)> cb);
    void messages(
            const ConversationId& id, int limit, failable_function<void(std::vector<Message>)> cb);
    void messages(
            const ConversationId& id,
            int limit,
            std::optional<MessageCursor> before,
            failable_function<void(std::vector<Message>)> cb);

    /// A single message by its Client-assigned id, or nullopt if it does not exist.
    void message(int64_t id, failable_function<void(std::optional<Message>)> cb);

    /// Sends a text message, storing it immediately and dispatching it via Core.
    ///
    /// Yields the Client message id of the stored row, which is what subsequent
    /// ChangeType::message_updated signals carry as delivery progresses.  Creates the conversation
    /// if it does not already exist.
    ///
    /// @throws std::invalid_argument if the conversation is not a DM (groups and communities are
    /// not implemented yet); thrown on the calling thread, before anything is dispatched.
    void send_message(
            const ConversationId& id,
            std::string_view body,
            failable_function<void(int64_t message_id)> cb);

    /// Sends a message carrying files, which turns sending into two stages: each attachment is
    /// encrypted and uploaded to the file server, and only then is the message — now able to name
    /// where those files live — dispatched to the swarms.
    ///
    /// Returns as soon as the row is stored, as the plain overload does, so the message is
    /// displayable immediately; it sits in SendState::uploading until the uploads finish and moves
    /// on to the ordinary send states from there.  An upload that fails fails the message, leaving
    /// it in SendState::failed with nothing sent.
    ///
    /// `on_upload` follows one attachment, identified by `index`, its position in `attachments`:
    ///
    /// - `result` unset — under way.  `sent`/`total` are encrypted bytes.  The first such report
    ///   for an attachment is always 0/0 and means it has started rather than that it has sent
    ///   nothing: it comes before the transfer is established, which is what tells an attachment
    ///   being worked on from one still waiting its turn.  The size is not known until then, so a
    ///   progress bar is sized from the first report carrying a non-zero total.
    /// - `result == 0` — done, and the file server gave us an id for it.  Note this is the only
    ///   thing that means done: `sent == total` merely means the last byte was acknowledged, and
    ///   the server's decision to accept the file arrives after that.
    /// - anything else — that attachment failed, with the file server's status code or one of the
    ///   network layer's own negative codes.  The message fails as a whole, but this is reported
    ///   per attachment, so a list of them can mark the one that broke rather than all of them.
    ///
    /// Reports for one attachment arrive in order — progress, then exactly one result — but
    /// reports for different attachments may interleave, and a failure does not stop the others
    /// being reported.  An attachment that never produces a result was not attempted, or had not
    /// finished when the message failed; either way that is not something to read as success.
    ///
    /// It is taken here rather than through `callbacks` because it belongs to this call: those
    /// handlers report what the network did to us, whereas this reports how something we asked for
    /// is going, and a caller passing it here can bind whatever it wants to update without matching
    /// an id back to it.
    ///
    /// Progress fires as often as the transfer reports, which on a fast upload is often; coalescing
    /// is the caller's to do, since dropping intermediate values loses nothing.  Like the
    /// `callbacks` handlers it runs on Core's event loop, so it must not block or throw — and note
    /// it can fire before this function returns, so it must not depend on anything the caller sets
    /// up afterwards.
    ///
    /// The files are read at this point, not when they were attached, so they must still exist.
    /// Nothing about them is stored: what persists is the message, whose content names the uploaded
    /// copies.  Re-sending a failed message therefore uploads again.
    ///
    /// @throws std::invalid_argument if the conversation is not a DM, or if any attachment's file
    /// cannot be opened or exceeds the file server's limit; thrown on the calling thread, before
    /// anything is stored or dispatched.
    void send_message(
            const ConversationId& id,
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            std::function<
                    void(size_t index, int64_t sent, int64_t total, std::optional<int> result)>
                    on_upload,
            failable_function<void(int64_t message_id)> cb);

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

    /// Fetches one of a message's attachments and writes it to `dest`, decrypting it on the way.
    ///
    /// Nothing is downloaded until this is called.  An arriving message records where its files are
    /// and what they are called, and stops there: whether a file is worth the bandwidth is the
    /// application's decision, and on a metered connection it is the user's.
    ///
    /// `dest` is the caller's choice and is not remembered.  Where a file went is the application's
    /// business — it chose the location and can move it afterwards — so nothing here would stay
    /// true.  Saving the same attachment twice to two places is therefore fine and means what it
    /// says.  The file is written whole or not at all: it lands at a temporary name beside `dest`
    /// and is renamed only once it has been decrypted and verified, so an interrupted save leaves
    /// no half-file that looks finished.
    ///
    /// `on_progress` reports as `send_message`'s `on_upload` does and is indexed the same way, so
    /// a display built for sending works unchanged in the other direction: `result` unset means
    /// under way with `done`/`total` in encrypted bytes, `result == 0` means written and verified,
    /// and anything else is the failure's status code.
    ///
    /// `notify_sender` tells the person who sent it that we saved their file, which is what
    /// Session's other clients do and so what a recipient expects.  Passing false keeps the save to
    /// ourselves -- worth offering as a setting, since whether fetching someone's photo should be
    /// reported back to them is a privacy decision rather than a technical one.  Only ever sent for
    /// a message we received: saving from our own message notifies nobody, and neither does a
    /// failed save.
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
            failable_function<void()> cb,
            bool notify_sender = true);

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

  protected:
    // Reachable by SyncClient, which dispatches onto the loop exactly as the callback forms do.
    // Everything here assumes it is already on that thread.

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
  protected:
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
            failable_function<void()> cb,
            bool notify_sender);

    // Tells a message's sender that we saved one of its attachments.  Fire and forget: nothing
    // waits on it and a failure is logged rather than reported, since it is a courtesy to them
    // rather than part of what the caller asked for.
    void _notify_media_saved(int64_t message_id, size_t index);

    // Records that the recipient of a message saved one of its attachments: us, for one we
    // received, and them for one we sent.  An unset `index` means all of the message's
    // attachments, which is what a peer saving several at once reports.
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
  private:
    void _dispatch(std::function<void()> work);

  protected:
    void _require_dm(const ConversationId& id);
    void _require_readable(const std::vector<OutgoingAttachment>& attachments);

  private:
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

    // Writes what our tables say about one account back into the Contacts config.
    //
    // Re-derived from the rows rather than applied alongside each change, so the mapping lives in
    // one place and cannot drift from the tables it describes: a caller has to remember to call
    // this, but it cannot remember to call it *wrongly*.  Idempotent -- assigning a config field its
    // existing value does not dirty it -- so it is safe to call whenever a row might have moved.
    //
    // Not for our own account: our profile is UserProfile's, and we are not a contact.
    void _sync_contact(const ConversationId& id);

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
