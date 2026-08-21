#pragma once

#include <optional>
#include <session/client/attachment.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/handler.hpp>
#include <session/client/message.hpp>
#include <session/clock.hpp>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace session::client {

class Client;

/// A conversation: what it looks like, and everything you can do to it.
///
/// **The values are a snapshot; the operations are not.**  The fields were read when this was
/// handed to you, and the conversation may have moved on since — another device can rename, pin or
/// delete it at any moment.  The operations do not read the fields; they act through `id`, which
/// stays meaningful however old this object is.  So a stale object still does the right thing when
/// acted on, and only what it *says* can be out of date.  To see current values, ask for it again.
///
/// There is no way to obtain one that was never populated: `Client::conversation()` fetches one,
/// `conversations()` lists them, `open_dm()` makes one, and the callbacks hand them over — each of
/// those has read the database.  So an empty `display_name` means nobody knows their name, never
/// that this object has not looked yet.
///
/// Every operation comes in two forms: one taking a handler, which returns immediately and reports
/// later, and one taking `wait`, which blocks the calling thread and throws instead of reporting.
/// See `wait_t` for which to use where.
///
/// Cheap to copy and safe to hold, including on another thread — but it names a Client and must not
/// outlive it.
class Conversation {
  public:
    ConversationId id;

    /// Best known display name, or empty if none is known yet.
    ///
    /// For a DM this is the nickname we gave them if there is one, and otherwise the name they gave
    /// themselves — learned either from the `LokiProfile` on a message or from the Contacts config,
    /// whichever is the fresher.  Empty is normal and expected: an account we have seen but know
    /// nothing else about has no name, and the caller decides how to render that.
    std::string display_name;

    /// Body of the most recent message, for a conversation-list preview.  Empty if the
    /// conversation has no messages or the latest carries no text.
    std::string last_message;

    /// Timestamp of the most recent message, or the conversation's creation time if it has none.
    sys_ms last_activity;

    /// Count of incoming messages newer than the read watermark.
    int unread = 0;

    /// Deliberately marked unread — "come back to this" — rather than having unread messages.
    ///
    /// Independent of `unread`: it survives having read everything, which is what it is for, and
    /// reading the conversation is what clears it.  Synced, so it arrives from other devices too.
    bool marked_unread = false;

    /// Pinning, numerically identical to the value the Contacts and UserGroups configs sync: 0 is
    /// unpinned, a positive value is pinned with higher values first, and a negative value is
    /// hidden.
    ///
    /// Hidden is a statement about the *list*: `conversations()` omits them, so this is never
    /// negative on anything reached that way.  Naming a conversation still reaches one, since that
    /// is not the same as asking what the list contains — and it is how a hidden conversation is
    /// reached at all.
    ///
    /// Conversations sort by priority before recency, and equal priorities form a block that sorts
    /// among itself by last_activity — so pinning several conversations together keeps them at the
    /// top while still letting the most recently active of them lead.
    int priority = 0;

    /// The display name if known, otherwise the conversation's string id — a reasonable default
    /// for a caller that has no better fallback of its own.
    std::string name_or_id() const { return display_name.empty() ? id.to_string() : display_name; }

    Conversation(Client& client, ConversationId id) : id{std::move(id)}, _client{&client} {}

    // -- Reading ------------------------------------------------------------------------------

    /// A window of history, newest first.  Pass the `cursor()` of the last message of a page as
    /// `before` to fetch the next (older) page; the message at the cursor is not repeated.
    void messages(failable_function<void(std::vector<Message>)> cb) const;
    void messages(int limit, failable_function<void(std::vector<Message>)> cb) const;
    void messages(
            int limit,
            std::optional<MessageCursor> before,
            failable_function<void(std::vector<Message>)> cb) const;
    std::vector<Message> messages(wait_t) const;
    std::vector<Message> messages(int limit, wait_t) const;
    std::vector<Message> messages(int limit, std::optional<MessageCursor> before, wait_t) const;

    // -- Read state ---------------------------------------------------------------------------

    /// Marks incoming messages up to and including `up_to` as read, moving the unread watermark
    /// forward.  Passing nullopt marks everything currently stored as read — which is not the same
    /// as parking the watermark at infinity: a message that arrives afterwards is still unread,
    /// even if its timestamp is older than the one we just read to.
    ///
    /// Never moves the watermark backwards.  Clears `marked_unread`, since reading the conversation
    /// is the thing that was being asked for.
    void mark_read(failable_function<void()> cb);
    void mark_read(std::optional<sys_ms> up_to, failable_function<void()> cb);
    void mark_read(wait_t);
    void mark_read(std::optional<sys_ms> up_to, wait_t);

    /// Marks the conversation unread, or clears that — the deliberate "I want to come back to this"
    /// rather than a count of messages.  Synced, so it follows you between devices.
    void set_marked_unread(bool unread, failable_function<void()> cb);
    void set_marked_unread(bool unread, wait_t);

    // -- Settings -----------------------------------------------------------------------------

    /// Sets pinning: 0 unpinned, positive pinned with higher values first, negative hidden.
    ///
    /// Reported to subscribers as `conversation_list_replaced`, not as an update to the one
    /// conversation, because hiding removes a conversation from the list and unhiding returns it —
    /// so what changed is the list, not a row in it.
    void set_priority(int priority, failable_function<void()> cb);
    void set_priority(int priority, wait_t);

    // -- Sending ------------------------------------------------------------------------------

    /// Sends a text message, storing it immediately and dispatching it via Core.  Yields the
    /// Client message id of the stored row, which is what subsequent `message_updated` handlers
    /// carry as delivery progresses.
    void send_message(std::string_view body, failable_function<void(int64_t message_id)> cb);
    int64_t send_message(std::string_view body, wait_t);

    /// Sends a message carrying files, which turns sending into two stages: each attachment is
    /// encrypted and uploaded to the file server, and only then is the message — now able to name
    /// where those files live — dispatched to the swarms.
    ///
    /// Returns as soon as the row is stored, as the plain overload does, so the message is
    /// displayable immediately; it sits in `SendState::uploading` until the uploads finish and
    /// moves on to the ordinary send states from there.  An upload that fails fails the message,
    /// leaving it in `SendState::failed` with nothing sent.
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
    /// @throws std::invalid_argument if any attachment's file cannot be opened or exceeds the file
    /// server's limit; thrown on the calling thread, before anything is stored or dispatched.
    using upload_progress =
            std::function<void(size_t index, int64_t sent, int64_t total, std::optional<int> result)>;
    void send_message(
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            upload_progress on_upload,
            failable_function<void(int64_t message_id)> cb);
    int64_t send_message(
            std::string_view body,
            std::vector<OutgoingAttachment> attachments,
            upload_progress on_upload,
            wait_t);

    // -- Destroying ---------------------------------------------------------------------------
    //
    // Named for what a user is choosing rather than for what happens underneath — "delete
    // conversation" and "delete contact" differ by what they leave behind, not by how they delete.
    // They are composed here, and not left to a UI to assemble out of smaller pieces, because every
    // Session client has to compose them the same way: which fields a deletion resets, and what it
    // tells other devices, is part of what the operation *is*, and three clients each deriving it
    // separately is three chances to diverge.
    //
    // The deletion is *synced as an instruction*, not as a local act.  Clearing records the moment
    // it was cleared, so every device deletes what it holds from before then — including messages
    // this one never had, and messages that arrive afterwards but are older than the instruction.
    // A device that was offline for the whole thing catches up when it merges, rather than keeping
    // a history its owner told it to destroy.

    /// Deletes the messages, keeping the conversation itself and everything that describes it — the
    /// contact, the nickname, the pin.
    void clear_messages(failable_function<void()> cb);
    void clear_messages(wait_t);

    /// Removes the conversation from the list without forgetting who it is with: the contact entry
    /// stays, so a nickname and an approval survive, and a new message brings the conversation
    /// back.
    ///
    /// `keep_messages` distinguishes the two things a UI calls this for.  Deleting a conversation
    /// destroys its history; hiding one — which is what "Hide" on Note to Self does — leaves the
    /// history to come back with it.
    void delete_conversation(failable_function<void()> cb);
    void delete_conversation(bool keep_messages, failable_function<void()> cb);
    void delete_conversation(wait_t);
    void delete_conversation(bool keep_messages, wait_t);

  protected:
    /// Never null, and not owned: the Client this came from, which must outlive it.
    Client* _client;
};

/// A one-to-one conversation with another account.
class DM : public Conversation {
  public:
    explicit DM(Conversation base) : Conversation{std::move(base)} {}

    /// True while this is a message request rather than a conversation: someone we have never
    /// written to has written to us.
    ///
    /// Approval is not something anyone sets — it is recorded by messages flowing.  Writing to
    /// someone approves them, so answering a request is what accepts it, and there is no way back:
    /// what un-requests a conversation is deleting the contact, not clearing a flag.
    ///
    /// Requests are conversations in every other respect — they have history, an unread count and a
    /// name — which is why this is a property of one rather than a kind of its own.  What differs
    /// is which list it belongs to: `conversations()` omits them and `message_requests()` returns
    /// only them, so this is never true on anything the former returned.
    ///
    /// Never true for note to self.
    bool request = false;

    /// The mirror of `request`: we have written to someone who has never written back, so they have
    /// us in *their* message requests and have not answered.
    ///
    /// Set from the same evidence, read the other way round — nobody sends anything to say they
    /// accepted, so the only thing that clears this is a message from them.  A display showing
    /// "waiting for them to accept" wants this; the conversation is otherwise ordinary and is in
    /// `conversations()` like any other, because it is one we chose to start.
    ///
    /// The two are mutually exclusive: their having written to us is exactly what makes this false
    /// and what can make `request` true.
    bool awaiting_approval = false;

    /// True for the conversation with our own account — Session's "Note to Self".  It is an
    /// ordinary DM rather than a kind of its own, so this is the only thing distinguishing it, and
    /// it is reported here so that displaying it differently does not require the caller to know
    /// our session ID or to compare it themselves.  What to call it is still the caller's
    /// decision: `display_name` is whatever our own profile says, not a localised label.
    bool note_to_self = false;

    /// Blocks or unblocks the account.  Blocking is synced, so it takes effect on every device, and
    /// what they send is refused on arrival rather than hidden when drawing.
    ///
    /// Blocking someone we hold no contact entry for creates one, since being blocked is a fact
    /// about a relationship and there is nowhere else to record it.  It does not approve them, and
    /// unblocking does not undo anything else the block implied.
    void set_blocked(bool blocked, failable_function<void()> cb);
    void set_blocked(bool blocked, wait_t);

    /// Deletes the contact along with the conversation and its history, everywhere.
    ///
    /// This is the strong one: the entry goes from the Contacts config, so every device drops the
    /// conversation rather than merely hiding it, and what the entry held — the nickname, the
    /// approval in both directions, the block — goes with it.  Deleting a blocked contact therefore
    /// unblocks them; the block lived in the entry that was removed.
    ///
    /// What survives is the account itself, because we may still see them in a group or a
    /// community and need their name to render it.  A message from them afterwards arrives as a
    /// message request, exactly as one from a stranger would.
    ///
    /// Takes no `keep_messages`: there would be no conversation left to keep them in.
    ///
    /// @throws std::invalid_argument for our own account, which is not a contact of ours.
    void delete_contact(failable_function<void()> cb);
    void delete_contact(wait_t);
};

/// A closed group.  Nothing of its own yet: what distinguishes a group — its membership, who
/// administers it, whether we have accepted the invitation — arrives with UserGroups.
class Group : public Conversation {
  public:
    explicit Group(Conversation base) : Conversation{std::move(base)} {}
};

/// A community (open group) room.  As above: moderation and room metadata arrive with the config
/// that carries them.
class Community : public Conversation {
  public:
    explicit Community(Conversation base) : Conversation{std::move(base)} {}
};

/// A conversation of whichever kind it turned out to be.
///
/// The kind is a variant rather than a pointer so that a list of these is one contiguous block with
/// no allocation per row — a conversation list is re-read on every redraw, which makes it the one
/// place where that matters.  Reading a field common to every kind costs a compare against the
/// variant's discriminant and nothing else: each alternative holds its `Conversation` at the same
/// offset, so the compiler folds the dispatch away entirely.
///
/// **Keep `Conversation` the first base of any kind added here.** A second base ahead of it moves
/// the shared fields to a different offset in that one alternative, and the accessors below quietly
/// become a runtime selection instead of nothing at all.
class AnyConversation {
  public:
    std::variant<DM, Group, Community> kind;

    AnyConversation(DM c) : kind{std::move(c)} {}
    AnyConversation(Group c) : kind{std::move(c)} {}
    AnyConversation(Community c) : kind{std::move(c)} {}

    /// Everything every kind has, values and operations alike.  The shorthands below reach through
    /// this; it is here for anything they do not cover.
    Conversation& base() {
        return std::visit([](auto& c) -> Conversation& { return c; }, kind);
    }
    const Conversation& base() const {
        return std::visit([](const auto& c) -> const Conversation& { return c; }, kind);
    }

    const ConversationId& id() const { return base().id; }
    const std::string& display_name() const { return base().display_name; }
    const std::string& last_message() const { return base().last_message; }
    sys_ms last_activity() const { return base().last_activity; }
    int unread() const { return base().unread; }
    bool marked_unread() const { return base().marked_unread; }
    int priority() const { return base().priority; }
    std::string name_or_id() const { return base().name_or_id(); }

    /// The kind, or nullptr if it is not that one.  This is how a caller asks a question only one
    /// kind can answer — whether a conversation is a message request, who administers a group —
    /// and the nullptr is what stops that question being asked of a kind it means nothing to.
    DM* dm() { return std::get_if<DM>(&kind); }
    Group* group() { return std::get_if<Group>(&kind); }
    Community* community() { return std::get_if<Community>(&kind); }
    const DM* dm() const { return std::get_if<DM>(&kind); }
    const Group* group() const { return std::get_if<Group>(&kind); }
    const Community* community() const { return std::get_if<Community>(&kind); }

// Forwarded rather than reimplemented, so that an overload added to Conversation is reachable here
// without anything being added below.
#define SESSION_CONVO_FORWARD(name)                                        \
    template <typename... A>                                               \
    decltype(auto) name(A&&... a) {                                        \
        return base().name(std::forward<A>(a)...);                         \
    }                                                                      \
    template <typename... A>                                               \
    decltype(auto) name(A&&... a) const {                                  \
        return base().name(std::forward<A>(a)...);                         \
    }

    SESSION_CONVO_FORWARD(messages)
    SESSION_CONVO_FORWARD(mark_read)
    SESSION_CONVO_FORWARD(set_marked_unread)
    SESSION_CONVO_FORWARD(set_priority)
    SESSION_CONVO_FORWARD(send_message)
    SESSION_CONVO_FORWARD(clear_messages)
    SESSION_CONVO_FORWARD(delete_conversation)

#undef SESSION_CONVO_FORWARD
};

}  // namespace session::client
