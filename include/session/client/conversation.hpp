#pragma once

#include <session/client/conversation_id.hpp>
#include <session/clock.hpp>
#include <string>
#include <variant>

namespace session::client {

/// What every conversation has, whatever kind it is: enough to draw a row in a list and to sort it
/// among the others.  The kinds below add what only they can answer.
///
/// A snapshot, not a handle.  These are copied out of the database and handed to an application,
/// including onto another thread, so what one says was true when it was taken and may not be by the
/// time it is read.  Anything that *does* something to a conversation takes an id instead — see
/// `Client::conversation()` — because an id stays meaningful and a snapshot does not.
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
    /// Hidden is a statement about the *list*: conversations() omits them, so this is never
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
};

/// A one-to-one conversation with another account.
class DM : public Conversation {
  public:
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
};

/// A closed group.  Nothing of its own yet: what distinguishes a group — its membership, who
/// administers it, whether we have accepted the invitation — arrives with UserGroups.
class Group : public Conversation {};

/// A community (open group) room.  As above: moderation and room metadata arrive with the config
/// that carries them.
class Community : public Conversation {};

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

    /// Everything every kind has.  The accessors below are shorthands for reaching through this.
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
    const DM* dm() const { return std::get_if<DM>(&kind); }
    const Group* group() const { return std::get_if<Group>(&kind); }
    const Community* community() const { return std::get_if<Community>(&kind); }
};

}  // namespace session::client
