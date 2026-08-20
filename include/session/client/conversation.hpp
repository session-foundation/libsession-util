#pragma once

#include <session/client/conversation_id.hpp>
#include <session/clock.hpp>
#include <string>

namespace session::client {

struct Conversation {
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
    /// negative on anything reached that way.  conversation(id) still returns one, since naming a
    /// conversation is not the same as asking what the list contains — and it is how a hidden
    /// conversation is reached at all.
    ///
    /// Conversations sort by priority before recency, and equal priorities form a block that sorts
    /// among itself by last_activity — so pinning several conversations together keeps them at the
    /// top while still letting the most recently active of them lead.
    int priority = 0;

    /// True while this is a message request rather than a conversation: someone we have never
    /// written to has written to us.
    ///
    /// Approval is not something anyone sets — it is recorded by messages flowing.  Writing to
    /// someone approves them, so answering a request is what accepts it, and there is no way back:
    /// what un-requests a conversation is deleting the contact, not clearing a flag.
    ///
    /// Requests are conversations in every other respect — they have history, an unread count and a
    /// name — which is why this is a property of one rather than a separate kind.  What differs is
    /// which list it belongs to: `conversations()` omits them and `message_requests()` returns only
    /// them, so this is never true on anything the former returned.
    ///
    /// Never true for note to self, and (for now) never true for a group or community.
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
    /// and what can make `request` true.  Exempt for note to self and, for now, for groups and
    /// communities.
    bool awaiting_approval = false;

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

}  // namespace session::client
