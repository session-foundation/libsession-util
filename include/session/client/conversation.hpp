#pragma once

#include <session/client/conversation_id.hpp>
#include <session/clock.hpp>
#include <string>

namespace session::client {

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
