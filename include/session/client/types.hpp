#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <session/client/conversation_id.hpp>
#include <session/clock.hpp>
#include <session/util.hpp>
#include <string>

/// The values the conversation layer hands out.  Split from client.hpp so that signals.hpp can name
/// them without depending on Client, which depends on signals.hpp in turn.
namespace session::client {

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
