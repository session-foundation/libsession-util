#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <session/client/conversation_id.hpp>
#include <session/clock.hpp>
#include <session/util.hpp>
#include <string>

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

    /// Terminal, and unlike `failed` not worth trying again: something the message needs is gone
    /// rather than merely unreachable.  Currently that means an attachment whose file is no longer
    /// where it was — retrying re-reads the same path and will fail identically every time.
    ///
    /// Kept apart from `failed` so that an application knows which failures to offer a retry for,
    /// and which to offer only deletion.
    unsendable = 6,

    /// Attachments are being uploaded to the file server.  The message exists and is displayable,
    /// but nothing has gone to a swarm yet: it cannot, because the message has to carry the
    /// pointers the upload is still producing.  How far along that is, is reported to whoever asked
    /// for the send, through the progress handler they passed to send_message.
    uploading = 5,
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

    /// Delivery of the copy sent to the recipient — what "did it arrive" ordinarily means, and
    /// what a message list normally shows.  Unset on an incoming message.
    std::optional<SendState> send_state;

    /// Delivery of the copy deposited in our own swarm, which is how our other devices come to see
    /// a message we sent.  A separate send, retried separately, so it can still be pending when the
    /// recipient already has the message — worth surfacing somewhere detailed rather than in the
    /// message list, since it says nothing about whether the message arrived.
    ///
    /// Unset on an incoming message, and on a note to self, where the recipient's swarm is our own
    /// and `send_state` already describes the only send there was.
    std::optional<SendState> sync_send_state;

    /// Swarm-assigned hash of the copy of this message held in *our own* swarm: for an incoming
    /// message the one we retrieved, and for an outgoing one the copy we deposit for our other
    /// devices (which for a note to self is the only copy there is).  The copy sent to someone
    /// else is stored in their swarm under a different hash, which is not reported here.
    ///
    /// Unset for an outgoing message that has not been stored yet, and for one stored by a build
    /// whose storage server did not report a hash.
    std::optional<std::string> hash;

    MessageCursor cursor() const { return {timestamp, id}; }
};

}  // namespace session::client
