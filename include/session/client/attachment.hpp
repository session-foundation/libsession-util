#pragma once

#include <filesystem>
#include <optional>
#include <session/clock.hpp>
#include <string>

namespace session::client {

/// Reported through send_message's upload handler when an attachment's file is no longer at the
/// path it was attached from, which can happen between attaching and sending, or to a message
/// being resumed in a later run.  Deliberately outside the network layer's code space: nothing
/// about this came from the network, and the message becomes SendState::unsendable rather than
/// merely failed.
constexpr int ATTACHMENT_FILE_MISSING = -20001;

/// Reported through save_attachment's progress handler when the file arrived but could not be
/// turned back into the file it claims to be: it failed to authenticate, its sender described it
/// wrongly, or it could not be written.  Distinct from a transfer failure, and unlike one it is not
/// worth retrying -- the bytes on the file server will be the same bytes next time.
constexpr int ATTACHMENT_UNREADABLE = -20002;

/// A file to attach to an outgoing message.  Attaching costs nothing: the file is read, encrypted
/// and uploaded when the message is sent, not when it is attached, so a caller can hold these
/// against a draft for as long as the user takes to write it.
struct OutgoingAttachment {
    /// The file to send.  Read at send time, so it must still be there and unchanged by then.
    std::filesystem::path path;

    /// MIME type to advertise.  Recipients use it to decide how to display the attachment; when
    /// unset it is inferred from the filename's extension.
    std::optional<std::string> content_type;

    /// Name to advertise, defaulting to `path`'s filename.  Worth setting explicitly when the
    /// local file is a temporary whose name means nothing to the recipient.
    std::optional<std::string> filename;

    /// Text shown with the attachment.  Distinct from the message body, which is shown as its own
    /// message.
    std::optional<std::string> caption;

    /// Marks this as a recorded voice message rather than an ordinary audio file, which clients
    /// present differently.
    bool voice_message = false;

    /// Pixel dimensions, for visual media.  Recipients use them to lay out a placeholder before
    /// the file itself has been fetched, so supplying them avoids the layout jumping.
    ///
    /// TODO: these are the caller's to supply because libsession cannot read them -- deriving them
    /// means either an image library or hand-written header parsing of untrusted files.  Worth
    /// revisiting if libsession takes on an image dependency for other reasons (thumbnailing, say),
    /// at which point every client stops needing its own.
    std::optional<uint32_t> width;
    std::optional<uint32_t> height;
};

/// An attachment on a stored message, in either direction, as reported on `Message::attachments`.
///
/// The descriptive fields are the same ones `OutgoingAttachment` supplies, and on an incoming
/// attachment they are the sender's claims: nothing here has been checked against the file, which
/// has usually not been fetched at all.  In particular `content_type` and `filename` are chosen by
/// whoever sent it, so treat them as display hints rather than as facts about the bytes.
/// How an attachment transfer is going.
///
/// Reported two ways, for the two kinds of transfer: handed directly to whoever called
/// `save_attachment`, and — for a download nobody asked for — broadcast through
/// `callbacks::attachment_progress`, since a background fetch has no caller to hand anything to.
struct AttachmentProgress {
    int64_t message_id;
    size_t index;

    /// Encrypted bytes so far, and how many are expected.  Encrypted rather than the file's own
    /// size because that is what is actually being moved and therefore what a proportion should be
    /// computed from; the two differ by padding and framing.
    ///
    /// `total` is 0 until the server has said how big it is, which is not known when a transfer
    /// starts — so the first report of any transfer is 0 of 0, meaning "beginning".
    int64_t done = 0;
    int64_t total = 0;

    /// Unset while it is running, 0 once the file is here and verified, and otherwise the status of
    /// whatever went wrong.  Exactly one report per transfer carries a value.
    std::optional<int> result;
};

struct Attachment {
    /// Position within the message's attachment list.  This is the index `send_message`'s upload
    /// handler reports progress against, and what `save_attachment` takes.
    size_t index;

    std::optional<std::string> content_type;
    std::optional<std::string> filename;
    std::optional<std::string> caption;

    /// A recorded voice message rather than an ordinary audio file, which clients present
    /// differently.
    bool voice_message = false;

    std::optional<uint32_t> width;
    std::optional<uint32_t> height;

    /// The file's size in bytes, before encryption -- what the file server holds is larger, since
    /// it carries the stream's per-chunk overhead and the padding that hides the true length.
    ///
    /// Unset on an outgoing attachment that has not been uploaded yet.  On an incoming one this is
    /// the sender's claim: for a legacy-encrypted attachment it is load-bearing, being what the
    /// padding is trimmed by, and a wrong value there shows up as a corrupt file.
    std::optional<int64_t> size;

    /// Whether the file is on the file server: for an outgoing attachment, that its upload
    /// finished, which is how a partly-uploaded message reports which of its files got through.
    /// Always true for an incoming attachment, which is where it came from.
    ///
    /// Where the file is *locally* is deliberately not here.  A local path is an argument to
    /// sending or saving, not a property of the attachment: the application chose it and knows it,
    /// and anything recorded here would go stale as soon as the file was moved.
    bool uploaded = false;

    /// When the *recipient* of this message last saved this attachment -- us, on an incoming one,
    /// and the other party on one we sent.  The same fact from either end, so it does not have to
    /// be read differently depending on `Message::outgoing`.
    ///
    /// What it is for is knowing whether offering "save" again is pointless, and — on a message we
    /// sent — whether the file reached a person rather than merely a file server.
    ///
    /// Unset means **not known to have been saved**, which is not the same as not saved, and must
    /// not be shown as though it were.  On an outgoing attachment it depends entirely on the other
    /// end volunteering a notification: a client that sends none, or one too old to say which
    /// message it means, leaves this unset no matter how many times its user saved the file.  A
    /// sender reading an absent value as "they never got it" would be wrong.
    std::optional<sys_ms> saved_at;
};

}  // namespace session::client
