#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace session::client {

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
    std::optional<uint32_t> width;
    std::optional<uint32_t> height;
};

}  // namespace session::client
