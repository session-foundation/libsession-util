#pragma once

#include <string_view>

/// The `Error::code` values Client reports, named so that a caller comparing against one cannot be
/// defeated by a typo at either end, and so that adding one is a visible change rather than a new
/// string literal somewhere in a function body.
///
/// Dotted and grouped by what failed.  An open set: a caller that meets a code it does not know
/// falls back to the message, so this list growing is not a breaking change.
namespace session::client::err {

/// A name or nickname longer than the config will hold.  See `config::validate_contact_name`.
inline constexpr std::string_view name_too_long = "contacts.name_too_long";

/// The operation names a conversation, message or attachment that is not there.
inline constexpr std::string_view not_found = "client.not_found";

/// The arguments are wrong in a way the caller could have checked -- a path that is a directory, a
/// conversation that is not a DM.  Reported rather than thrown only where the check cannot happen
/// until the work is already on the loop.
inline constexpr std::string_view invalid_argument = "client.invalid_argument";

/// A file could not be fetched from the file server.  The message carries the status.
inline constexpr std::string_view download_failed = "attachment.download_failed";

/// A file arrived but could not be decrypted or did not match what was promised.
inline constexpr std::string_view download_corrupt = "attachment.download_corrupt";

/// A file could not be written where it was asked to go.
inline constexpr std::string_view save_failed = "attachment.save_failed";

/// An upload to the file server did not complete.  The message carries the status.
inline constexpr std::string_view upload_failed = "attachment.upload_failed";

/// There is no network attached, so nothing that needs one can be done.
inline constexpr std::string_view no_network = "client.no_network";

}  // namespace session::client::err
