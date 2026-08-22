#pragma once

#include <filesystem>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "session/types.hpp"

/// A cache of files we downloaded, on disk, encrypted under one key of our own.
///
/// Re-encrypted rather than kept as the file server gave them to us, because the key that opened a
/// download belongs to something that goes away: an attachment's key lives in the message, a
/// profile picture's in the Contacts config, and a deleted message or a changed picture would leave
/// us holding a file we can no longer read.  A key we own outlives both.
///
/// Encrypted rather than kept as plaintext because the disk is not a trusted place: it ends up in
/// backups, in disk images, and in whoever's hands the machine does.  That is also why the padding
/// is kept -- see `attachment::Encryptor`'s key-taking constructor.
///
/// Entirely files, with no database rows of its own.  What is still referenced is already recorded
/// -- `accounts.profile_pic_url` and `message_attachments.url` -- so a second record of it would be
/// a second thing to keep in step, and the one that gets out of step is the one that decides what
/// to delete.
namespace session::client::cache {

/// The subdirectory a kind of download lives in.  Separate so that a sweep of one cannot consider
/// the other's files unreferenced, which it would, since neither knows the other's urls.
inline constexpr std::string_view PROFILE_DIR = "profile";
inline constexpr std::string_view ATTACHMENT_DIR = "attachments";

/// Where `url`'s cached file lives beneath `dir`.
///
/// Named for a hash of the url with any query string and fragment removed.  Those are not part of
/// which file this is: the fragment carries what is needed to *reach* and unpack the bytes -- the
/// server's key, connection details, decompression hints -- while the bytes at the base url are the
/// bytes.  Two references differing only there name the same file, and hashing the whole thing
/// would cache it twice.
///
/// Hashed rather than escaped because a url is not a filename: it is long, it contains separators,
/// and its length is unbounded.  A fixed-width hex name is none of those things.
std::filesystem::path path_for(
        const std::filesystem::path& dir, std::string_view kind, std::string_view url);

/// Reads and decrypts a cached file, or nullopt if it is not there.
///
/// Nullopt for an unreadable or corrupted file too, rather than throwing: a cache that cannot
/// answer is a cache miss, and the caller's next move -- fetch it again -- is the same either way.
/// The unreadable file is removed, since nothing else would ever remove it.
std::optional<std::vector<std::byte>> read(
        const std::filesystem::path& file, std::span<const std::byte, 32> key);

/// Encrypts `data` and writes it to `file`, creating the directory if needed.
///
/// Written to a temporary name in the same directory and renamed into place, so a crash or a
/// concurrent read never sees a half-written file: the rename is atomic and the name only ever
/// exists complete.  The temporary carries a suffix a sweep knows to leave alone.
void write(
        const std::filesystem::path& file,
        std::span<const std::byte, 32> key,
        std::span<const std::byte> data);

/// The suffix an in-progress write carries.  A sweep must skip these: it decides what to delete by
/// what is *not* referenced, and a download that has not finished is not referenced yet.
inline constexpr std::string_view PARTIAL_SUFFIX = ".part";

/// Unlinks everything in `dir/kind` that `referenced` does not name, and says how many went.
///
/// Compare and converge rather than deleting a file when the row naming it goes: those rows go by
/// cascade when a conversation is deleted, and no code of ours runs to see it.  Listing what is
/// still referenced and unlinking the difference survives that, and also collects what a crash
/// mid-download left behind -- which collecting paths before a delete never would.
///
/// Only safe because the directory is ours outright: "anything not in the list" is a statement
/// about a place nothing else writes to.
size_t sweep(
        const std::filesystem::path& dir,
        std::string_view kind,
        const std::set<std::string>& referenced_urls);

}  // namespace session::client::cache
