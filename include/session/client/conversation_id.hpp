#pragma once

#include <compare>
#include <cstddef>
#include <session/util.hpp>
#include <span>
#include <string>
#include <string_view>

namespace session::client {

/// Opaque identifier for a conversation.
///
/// A conversation is keyed differently depending on its kind — a DM by the remote session ID, a
/// closed group by the group ID, a community by server URL plus room token — so this deliberately
/// does not decay to any one of those.  Extracting the underlying value requires naming the kind
/// you expect (session_id(), group_id(), community()), which throws if the conversation is not of
/// that kind.
///
/// The string form from to_string() round-trips through parse() and is stable across releases: it
/// is what gets stored in the database and what an application may persist (a CLI argument, a
/// bookmark).  It is *not* guaranteed to be a good display string.
class ConversationId {
  public:
    enum class Type : int {
        dm = 0,         ///< One-to-one conversation, keyed on the remote 0x05 session ID
        group = 1,      ///< Closed group, keyed on the 0x03 group ID
        community = 2,  ///< Community (open group), keyed on server base URL + room token
    };

    /// Constructs a DM conversation id from a 33-byte 0x05-prefixed session ID.
    /// @throws std::invalid_argument if the first byte is not 0x05.
    static ConversationId dm(std::span<const std::byte, 33> session_id);

    /// Constructs a closed group conversation id from a 33-byte 0x03-prefixed group ID.
    /// @throws std::invalid_argument if the first byte is not 0x03.
    static ConversationId group(std::span<const std::byte, 33> group_id);

    /// Constructs a community conversation id.  `base_url` is normalised (lowercased, trailing
    /// slash removed) and `room` is lowercased, so that the same community reached by differently
    /// spelled URLs compares equal.
    /// @throws std::invalid_argument if either argument is empty, or `room` contains a '/'.
    static ConversationId community(std::string_view base_url, std::string_view room);

    /// Parses the form produced by to_string().
    /// @throws std::invalid_argument if the string is not a valid conversation id.
    static ConversationId parse(std::string_view s);

    Type type() const { return _type; }

    /// The remote 0x05-prefixed session ID.  @throws std::logic_error unless type() == dm.
    std::span<const std::byte, 33> session_id() const;

    /// The 0x03-prefixed group ID.  @throws std::logic_error unless type() == group.
    std::span<const std::byte, 33> group_id() const;

    /// The community server base URL and room token.
    /// @throws std::logic_error unless type() == community.
    std::pair<std::string_view, std::string_view> community() const;

    /// The stable, round-trippable string form:
    /// - dm:        the 66-character hex session ID, e.g. "05abc…"
    /// - group:     the 66-character hex group ID, e.g. "03abc…"
    /// - community: "community:<base_url>/<room>"
    ///
    /// The dm and group forms are exactly the session/group IDs a user would paste, which is what
    /// makes them usable directly as CLI arguments.
    std::string to_string() const;

    std::strong_ordering operator<=>(const ConversationId&) const = default;
    bool operator==(const ConversationId&) const = default;

  private:
    ConversationId(Type t, std::string key) : _type{t}, _key{std::move(key)} {}

    static ConversationId _from_prefixed(
            std::span<const std::byte, 33> id, std::byte want, Type type);

    Type _type;
    // For dm/group: the 33 raw ID bytes.  For community: "<base_url>/<room>", already normalised.
    std::string _key;
};

}  // namespace session::client

namespace std {
template <>
struct hash<session::client::ConversationId> {
    size_t operator()(const session::client::ConversationId& c) const {
        return hash<string>{}(c.to_string());
    }
};
}  // namespace std
