#include <oxenc/hex.h>

#include <algorithm>
#include <cctype>
#include <session/client/conversation_id.hpp>
#include <session/format.hpp>
#include <stdexcept>

namespace session::client {

using namespace std::literals;

static constexpr std::string_view COMMUNITY_PREFIX = "community:"sv;

ConversationId ConversationId::_from_prefixed(
        std::span<const std::byte, 33> id, std::byte want, Type type) {
    if (id[0] != want)
        throw std::invalid_argument{
                "Invalid conversation id: expected a 0x{:02x} prefix, got 0x{:02x}"_format(
                        std::to_integer<int>(want), std::to_integer<int>(id[0]))};
    return ConversationId{type, std::string{reinterpret_cast<const char*>(id.data()), id.size()}};
}

ConversationId ConversationId::dm(std::span<const std::byte, 33> session_id) {
    return _from_prefixed(session_id, std::byte{0x05}, Type::dm);
}

ConversationId ConversationId::group(std::span<const std::byte, 33> group_id) {
    return _from_prefixed(group_id, std::byte{0x03}, Type::group);
}

static std::string lowercase(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    std::ranges::transform(s, std::back_inserter(out), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

ConversationId ConversationId::community(std::string_view base_url, std::string_view room) {
    // Normalise so that the same community written two ways is one conversation, not two: the
    // scheme and host are case-insensitive, room tokens are defined lowercase, and a trailing
    // slash on the server URL is meaningless.
    while (base_url.ends_with('/'))
        base_url.remove_suffix(1);

    if (base_url.empty())
        throw std::invalid_argument{"Invalid community conversation id: empty server URL"};
    if (room.empty())
        throw std::invalid_argument{"Invalid community conversation id: empty room token"};
    if (room.find('/') != std::string_view::npos)
        throw std::invalid_argument{"Invalid community conversation id: room contains a '/'"};

    return ConversationId{Type::community, "{}/{}"_format(lowercase(base_url), lowercase(room))};
}

ConversationId ConversationId::parse(std::string_view s) {
    if (s.starts_with(COMMUNITY_PREFIX)) {
        auto rest = s.substr(COMMUNITY_PREFIX.size());
        auto slash = rest.rfind('/');
        if (slash == std::string_view::npos)
            throw std::invalid_argument{"Invalid community conversation id: no room token"};
        return community(rest.substr(0, slash), rest.substr(slash + 1));
    }

    if (s.size() != 66 || !oxenc::is_hex(s))
        throw std::invalid_argument{"Invalid conversation id: not a hex session or group ID"};

    auto raw = oxenc::from_hex(s);
    std::span<const std::byte, 33> id{reinterpret_cast<const std::byte*>(raw.data()), 33};
    if (raw[0] == '\x05')
        return dm(id);
    if (raw[0] == '\x03')
        return group(id);
    throw std::invalid_argument{
            "Invalid conversation id: unrecognised prefix {:.2s}"_format(std::string_view{s})};
}

std::span<const std::byte, 33> ConversationId::session_id() const {
    if (_type != Type::dm)
        throw std::logic_error{"session_id() called on a non-DM conversation id"};
    return std::span<const std::byte, 33>{
            reinterpret_cast<const std::byte*>(_key.data()), _key.size()};
}

std::span<const std::byte, 33> ConversationId::group_id() const {
    if (_type != Type::group)
        throw std::logic_error{"group_id() called on a non-group conversation id"};
    return std::span<const std::byte, 33>{
            reinterpret_cast<const std::byte*>(_key.data()), _key.size()};
}

std::pair<std::string_view, std::string_view> ConversationId::community() const {
    if (_type != Type::community)
        throw std::logic_error{"community() called on a non-community conversation id"};
    std::string_view key{_key};
    auto slash = key.rfind('/');
    return {key.substr(0, slash), key.substr(slash + 1)};
}

std::string ConversationId::to_string() const {
    if (_type == Type::community)
        return "{}{}"_format(COMMUNITY_PREFIX, _key);
    return oxenc::to_hex(_key);
}

}  // namespace session::client
