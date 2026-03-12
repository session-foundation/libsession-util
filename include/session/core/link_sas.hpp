#pragma once

#include <array>
#include <span>
#include <string_view>

namespace session {

using namespace std::literals;

/// The 64 emoji used for short authentication strings, from the Matrix client-server API
/// specification v1.17, section 10.12.2.2.6.  Selected for reasonable distinctiveness and
/// cross-platform compatibility.
inline constexpr std::array SAS_EMOJI = {
        // clang-format off
        "🐶"sv, "🐱"sv, "🦁"sv, "🐎"sv, "🦄"sv, "🐷"sv, "🐘"sv, "🐰"sv,
        "🐼"sv, "🐓"sv, "🐧"sv, "🐢"sv, "🐟"sv, "🐙"sv, "🦋"sv, "🌷"sv,
        "🌳"sv, "🌵"sv, "🍄"sv, "🌏"sv, "🌙"sv, "☁️"sv,  "🔥"sv, "🍌"sv,
        "🍎"sv, "🍓"sv, "🌽"sv, "🍕"sv, "🎂"sv, "❤️"sv,  "😀"sv, "🤖"sv,
        "🎩"sv, "👓"sv, "🔧"sv, "🎅"sv, "👍"sv, "☂️"sv,  "⌛"sv, "⏰"sv,
        "🎁"sv, "💡"sv, "📕"sv, "✏️"sv,  "📎"sv, "✂️"sv,  "🔒"sv, "🔑"sv,
        "🔨"sv, "☎️"sv,  "🏁"sv, "🚂"sv, "🚲"sv, "✈️"sv,  "🚀"sv, "🏆"sv,
        "⚽"sv, "🎸"sv, "🎺"sv, "🔔"sv, "⚓"sv, "🎧"sv, "📁"sv, "📌"sv,
        // clang-format on
};
static_assert(SAS_EMOJI.size() == 64);

}  // namespace session

namespace session::core {

/// Computes the short authentication string (SAS) for a device link request from its decrypted
/// plaintext bytes.  The derivation is:
///   1. salt = BLAKE2b-16(M, pers="SessionLinkEmoji")
///   2. seed = Argon2id(M, salt, size=16, ops=2, mem=16MiB)
///   3. Interpret seed as a 128-bit little-endian integer; extract 6-bit indices.
///
/// Returns 21 string_view values (into the SAS_EMOJI table) for the full SAS sequence.  The first
/// 7 are the standard short display; all 21 are available for the extended view.  Formatting and
/// joining is left to the caller; the recommended layout is the first 7 joined with spaces for the
/// standard view, and 3 lines of 7 (joined with spaces within lines, newlines between) for the
/// extended view.
std::array<std::string_view, 21> link_request_sas(std::span<const std::byte> plaintext);

}  // namespace session::core
