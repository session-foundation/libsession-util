#pragma once

#include <fmt/format.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <concepts>
#include <oxen/log/format.hpp>
#include <ranges>
#include <span>
#include <type_traits>

namespace session {

/// Concept matching contiguous ranges of std::byte.
template <typename T>
concept byte_spannable = std::ranges::contiguous_range<T> &&
                         std::same_as<std::remove_cv_t<std::ranges::range_value_t<T>>, std::byte>;

/// User-defined literals for convenient fmt::format usage, re-exported from oxen::log::literals.
///
/// "_format" works like fmt::format but with the format string as a UDL:
///
///     "xyz {}"_format(42)        // returns std::string "xyz 42"
///
/// "_format_to" appends in-place to an existing string (more efficient than +=):
///
///     std::string s = "hello";
///     "xyz {}"_format_to(s, 42)  // s is now "helloxyz 42"
///
/// Available via `using namespace session::literals;` or `using namespace session;`.
inline namespace literals {
    using oxen::log::literals::operator""_format;
    using oxen::log::literals::operator""_format_to;
}  // namespace literals

}  // namespace session

namespace fmt {

/// Generic formatter for any byte_spannable type (std::span, std::array, std::vector of std::byte).
///
/// Format spec:
///   {}  or  {:x}  — full lowercase hex (default)
///   {:z}          — hex with leading zero bytes stripped
///   {:a}          — base32z encoding
///   {:b}          — base64 encoding (padded)
///   {:B}          — base64 encoding (unpadded)
///   {:r}          — raw bytes
///
/// Ellipsis truncation: use {:W.T} before any mode letter, where W is the total output width
/// (including the single "…" character) and T is the number of characters shown after the
/// ellipsis. W must be >= 2 and >= T+2.  If the encoded value fits within W characters, no
/// truncation occurs.
///
/// For example, with a 32-byte all-zero value:
///   {:x}    → "0000000000000000000000000000000000000000000000000000000000000000"
///   {:z}    → "0"
///   {:10.4} → "00000…0000"
///   {:9.4x} → "0000…0000"
template <session::byte_spannable T>
struct formatter<T, char> {
  private:
    enum class mode_t { full_hex, stripped_hex, b32z, b64, b64_unpadded, raw };
    mode_t mode = mode_t::full_hex;
    bool do_ellipsis = false;
    int ellipsis_width = -1, ellipsis_tail = -1;

  public:
    constexpr fmt::format_parse_context::iterator parse(fmt::format_parse_context& ctx) {
        auto it = ctx.begin();
        for (; it != ctx.end(); ++it) {
            char c = *it;
            if (c == '}')
                break;

            bool mode_set = false;
            switch (c) {
                case 'x':
                    mode = mode_t::full_hex;
                    mode_set = true;
                    break;
                case 'z':
                    mode = mode_t::stripped_hex;
                    mode_set = true;
                    break;
                case 'r':
                    mode = mode_t::raw;
                    mode_set = true;
                    break;
                case 'a':
                    mode = mode_t::b32z;
                    mode_set = true;
                    break;
                case 'b':
                    mode = mode_t::b64;
                    mode_set = true;
                    break;
                case 'B':
                    mode = mode_t::b64_unpadded;
                    mode_set = true;
                    break;
                case '0':
                    // Leading zero before any width digits means zero-fill, which we don't support
                    if (!do_ellipsis && ellipsis_width == -1)
                        throw fmt::format_error{
                                "invalid format for byte span: 0-fill is not supported"};
                    [[fallthrough]];
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9': {
                    auto& v = do_ellipsis ? ellipsis_tail : ellipsis_width;
                    v = (v < 0 ? 0 : v) * 10 + (c - '0');
                    break;
                }
                case '.':
                    if (!do_ellipsis && ellipsis_width >= 2) {
                        do_ellipsis = true;
                        break;
                    }
                    [[fallthrough]];
                default: throw fmt::format_error{"invalid format spec for byte span"};
            }

            if (mode_set) {
                if (++it == ctx.end() || *it != '}')
                    throw fmt::format_error{
                            "invalid format for byte span: trailing characters after mode"};
                break;
            }
        }

        if (do_ellipsis) {
            if (ellipsis_tail < 0)
                throw fmt::format_error{
                        "invalid ellipsis format for byte span: missing tail length after '.'"};
            if (ellipsis_tail > ellipsis_width - 2)
                throw fmt::format_error{
                        "invalid ellipsis format for byte span: width must be >= tail+2"};
        } else if (ellipsis_width >= 0) {
            throw fmt::format_error{
                    "invalid format for byte span: width specified without '.' and tail length"};
        }

        return it;
    }

    auto format(const T& v, fmt::format_context& ctx) const {
        const auto* data = reinterpret_cast<const unsigned char*>(std::ranges::data(v));
        std::span<const unsigned char> bytes{data, std::ranges::size(v)};

        fmt::memory_buffer buf;
        auto out = do_ellipsis ? fmt::appender(buf) : ctx.out();

        switch (mode) {
            case mode_t::raw: out = std::copy(bytes.begin(), bytes.end(), out); break;
            case mode_t::b64: out = oxenc::to_base64(bytes.begin(), bytes.end(), out); break;
            case mode_t::b64_unpadded:
                out = oxenc::to_base64(bytes.begin(), bytes.end(), out, false);
                break;
            case mode_t::b32z: out = oxenc::to_base32z(bytes.begin(), bytes.end(), out); break;
            case mode_t::stripped_hex: {
                auto it = bytes.begin();
                while (it != bytes.end() && *it == 0)
                    ++it;
                if (it == bytes.end()) {
                    *out++ = '0';
                    break;
                }
                // If the first remaining byte would produce a leading 0 in hex (e.g. 0x0a → "0a"),
                // skip the leading '0' so the output starts with the significant hex digit.
                if (*it < 16) {
                    char pair[2];
                    oxenc::to_hex(it, it + 1, pair);
                    *out++ = pair[1];
                    ++it;
                }
                out = oxenc::to_hex(it, bytes.end(), out);
                break;
            }
            case mode_t::full_hex:
            default: out = oxenc::to_hex(bytes.begin(), bytes.end(), out); break;
        }

        if (!do_ellipsis)
            return out;

        std::string_view full{buf.data(), buf.size()};
        auto final_out = ctx.out();
        if (full.size() <= static_cast<size_t>(ellipsis_width)) {
            final_out = std::copy(full.begin(), full.end(), final_out);
        } else {
            final_out = std::copy(
                    full.begin(), full.begin() + (ellipsis_width - 1 - ellipsis_tail), final_out);
            constexpr std::string_view ellipsis_char{"…"};
            final_out = std::copy(ellipsis_char.begin(), ellipsis_char.end(), final_out);
            final_out = std::copy(full.end() - ellipsis_tail, full.end(), final_out);
        }
        return final_out;
    }
};

}  // namespace fmt
