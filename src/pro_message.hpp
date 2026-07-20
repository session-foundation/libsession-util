#pragma once

#include <charconv>
#include <concepts>
#include <cstddef>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace session::pro {

/// Builds the byte string that is Ed25519-signed for a Pro proof (§2) or a signed request (§3),
/// following the signed-message construction in pro-wire-protocol.md §1.1. Pass the 16-byte domain
/// prefix first, then the fields in order; each field is encoded by its type:
///
/// - **byte-spannable** (public key, revocation tag — fixed-width raw values): appended verbatim
///   and self-delimiting;
/// - **integer**: canonical decimal ASCII (`std::to_chars`, base 10, locale-independent — never a
///   locale-aware formatter);
/// - **string_view** (`provider_code`, and the opaque variable-length `payment_id` via
///   `to_string_view`): its bytes verbatim.
///
/// A single NUL byte is inserted between two *adjacent* variable-length fields (integer/string);
/// raw fields need no separator, and the domain prefix (also raw) never precedes one. The message
/// is signed directly — there is no pre-hash (Ed25519 hashes internally).
template <typename... Fields>
std::vector<std::byte> signed_message(std::string_view domain, const Fields&... fields) {
    std::vector<std::byte> buf;
    bool prev_var = false;  // the previously-appended field was variable-length (int/string)

    auto put_chars = [&](std::string_view s) {
        for (char c : s)
            buf.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    };
    put_chars(domain);  // domain prefix: fixed-width, self-delimiting

    auto append = [&](const auto& field) {
        using T = std::remove_cvref_t<decltype(field)>;
        if constexpr (std::is_integral_v<T>) {
            if (prev_var)
                buf.push_back(std::byte{0});
            char tmp[24];  // enough for -9223372036854775808 (20 chars)
            auto [ptr, ec] = std::to_chars(tmp, tmp + sizeof(tmp), field);
            put_chars({tmp, static_cast<std::size_t>(ptr - tmp)});
            prev_var = true;
        } else if constexpr (std::convertible_to<const T&, std::string_view>) {
            if (prev_var)
                buf.push_back(std::byte{0});
            put_chars(field);
            prev_var = true;
        } else {
            static_assert(
                    std::convertible_to<const T&, std::span<const std::byte>>,
                    "signed_message() fields must be an integer, a string_view, or a "
                    "byte-spannable raw value (e.g. a public key or tag)");
            std::span<const std::byte> b = field;
            buf.insert(buf.end(), b.begin(), b.end());
            prev_var = false;
        }
    };
    (append(fields), ...);
    return buf;
}

}  // namespace session::pro
