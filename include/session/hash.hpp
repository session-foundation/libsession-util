#pragma once

#include <oxenc/common.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <array>
#include <optional>
#include <ranges>
#include <span>
#include <type_traits>
#include <vector>

#include "types.hpp"

namespace session::hash {

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function for generating a hash that takes a span
/// to write the hash into.  The size of the hash is determined from the size of the span.
///
/// Inputs:
/// - `hash` -- writable span in which to write the hash.  The size of the span must be between 16
///   and 64.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.  Must be less than 64 bytes long.
void hash(
        std::span<unsigned char> hash,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key = std::nullopt);

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function that returns a vector of the requested
/// size containing the hash.
///
/// Inputs:
/// - `size` -- length of the hash to be generated.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.
///
/// Outputs:
/// - a `size` byte hash.
std::vector<unsigned char> hash(
        const size_t size,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key = std::nullopt);

template <typename T>
concept ByteContainer =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>>;

/// API: hash/blake2b_update
///
/// Wrapper about crypto_generichash_blake2b_update that takes any number of contiguous byte
/// containers and updates the hash state with them, in argument order.
template <ByteContainer... T>
    requires(sizeof...(T) > 0)
void update_all(crypto_generichash_blake2b_state& st, const T&... args) {
    auto update_one = [&st](const auto& arg) {
        crypto_generichash_blake2b_update(
                &st,
                reinterpret_cast<const unsigned char*>(std::ranges::data(arg)),
                std::ranges::size(arg));
    };
    (update_one(args), ...);
}

namespace detail {

    template <typename T, size_t N>
    std::integral_constant<size_t, N> extract_extent(const std::array<T, N>&);
    template <typename T, size_t N>
    std::integral_constant<size_t, N> extract_extent(std::span<T, N>);
    template <typename T, size_t N>
    std::integral_constant<size_t, N> extract_extent(const T (&)[N]);
    std::integral_constant<size_t, std::dynamic_extent> extract_extent(...);

    template <typename T>
    constexpr size_t container_extent_v = decltype(extract_extent(std::declval<T&>()))::value;
}  // namespace detail

template <typename T>
concept Blake2BOutputContainer =
        std::ranges::contiguous_range<T> && !std::is_const_v<std::ranges::range_value_t<T>> &&
        oxenc::basic_char<std::ranges::range_value_t<T>> &&
        detail::container_extent_v<T> != std::dynamic_extent &&
        detail::container_extent_v<T> >= 1 && detail::container_extent_v<T> <= 64;

template <typename T>
concept Blake2BKey =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>> &&
        detail::container_extent_v<T> != std::dynamic_extent && detail::container_extent_v<T> <= 64;

/// Helper value to pass a null `key` to blake2b or blake2b_pers.
inline constexpr std::span<unsigned char, 0> nullkey{};

/// API: hash/blake2b_key
///
/// This version of blake2b() takes a key as the second argument and computes a keyed hash.  The key
/// must be between 0 and 64 characters long.  (A 0-length key is equivalent to no key).
template <Blake2BOutputContainer Out, Blake2BKey Key, ByteContainer... T>
    requires(sizeof...(T) > 0)
void blake2b_key(Out& out, const Key& key, const T&... args) {
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(
            &st, std::ranges::data(key), std::ranges::size(key), std::ranges::size(out));
    update_all(st, args...);
    crypto_generichash_blake2b_final(&st, std::ranges::data(out), std::ranges::size(out));
}

/// API: hash/blake2b
///
/// One-shot hasher that takes an output container and and any number of contiguous byte containers,
/// computes the blake2b hash of the concatentation of the containers (in argument order) and then
/// writes the hash into the output container.
///
/// This version uses neither key nor personalisation strings; see blake2b_key, blake2b_pers, and
/// blake2b_key_pers if you want one or both of those.
///
/// Output must be a fixed extent span or containers (e.g. std::array), and must satisfy the blake2b
/// requirements (output size in [1,64]).
template <Blake2BOutputContainer Out, ByteContainer... T>
    requires(sizeof...(T) > 0)
void blake2b(Out& out, const T&... args) {
    return blake2b_key(out, nullkey, args...);
}

/// API: hash/blake2b_key_pers
///
/// This version of blake2b() takes a both a key and a 16-byte personalisation string as the second
/// and third arguments and computes a keyed hash with a personalisation string.  The
/// personalisation string must be exact 16 bytes, and is typically constructed with "..."_b2b_pers
/// for compile-time validation.  The key must be between 0 and 64 bytes long.
template <Blake2BOutputContainer Out, Blake2BKey Key, ByteContainer... T>
    requires(sizeof...(T) > 0)
void blake2b_key_pers(
        Out& out, const Key& key, std::span<const unsigned char, 16> pers, const T&... args) {
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init_salt_personal(
            &st,
            std::ranges::data(key),
            std::ranges::size(key),
            std::ranges::size(out),
            /*salt=*/nullptr,
            pers.data());
    update_all(st, args...);
    crypto_generichash_blake2b_final(&st, std::ranges::data(out), std::ranges::size(out));
}

/// API: hash/blake2b_pers
///
/// This version of blake2b() takes a 16-byte personality string as the second argument and computes
/// a unkeyed hash with a personalisation string.  The personalization string must be exact 16
/// bytes, and is typically constructed with "..."_b2b_pers for compile-time validation.
template <Blake2BOutputContainer Out, ByteContainer... T>
    requires(sizeof...(T) > 0)
void blake2b_pers(Out& out, std::span<const unsigned char, 16> pers, const T&... args) {
    return blake2b_key_pers(out, nullkey, pers, args...);
}

// Helper callable usable with unordered_map and similar to hash an array of chars by simply copying
// the first sizeof(size_t) bytes, suitable for use with pre-hashed values.
struct identity_hasher {
    template <oxenc::basic_char Char, size_t N>
        requires(N >= sizeof(size_t))
    constexpr size_t operator()(const std::array<Char, N>& v) const noexcept {
        size_t out;
        std::copy(v.begin(), v.begin() + sizeof(out), reinterpret_cast<Char*>(&out));
        return out;
    }
};

}  // namespace session::hash

namespace session {

template <size_t N>
struct StringLiteral {
    std::array<char, N - 1> chars;
    constexpr StringLiteral(const char (&s)[N]) {
        for (size_t i = 0; i < N - 1; ++i)
            chars[i] = s[i];
    }
};

inline namespace literals {

    /// User-defined literal for a 16-byte, unsigned char array intended for use as a BLAKE2b
    /// personality value. Example:
    ///
    ///     using namespace session::hash::literals;
    ///     constexpr auto PERS_XYZ = "XYZ-XYZ-XYZ-WXYZ"_b2b_pers;
    ///
    template <StringLiteral Str>
    constexpr auto operator""_b2b_pers() {
        static_assert(
                Str.chars.size() == 16,
                "BLAKE2b personalization strings must be exactly 16 bytes long");
        std::array<unsigned char, 16> pers;
        for (size_t i = 0; i < pers.size(); i++)
            pers[i] = static_cast<unsigned char>(Str.chars[i]);
        return pers;
    }

}  // namespace literals

}  // namespace session
