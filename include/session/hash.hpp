#pragma once

#include <oxenc/common.h>
#include <oxenc/endian.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_xof_shake256.h>
#include <sodium/utils.h>

#include <array>
#include <optional>
#include <ranges>
#include <span>
#include <type_traits>
#include <vector>

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
///
/// Deprecated: prefer hash::blake2b (unkeyed) or hash::blake2b_key (keyed) instead.
[[deprecated("Use hash::blake2b or hash::blake2b_key instead")]]
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
///
/// Deprecated: prefer hash::blake2b (unkeyed) or hash::blake2b_key (keyed) instead.
[[deprecated("Use hash::blake2b or hash::blake2b_key instead")]]
std::vector<unsigned char> hash(
        const size_t size,
        std::span<const unsigned char> msg,
        std::optional<std::span<const unsigned char>> key = std::nullopt);

template <typename T>
concept ByteContainer =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>>;
template <typename T>
concept HashInput = ByteContainer<T> || oxenc::endian_swappable_integer<T>;

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

    template <HashInput U>
    auto make_hashable(const U& val) {
        if constexpr (ByteContainer<U>)
            return std::span{
                    reinterpret_cast<const unsigned char*>(std::ranges::data(val)),
                    std::ranges::size(val)};
        else if constexpr (oxenc::little_endian || sizeof(val) == 1)
            return std::span{reinterpret_cast<const unsigned char*>(&val), sizeof(val)};
        else {
            std::array<unsigned char, sizeof(val)> swapped;
            oxenc::write_big_as_host(swapped.data(), val);
            return swapped;
        }
    }
    // Initializes a SHAKE-256 (or SHA3-256) keccak state with the given domain suffix byte and
    // absorbs all of `args` into it.  The domain byte distinguishes the hash function:
    //   - 0x1F = SHAKE-256 (crypto_xof_shake256_DOMAIN_STANDARD)
    //   - 0x06 = SHA3-256
    // See the sha3_256 API doc comment for the explanation of why this works.
    template <HashInput... T>
        requires(sizeof...(T) > 0)
    void keccak_absorb(crypto_xof_shake256_state& st, unsigned char domain, const T&... args) {
        crypto_xof_shake256_init_with_domain(&st, domain);
        auto update = [&st](std::span<const unsigned char> arg) {
            crypto_xof_shake256_update(&st, arg.data(), arg.size());
        };
        (update(make_hashable(args)), ...);
    }
}  // namespace detail

/// API: hash/update_all
///
/// Wrapper about crypto_generichash_blake2b_update that takes any number of contiguous byte
/// containers *or* integer values and updates the hash state with them, in argument order.  Integer
/// values are always written as raw bytes in little-endian encoding (i.e. they will be byte-swapped
/// if necessary).
template <HashInput... T>
    requires(sizeof...(T) > 0)
void update_all(crypto_generichash_blake2b_state& st, const T&... args) {
    auto update_hash = [&st](std::span<const unsigned char> arg) {
        crypto_generichash_blake2b_update(&st, arg.data(), arg.size());
    };
    (update_hash(detail::make_hashable(args)), ...);
}

/// Concept for a fixed-size, writable byte container — the basic requirement for any hash output.
template <typename T>
concept HashOutputContainer =
        std::ranges::contiguous_range<T> && !std::is_const_v<std::ranges::range_value_t<T>> &&
        oxenc::basic_char<std::ranges::range_value_t<T>> &&
        detail::container_extent_v<T> != std::dynamic_extent && detail::container_extent_v<T> >= 1;

template <typename T>
concept Blake2BOutputContainer = HashOutputContainer<T> && detail::container_extent_v<T> <= 64;

template <typename T>
concept Blake2BKey =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>> &&
        (detail::container_extent_v<T> == std::dynamic_extent ||
         detail::container_extent_v<T> <= 64);

/// Helper value to pass a null `key` to blake2b or blake2b_pers.
inline constexpr std::span<unsigned char, 0> nullkey{};

/// API: hash/blake2b_key
///
/// This version of blake2b() takes a key as the second argument and computes a keyed hash.  The key
/// must be between 0 and 64 characters long.  (A 0-length key is equivalent to no key).
///
/// Two overloads are provided:
/// - write-to-output: `blake2b_key(out, key, args...)` writes the hash into `out`
/// - return-value: `blake2b_key<N>(key, args...)` returns a `std::array<unsigned char, N>`
template <Blake2BOutputContainer Out, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b_key(Out& out, const Key& key, const T&... args) {
    crypto_generichash_blake2b_state st;
    // Dynamic-extent keys are silently truncated to 64 bytes (the blake2b key size limit); static-
    // extent keys are guaranteed ≤ 64 at compile time by the Blake2BKey concept.
    crypto_generichash_blake2b_init(
            &st,
            reinterpret_cast<const unsigned char*>(std::ranges::data(key)),
            std::min<size_t>(std::ranges::size(key), 64),
            std::ranges::size(out));
    update_all(st, args...);
    crypto_generichash_blake2b_final(
            &st, reinterpret_cast<unsigned char*>(std::ranges::data(out)), std::ranges::size(out));
}
template <size_t N, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<unsigned char, N> blake2b_key(const Key& key, const T&... args) {
    std::array<unsigned char, N> result;
    blake2b_key(result, key, args...);
    return result;
}

/// API: hash/blake2b
///
/// One-shot hasher that takes an output container and any number of contiguous byte containers or
/// integer values, computes the blake2b hash of the concatentation of the containers (in argument
/// order) and then writes the hash into the output container.  Integer values are hashed as their
/// little-endian (fixed size) byte representation.
///
/// This version uses neither key nor personalisation strings; see blake2b_key, blake2b_pers, and
/// blake2b_key_pers if you want one or both of those.
///
/// Output must be a fixed extent span or containers (e.g. std::array), and must satisfy the blake2b
/// requirements (output size in [1,64]).
///
/// It is permitted for overlap between the output and input containers; the output container is not
/// written until all input containers have been consumed.
///
/// Two overloads are provided:
/// - write-to-output: `blake2b(out, args...)` writes the hash into `out`
/// - return-value: `blake2b<N>(args...)` returns a `std::array<unsigned char, N>`
template <Blake2BOutputContainer Out, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b(Out& out, const T&... args) {
    return blake2b_key(out, nullkey, args...);
}
template <size_t N, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<unsigned char, N> blake2b(const T&... args) {
    std::array<unsigned char, N> result;
    blake2b(result, args...);
    return result;
}

/// API: hash/blake2b_key_pers
///
/// This version of blake2b() takes a both a key and a 16-byte personalisation string as the second
/// and third arguments and computes a keyed hash with a personalisation string.  The
/// personalisation string must be exact 16 bytes, and is typically constructed with "..."_b2b_pers
/// for compile-time validation.  The key must be between 0 and 64 bytes long.
///
/// Two overloads are provided:
/// - write-to-output: `blake2b_key_pers(out, key, pers, args...)` writes the hash into `out`
/// - return-value: `blake2b_key_pers<N>(key, pers, args...)` returns a `std::array<unsigned char,
/// N>`
template <Blake2BOutputContainer Out, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b_key_pers(
        Out& out, const Key& key, std::span<const unsigned char, 16> pers, const T&... args) {
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init_salt_personal(
            &st,
            reinterpret_cast<const unsigned char*>(std::ranges::data(key)),
            std::min<size_t>(std::ranges::size(key), 64),
            std::ranges::size(out),
            /*salt=*/nullptr,
            pers.data());
    update_all(st, args...);
    crypto_generichash_blake2b_final(
            &st, reinterpret_cast<unsigned char*>(std::ranges::data(out)), std::ranges::size(out));
}
template <size_t N, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<unsigned char, N> blake2b_key_pers(
        const Key& key, std::span<const unsigned char, 16> pers, const T&... args) {
    std::array<unsigned char, N> result;
    blake2b_key_pers(result, key, pers, args...);
    return result;
}

/// API: hash/blake2b_pers
///
/// This version of blake2b() takes a 16-byte personality string as the second argument and computes
/// a unkeyed hash with a personalisation string.  The personalization string must be exact 16
/// bytes, and is typically constructed with "..."_b2b_pers for compile-time validation.
///
/// Two overloads are provided:
/// - write-to-output: `blake2b_pers(out, pers, args...)` writes the hash into `out`
/// - return-value: `blake2b_pers<N>(pers, args...)` returns a `std::array<unsigned char, N>`
template <Blake2BOutputContainer Out, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b_pers(Out& out, std::span<const unsigned char, 16> pers, const T&... args) {
    return blake2b_key_pers(out, nullkey, pers, args...);
}
template <size_t N, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<unsigned char, N> blake2b_pers(
        std::span<const unsigned char, 16> pers, const T&... args) {
    std::array<unsigned char, N> result;
    blake2b_pers(result, pers, args...);
    return result;
}

/// API: hash/shake256
///
/// SHAKE256 XOF hasher/squeezer.  Construct with any number of contiguous byte containers or
/// integer values to absorb their concatenation, then call operator() with one or more fixed-size
/// output containers to squeeze output.  Multiple operator() calls squeeze sequentially.  Integer
/// values are absorbed as their little-endian (fixed-size) byte representation.
///
/// Unlike blake2b, SHAKE256 has no key or personalisation mechanism; callers achieve domain
/// separation by simply prepending a domain string as the first argument.
///
/// The internal keccak state is zeroed on destruction.
///
/// Example:
///
///     // Squeeze two outputs in one call:
///     hash::shake256("SessionMyKey"_uc, seed)(out_a, out_b);
///
///     // Or squeeze incrementally:
///     hash::shake256 sq{"SessionMyKey"_uc, seed};
///     sq(out_a);
///     sq(out_b);
///
struct [[nodiscard]] shake256 {
    crypto_xof_shake256_state st;

    template <HashInput... T>
        requires(sizeof...(T) > 0)
    explicit shake256(const T&... args) {
        detail::keccak_absorb(st, crypto_xof_shake256_DOMAIN_STANDARD, args...);
    }

    ~shake256() { sodium_memzero(&st, sizeof(st)); }

    shake256(const shake256&) = delete;
    shake256& operator=(const shake256&) = delete;
    shake256(shake256&&) = delete;
    shake256& operator=(shake256&&) = delete;

    template <HashOutputContainer... Outs>
        requires(sizeof...(Outs) > 0)
    shake256& operator()(Outs&&... outs) {
        (crypto_xof_shake256_squeeze(
                 &st,
                 reinterpret_cast<unsigned char*>(std::ranges::data(outs)),
                 std::ranges::size(outs)),
         ...);
        return *this;
    }

    /// Squeezes N bytes from the state and returns them as a `std::array<unsigned char, N>`.
    template <size_t N>
        requires(N >= 1)
    std::array<unsigned char, N> squeeze() {
        std::array<unsigned char, N> result;
        (*this)(result);
        return result;
    }
};

/// API: hash/sha3_256
///
/// One-shot SHA3-256 (NIST FIPS 202) hasher.  Takes a fixed-size 32-byte output container and any
/// number of contiguous byte containers or integer values, computes the SHA3-256 hash of their
/// concatenation (in argument order), and writes the result into the output container.  Integer
/// values are hashed as their little-endian (fixed-size) byte representation.
///
/// Implementation note: SHA3-256 and SHAKE-256 share identical Keccak-1600 sponge parameters
/// (state=1600 bits, rate=136 bytes, capacity=512 bits) and differ *only* in the domain suffix
/// byte absorbed into the state during padding before the final squeeze:
///
///   - SHAKE-256: 0x1F  (FIPS 202 §6.2 XOF suffix '11111')
///   - SHA3-256:  0x06  (FIPS 202 §6.1 hash suffix '01', plus the leading '1' of the Keccak
///                       multi-rate padding '10*1', making the combined byte '0000 0110')
///
/// Because the sponge parameters are identical, crypto_xof_shake256_init_with_domain(&st, 0x06)
/// followed by absorbing input and squeezing 32 bytes is exactly SHA3-256.  This is the intended
/// use of init_with_domain, not a workaround.
///
/// The temporary keccak state is zeroed before this function returns.
///
/// Two overloads are provided:
/// - write-to-output: `sha3_256(out, args...)` writes the hash into `out`
/// - return-value: `sha3_256<32>(args...)` returns a `std::array<unsigned char, 32>`
template <HashOutputContainer Out, HashInput... T>
    requires(detail::container_extent_v<Out> == 32 && sizeof...(T) > 0)
void sha3_256(Out& out, const T&... args) {
    crypto_xof_shake256_state st;
    detail::keccak_absorb(st, 0x06, args...);
    crypto_xof_shake256_squeeze(&st, reinterpret_cast<unsigned char*>(std::ranges::data(out)), 32);
    sodium_memzero(&st, sizeof(st));
}
template <size_t N, HashInput... T>
    requires(N == 32 && sizeof...(T) > 0)
std::array<unsigned char, 32> sha3_256(const T&... args) {
    std::array<unsigned char, 32> result;
    sha3_256(result, args...);
    return result;
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
    static constexpr size_t size() { return N; }
};

inline namespace literals {

    /// User-defined literal for a 16-byte, unsigned char array intended for use as a BLAKE2b
    /// personality value. Example:
    ///
    ///     using namespace session::literals;
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

    /// User-defined literal for an arbitrary-length, unsigned char array; this is primarily
    /// intended for fixed keys with BLAKE2b hash.  Example:
    ///
    ///     using namespace session::literals;
    ///     constexpr auto HASH_KEY_42 = "forty-two"_uc;
    ///
    template <StringLiteral Str>
    constexpr auto operator""_uc() {
        std::array<unsigned char, Str.chars.size()> pers;
        for (size_t i = 0; i < pers.size(); i++)
            pers[i] = static_cast<unsigned char>(Str.chars[i]);
        return pers;
    }

}  // namespace literals

}  // namespace session
