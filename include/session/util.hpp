#pragma once

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <type_traits>
#include <vector>

#include "types.hpp"

namespace session {

// Helper function to go to/from char pointers to unsigned char pointers:
inline const unsigned char* to_unsigned(const char* x) {
    return reinterpret_cast<const unsigned char*>(x);
}
inline unsigned char* to_unsigned(char* x) {
    return reinterpret_cast<unsigned char*>(x);
}
inline const unsigned char* to_unsigned(const std::byte* x) {
    return reinterpret_cast<const unsigned char*>(x);
}
inline unsigned char* to_unsigned(std::byte* x) {
    return reinterpret_cast<unsigned char*>(x);
}
// These do nothing, but having them makes template metaprogramming easier:
inline const unsigned char* to_unsigned(const unsigned char* x) {
    return x;
}
inline unsigned char* to_unsigned(unsigned char* x) {
    return x;
}
inline const char* from_unsigned(const unsigned char* x) {
    return reinterpret_cast<const char*>(x);
}
inline char* from_unsigned(unsigned char* x) {
    return reinterpret_cast<char*>(x);
}
// Helper function to switch between basic_string_view<C> and ustring_view
inline ustring_view to_unsigned_sv(std::string_view v) {
    return {to_unsigned(v.data()), v.size()};
}
inline ustring_view to_unsigned_sv(std::basic_string_view<std::byte> v) {
    return {to_unsigned(v.data()), v.size()};
}
inline ustring_view to_unsigned_sv(ustring_view v) {
    return v;  // no-op, but helps with template metaprogamming
}
inline std::string_view from_unsigned_sv(ustring_view v) {
    return {from_unsigned(v.data()), v.size()};
}
template <size_t N>
inline std::string_view from_unsigned_sv(const std::array<unsigned char, N>& v) {
    return {from_unsigned(v.data()), v.size()};
}
template <typename T, typename A>
inline std::string_view from_unsigned_sv(const std::vector<T, A>& v) {
    return {from_unsigned(v.data()), v.size()};
}
template <typename Char, size_t N>
inline std::basic_string_view<Char> to_sv(const std::array<Char, N>& v) {
    return {v.data(), N};
}

inline uint64_t get_timestamp() {
    return std::chrono::steady_clock::now().time_since_epoch().count();
}

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(std::string_view s1, std::string_view s2) {
    return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    });
}

// C++20 starts_/ends_with backport
inline constexpr bool starts_with(std::string_view str, std::string_view prefix) {
    return str.size() >= prefix.size() && str.substr(prefix.size()) == prefix;
}

inline constexpr bool end_with(std::string_view str, std::string_view suffix) {
    return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
}

// Calls sodium_malloc for secure allocation; throws a std::bad_alloc on allocation failure
void* sodium_buffer_allocate(size_t size);
// Frees a pointer constructed with sodium_buffer_allocate.  Does nothing if `p` is nullptr.
void sodium_buffer_deallocate(void* p);
// Calls sodium_memzero to zero a buffer
void sodium_zero_buffer(void* ptr, size_t size);

// Works similarly to a unique_ptr, but allocations and free go via libsodium (which is slower, but
// more secure for sensitive data).
template <typename T>
struct sodium_ptr {
  private:
    T* x;

  public:
    sodium_ptr() : x{nullptr} {}
    sodium_ptr(std::nullptr_t) : sodium_ptr{} {}
    ~sodium_ptr() { reset(x); }

    // Allocates and constructs a new `T` in-place, forwarding any given arguments to the `T`
    // constructor.  If this sodium_ptr already has an object, `reset()` is first called implicitly
    // to destruct and deallocate the existing object.
    template <typename... Args>
    T& emplace(Args&&... args) {
        if (x)
            reset();
        x = static_cast<T>(sodium_buffer_allocate(sizeof(T)));
        new (x) T(std::forward<Args>(args)...);
        return *x;
    }

    void reset() {
        if (x) {
            x->~T();
            sodium_buffer_deallocate(x);
            x = nullptr;
        }
    }
    void operator=(std::nullptr_t) { reset(); }

    T& operator*() { return *x; }
    const T& operator*() const { return *x; }

    T* operator->() { return x; }
    const T* operator->() const { return x; }

    explicit operator bool() const { return x != nullptr; }
};

// Wrapper around a type that uses `sodium_memzero` to zero the container on destruction; may only
// be used with trivially destructible types.
template <typename T, typename = std::enable_if_t<std::is_trivially_destructible_v<T>>>
struct sodium_cleared : T {
    using T::T;

    ~sodium_cleared() { sodium_zero_buffer(this, sizeof(*this)); }
};

template <size_t N>
using cleared_array = sodium_cleared<std::array<unsigned char, N>>;

using uc32 = std::array<unsigned char, 32>;
using uc33 = std::array<unsigned char, 33>;
using uc64 = std::array<unsigned char, 64>;
using cleared_uc32 = cleared_array<32>;
using cleared_uc64 = cleared_array<64>;

// This is an optional (i.e. can be empty) fixed-size (at construction) buffer that does allocation
// and freeing via libsodium.  It is slower and heavier than a regular allocation type but takes
// extra precautions, intended for storing sensitive values.
template <typename T>
struct sodium_array {
  private:
    T* buf;
    size_t len;

  public:
    // Default constructor: makes an empty object (that is, has no buffer and has `.size()` of 0).
    sodium_array() : buf{nullptr}, len{0} {}

    // Constructs an array with a given size, default-constructing the individual elements.
    template <typename = std::enable_if_t<std::is_default_constructible_v<T>>>
    explicit sodium_array(size_t length) :
            buf{length == 0 ? nullptr
                            : static_cast<T*>(sodium_buffer_allocate(length * sizeof(T)))},
            len{0} {

        if (length > 0) {
            if constexpr (std::is_trivial_v<T>) {
                std::memset(buf, 0, length * sizeof(T));
                len = length;
            } else if constexpr (std::is_nothrow_default_constructible_v<T>) {
                for (; len < length; len++)
                    new (buf[len]) T();
            } else {
                try {
                    for (; len < length; len++)
                        new (buf[len]) T();
                } catch (...) {
                    reset();
                    throw;
                }
            }
        }
    }

    ~sodium_array() { reset(); }

    // Moveable: ownership is transferred to the new object and the old object becomes empty.
    sodium_array(sodium_array&& other) : buf{other.buf}, len{other.len} {
        other.buf = nullptr;
        other.len = 0;
    }
    sodium_array& operator=(sodium_array&& other) {
        sodium_buffer_deallocate(buf);
        buf = other.buf;
        len = other.len;
        other.buf = nullptr;
        other.len = 0;
    }

    // Non-copyable
    sodium_array(const sodium_array&) = delete;
    sodium_array& operator=(const sodium_array&) = delete;

    // Destroys the held array; after destroying elements the allocated space is overwritten with
    // 0s before being deallocated.
    void reset() {
        if (buf) {
            if constexpr (!std::is_trivially_destructible_v<T>)
                while (len > 0)
                    buf[--len].~T();

            sodium_buffer_deallocate(buf);
        }
        buf = nullptr;
        len = 0;
    }

    // Calls reset() to destroy the current value (if any) and then allocates a new
    // default-constructed one of the given size.
    template <typename = std::enable_if_t<std::is_default_constructible_v<T>>>
    void reset(size_t length) {
        reset();
        if (length > 0) {
            buf = static_cast<T*>(sodium_buffer_allocate(length * sizeof(T)));
            if constexpr (std::is_trivial_v<T>) {
                std::memset(buf, 0, length * sizeof(T));
                len = length;
            } else {
                for (; len < length; len++)
                    new (buf[len]) T();
            }
        }
    }

    // Loads the array from a pointer and size; this first resets a value (if present), allocates a
    // new array of the given size, the copies the given value(s) into the new buffer.  T must be
    // copyable.  This is *not* safe to use if `buf` points into the currently allocated data.
    template <typename = std::enable_if_t<std::is_copy_constructible_v<T>>>
    void load(const T* data, size_t length) {
        reset(length);
        if (length == 0)
            return;

        if constexpr (std::is_trivially_copyable_v<T>)
            std::memcpy(buf, data, sizeof(T) * length);
        else
            for (; len < length; len++)
                new (buf[len]) T(data[len]);
    }

    const T& operator[](size_t i) const {
        assert(i < len);
        return buf[i];
    }
    T& operator[](size_t i) {
        assert(i < len);
        return buf[i];
    }

    T* data() { return buf; }
    const T* data() const { return buf; }

    size_t size() const { return len; }
    bool empty() const { return len == 0; }
    explicit operator bool() const { return !empty(); }

    T* begin() { return buf; }
    const T* begin() const { return buf; }
    T* end() { return buf + len; }
    const T* end() const { return buf + len; }

    using difference_type = ptrdiff_t;
    using value_type = T;
    using pointer = value_type*;
    using reference = value_type&;
    using iterator_category = std::random_access_iterator_tag;
};

// sodium Allocator wrapper; this allocates/frees via libsodium, which is designed for dealing with
// sensitive data.  It is as a result slower and has more overhead than a standard allocator and
// intended for use with a container (such as std::vector) when storing keys.
template <typename T>
struct sodium_allocator {
    using value_type = T;

    [[nodiscard]] static T* allocate(std::size_t n) {
        return static_cast<T*>(sodium_buffer_allocate(n * sizeof(T)));
    }

    static void deallocate(T* p, std::size_t) { sodium_buffer_deallocate(p); }

    template <typename T2>
    bool operator==(const sodium_allocator<T2>&) const noexcept {
        return true;
    }
    template <typename T2>
    bool operator!=(const sodium_allocator<T2>&) const noexcept {
        return false;
    }
};

/// Vector that uses sodium's secure (but heavy) memory allocations
template <typename T>
using sodium_vector = std::vector<T, sodium_allocator<T>>;

template <typename T>
using string_view_char_type = std::conditional_t<
        std::is_convertible_v<T, std::string_view>,
        char,
        std::conditional_t<
                std::is_convertible_v<T, std::basic_string_view<unsigned char>>,
                unsigned char,
                std::conditional_t<
                        std::is_convertible_v<T, std::basic_string_view<std::byte>>,
                        std::byte,
                        void>>>;

template <typename T>
constexpr bool is_char_array = false;
template <typename Char, size_t N>
inline constexpr bool is_char_array<std::array<Char, N>> =
        std::is_same_v<Char, char> || std::is_same_v<Char, unsigned char> ||
        std::is_same_v<Char, std::byte>;

/// Takes a container of string-like binary values and returns a vector of ustring_views viewing
/// those values.  This can be used on a container of any type with a `.data()` and a `.size()`
/// where `.data()` is a one-byte value pointer; std::string, std::string_view, ustring,
/// ustring_view, etc. apply, as does std::array of 1-byte char types.
///
/// This is useful in various libsession functions that require such a vector.  Note that the
/// returned vector's views are valid only as the original container remains alive; this is
/// typically used inline rather than stored, such as:
///
///     session::function_taking_a_view_vector(session::to_view_vector(mydata));
///
/// There are two versions of this: the first takes a generic iterator pair; the second takes a
/// single container.
template <typename It>
std::vector<ustring_view> to_view_vector(It begin, It end) {
    std::vector<ustring_view> vec;
    vec.reserve(std::distance(begin, end));
    for (; begin != end; ++begin) {
        if constexpr (std::is_same_v<std::remove_cv_t<decltype(*begin)>, char*>)  // C strings
            vec.emplace_back(*begin);
        else {
            static_assert(
                    sizeof(*begin->data()) == 1,
                    "to_view_vector can only be used with containers of string-like types of "
                    "1-byte characters");
            vec.emplace_back(reinterpret_cast<const unsigned char*>(begin->data()), begin->size());
        }
    }
    return vec;
}

template <typename Container>
std::vector<ustring_view> to_view_vector(const Container& c) {
    return to_view_vector(c.begin(), c.end());
}

/// Truncates a utf-8 encoded string to at most `n` bytes long, but with care as to not truncate in
/// the middle of a unicode codepoint.  If the `n` length would shorten the string such that it
/// terminates in the middle of a utf-8 encoded unicode codepoint then the string is shortened
/// further to not include the sliced unicode codepoint.
///
/// For example, "happy 🎂🎂🎂!!" in utf8 encoding is 20 bytes long:
/// "happy \xf0\x9f\x8e\x82\xf0\x9f\x8e\x82\xf0\x9f\x8e\x82!!", that is:
/// - "happy " (6 bytes)
/// - 🎂 = 0xf0 0x9f 0x8e 0x82 (12 bytes = 3 × 4 bytes each)
/// - "!!" (2 bytes)
/// Truncating this to different lengths results in:
/// - 20, 21, or higher - the 20-byte full string
/// - 19: "happy 🎂🎂🎂!"
/// - 18: "happy 🎂🎂🎂"
/// - 17: "happy 🎂🎂" (14 bytes)
/// - 16, 15, 14: same result as 17
/// - 13, 12, 11, 10: "happy 🎂"
/// - 9, 8, 7, 6: "happy "
/// - 5: "happy"
/// - 4: "happ"
/// - 3: "hap"
/// - 2: "ha"
/// - 1: "a"
/// - 0: ""
///
/// This function is *not* (currently) aware of unicode "characters", but merely codepoints (because
/// grapheme clusters get incredibly complicated).  This is only designed to prevent invalid utf8
/// encodings.  For example, the pair 🇦🇺 (REGIONAL INDICATOR SYMBOL LETTER A, REGIONAL INDICATOR
/// SYMBOL LETTER U) is often rendered as a single Australian flag, but could get chopped here into
/// just 🇦 (REGIONAL INDICATOR SYMBOL LETTER A) rather than removing the getting split in the middle
/// of the pair, which would show up as a decorated A rather than an Australian flag.  Another
/// example, é (LATIN SMALL LETTER E, COMBINING ACUTE ACCENT) could get chopped between the e and
/// the accent modifier, and end up as just "e" in the truncated string.
///
inline std::string utf8_truncate(std::string val, size_t n) {
    if (val.size() <= n)
        return val;
    // The *first* char in a utf8 sequence is either:
    // 0b0....... -- single byte encoding, for values up to 0x7f (ascii)
    // 0b11...... -- multi-byte encoding for values >= 0x80; the number of sequential high bit 1's
    // in the first character indicate the sequence length (e.g. 0b1110.... starts a 3-byte
    // sequence).  In our birthday cake encoding, the first byte is \xf0 == 0b11110000, and so it is
    // a 4-byte sequence.
    //
    // That leaves 0x10...... bytes as continuation bytes, each one holding 6 bits of the unicode
    // codepoint, in big endian order, so our birthday cake (in bits): 0b11110000 0b10011111
    // 0b10001110 0b10000010 is the unicode value 0b000 011111 001110 000010 == 0x1f382 == U+1F382:
    // BIRTHDAY CAKE).
    //
    // To prevent slicing, then, we just have to ensure the the first byte after the slice point is
    // *not* a continuation byte (and therefore is either a plain ascii character codepoint, or is
    // the start of a multi-character codepoint).
    while (n > 0 && (val[n] & 0b1100'0000) == 0b1000'0000)
        --n;

    val.resize(n);
    return val;
}

}  // namespace session
