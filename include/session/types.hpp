#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <version>

#include "types.h"

namespace session {

template <typename T, typename... U>
static constexpr bool is_one_of = (std::is_same_v<T, U> || ...);

#if defined(__cpp_lib_is_scoped_enum) && __cpp_lib_is_scoped_enum >= 202011L

template <typename T>
using is_scoped_enum = std::is_scoped_enum<T>;

#else

/// `enum class`, as distinct from a plain `enum`: what tells them apart is that an unscoped
/// enumerator converts to its underlying integer on its own and a scoped one does not.
///
/// The `bool` parameter is what keeps `underlying_type_t` from being instantiated for a non-enum,
/// where it is ill-formed.
template <typename T, bool = std::is_enum_v<T>>
struct is_scoped_enum : std::false_type {};

template <typename T>
struct is_scoped_enum<T, true>
        : std::bool_constant<!std::is_convertible_v<T, std::underlying_type_t<T>>> {};

#endif

template <typename T>
inline constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;

enum class SessionIDPrefix {
    standard = 0,
    group = 0x3,
    community_blinded_legacy = 0x5,
    community_blinded = 0x15,
    version_blinded = 0x25,
    unblinded = 0x7,
};

namespace config {
    using seqno_t = std::int64_t;
}

/// Create a span of bytes that owns the `size` bytes of memory requested. If allocation fails, this
/// function throws a runtime exception. The `data` pointer is span must be freed once the span
/// is no longer needed.
span_u8 span_u8_alloc_or_throw(size_t size);

/// Create a span of bytes that copies the payload at `data` for `size` bytes. If allocation fails
/// this function throws a runtime exception. The `data` pointer is span must be freed once the span
/// is no longer needed.
span_u8 span_u8_copy_or_throw(const void* data, size_t size);
}  // namespace session
