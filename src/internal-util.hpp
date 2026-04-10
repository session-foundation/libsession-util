#pragma once
#include <fmt/format.h>

#include <algorithm>
#include <cstring>
#include <session/format.hpp>
#include <string_view>

using namespace session::literals;

namespace session {

// Copies `msg` into `buf`, truncating if necessary, always null-terminating.  Returns the number
// of bytes written INCLUDING the null terminator (i.e. the number of bytes of `buf` that were
// touched), or 0 if buf is null/empty.
inline size_t copy_c_str(char* buf, size_t buf_len, std::string_view msg) {
    if (!buf || !buf_len)
        return 0;
    auto n = std::min(msg.size(), buf_len - 1);
    std::memcpy(buf, msg.data(), n);
    buf[n++] = 0;
    return n;
}

// Overload for fixed-size char arrays; deduces the buffer size automatically.
template <size_t N>
size_t copy_c_str(char (&buf)[N], std::string_view msg) {
    return copy_c_str(buf, N, msg);
}

// Formats a message directly into a buffer with compile-time format checking.  Truncates if
// necessary, always null-terminates.  Returns the number of bytes written INCLUDING the null
// terminator, or 0 if buf is null/empty.
template <typename... Args>
size_t format_c_str(char* buf, size_t buf_len, fmt::format_string<Args...> format, Args&&... args) {
    if (!buf || !buf_len)
        return 0;
    auto result = fmt::format_to_n(buf, buf_len - 1, format, std::forward<Args>(args)...);
    *result.out = '\0';
    return static_cast<size_t>(result.out - buf) + 1;
}

}  // namespace session
