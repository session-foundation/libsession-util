#pragma once

#include <uchar.h>

/// Truncates an utf-16 encoded string to at most `codepoint_len` codepoints long, taking care to not
/// truncate in the middle of a surrogate pair.
size_t utf16_len_for_codepoints(
    const char16_t *utf16_string,
    size_t utf16_string_len,
    size_t codepoint_len
);