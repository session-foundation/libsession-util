#pragma once

#include "export.h"
#include <uchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Truncates an utf-16 encoded string to at most `codepoint_len` codepoints long, taking care to not
/// truncate in the middle of a surrogate pair.
LIBSESSION_EXPORT size_t utf16_len_for_codepoints(
    const char16_t *utf16_string,
    size_t utf16_string_len,
    size_t codepoint_len
);

#ifdef __cplusplus
}
#endif
