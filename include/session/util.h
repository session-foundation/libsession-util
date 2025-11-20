#pragma once

#include "export.h"
#include <uchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Truncates an utf-16 encoded string to at most `codepoint_len` codepoints long, taking care to not
/// truncate in the middle of a surrogate pair. Notes that if the input string contains invalid
/// UTF-16 sequences (e.g. unpaired surrogates) the behavior here is undefined.
LIBSESSION_EXPORT size_t utf16_count_truncated_to_codepoints(
    const char16_t *utf16_string,
    size_t utf16_string_len,
    size_t codepoint_len
);

/// Returns the number of unicode codepoints in a utf-16 encoded string.
LIBSESSION_EXPORT size_t utf16_count(
    const char16_t *utf16_string,
    size_t utf16_string_len
);

#ifdef __cplusplus
}
#endif
