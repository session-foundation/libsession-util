#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// C friendly buffer structure that is a pointer and length to a span of bytes.
struct span_u8 {
    uint8_t* data;
    size_t size;
};

struct bytes32 {
    uint8_t data[32];
};

struct bytes33 {
    uint8_t data[33];
};

struct bytes64 {
    uint8_t data[64];
};

/// Create a span of bytes that owns the `size` bytes of memory requested. If allocation fails, this
/// function throws a runtime exception. The `data` pointer is span must be freed once the span
/// is no longer needed.
span_u8 span_u8_alloc_or_throw(size_t size);

/// Create a span of bytes that copies the payload at `data` for `size` bytes. If allocation fails
/// this function throws a runtime exception. The `data` pointer is span must be freed once the span
/// is no longer needed.
span_u8 span_u8_copy_or_throw(const void* data, size_t size);

/// A wrapper around snprintf that fixes a common bug in the value the printing function returns
/// when a buffer is passed in. Irrespective of whether a buffer is passed in, snprintf is defined
/// to return:
///
///  number of characters (not including the terminating null character) which would have been
///  written to buffer if bufsz was ignored
///
/// This means if the user passes in a buffer to small, the return value is always the amount of
/// bytes required. This means the user always has to calculate the number of bytes written as:
///
///   size_t bytes_written = min(snprintf(buffer, size, ...), size);
///
/// This is error prone. This function does the `min(...)` for you so that this function
/// _always_ calculates the actual number of bytes written (not including the null-terminator). If a
/// NULL is passed in then this function returns the number of bytes actually needed to write the
/// entire string (as per normal snprintf behaviour).
int snprintf_bytes_written_clamped(char* buffer, size_t size, char const* fmt, ...);

#ifdef __cplusplus
}
#endif
