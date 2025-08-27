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

struct string8 {
    char* data;
    size_t size;
};

#define string8_literal(literal) {(char *)literal, sizeof(literal) - 1}

struct bytes32 {
    uint8_t data[32];
};

struct bytes33 {
    uint8_t data[33];
};

struct bytes64 {
    uint8_t data[64];
};

/// Basic bump allocating arena
struct arena_t
{
    uint8_t *data;
    size_t size;
    size_t max;
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

/// Allocate the string with the specific size. Throws on allocation failure.
string8 string8_alloc_or_throw(size_t size);

/// Create a string by copying the given pointer and size. Throws on allocation failure
string8 string8_copy_or_throw(const void* data, size_t size);

/// Allocate memory from the basic bump allocating arena. Returns a null pointer on failure.
void* arena_alloc(arena_t* arena, size_t bytes);

/// Create a string and allocate a copy of the data at pointer and size
string8 arena_alloc_to_string8(arena_t* arena, void const* data, size_t size);

#ifdef __cplusplus
}
#endif
