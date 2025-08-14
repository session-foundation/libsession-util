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

#ifdef __cplusplus
}
#endif
