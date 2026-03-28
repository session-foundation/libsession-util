#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPTIONAL
#if defined(_MSC_VER)
#define NON_NULL_ARG(...)
#else
#define NON_NULL_ARG(...) __attribute__((nonnull(__VA_ARGS__)))
#endif

/// C friendly buffer structure that is a pointer and length to a span of bytes.
typedef struct span_u8 span_u8;
struct span_u8 {
    unsigned char* data;
    size_t size;
};

typedef struct string8 string8;
struct string8 {
    char* data;
    size_t size;
};

#define string8_literal(literal) {(char*)literal, sizeof(literal) - 1}

typedef struct bytes32 bytes32;
struct bytes32 {
    unsigned char data[32];
};

typedef struct bytes33 bytes33;
struct bytes33 {
    unsigned char data[33];
};

typedef struct bytes64 bytes64;
struct bytes64 {
    unsigned char data[64];
};

/// Basic bump allocating arena
typedef struct arena_t arena_t;
struct arena_t {
    unsigned char* data;
    size_t size;
    size_t max;
};

/// Allocate memory from the basic bump allocating arena. Returns a null pointer on failure.
void* arena_alloc(arena_t* arena, size_t bytes);

/// Create a string and allocate a copy of the data at pointer and size
string8 arena_alloc_to_string8(arena_t* arena, void const* data, size_t size);

#ifdef __cplusplus
}
#endif
