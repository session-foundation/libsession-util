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

typedef struct cbytes32 cbytes32;
struct cbytes32 {
    unsigned char data[32];
};

typedef struct cbytes33 cbytes33;
struct cbytes33 {
    unsigned char data[33];
};

typedef struct cbytes64 cbytes64;
struct cbytes64 {
    unsigned char data[64];
};

#ifdef __cplusplus
}
#endif
