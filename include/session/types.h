#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct span_u8
{
    uint8_t *data;
    size_t size;
};

span_u8 span_u8_alloc_or_throw(size_t size);
span_u8 span_u8_copy_or_throw(const void *data, size_t size);

#ifdef __cplusplus
}
#endif
