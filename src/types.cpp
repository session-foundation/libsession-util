#include <fmt/core.h>
#include <session/types.h>

#include <cstdarg>
#include <session/types.hpp>

namespace session {
span_u8 span_u8_alloc_or_throw(size_t size) {
    span_u8 result = {};
    result.size = size;
    result.data = static_cast<uint8_t*>(malloc(size));
    if (!result.data)
        throw std::runtime_error(
                fmt::format("Failed to allocate {} bytes for span, out of memory", size));
    return result;
}

span_u8 span_u8_copy_or_throw(const void* data, size_t size) {
    span_u8 result = span_u8_alloc_or_throw(size);
    std::memcpy(result.data, data, result.size);
    return result;
}

string8 string8_alloc_or_throw(size_t size) {
    string8 result = {};
    result.size = size;
    result.data = static_cast<char*>(malloc(size + 1 /*null-terminator*/));
    if (!result.data)
        throw std::runtime_error(
                fmt::format("Failed to allocate {} bytes for string8, out of memory", size + 1));
    result.data[result.size] = 0;
    return result;
}

string8 string8_copy_or_throw(const void* data, size_t size) {
    string8 result = string8_alloc_or_throw(size);
    std::memcpy(result.data, data, result.size);
    result.data[result.size] = 0;
    return result;
}
};  // namespace session

int snprintf_clamped(char* buffer, size_t size, char const* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int bytes_required_not_incl_null = vsnprintf(buffer, size, fmt, args);
    va_end(args);

    int result = bytes_required_not_incl_null;
    if (buffer && size && bytes_required_not_incl_null >= (size - 1))
        result = size - 1;
    return result;
}

void* arena_alloc(arena_t* arena, size_t bytes) {
    void* result = nullptr;
    size_t new_size = arena->size + bytes;
    if (bytes && new_size <= arena->max) {
        result = arena->data + arena->size;
        arena->size = new_size;
    }
    return result;
}

string8 arena_alloc_to_string8(arena_t* arena, void const* data, size_t size) {
    string8 result = {};
    result.data = static_cast<char*>(arena_alloc(arena, size + 1));
    if (result.data) {
        result.size = size;
        std::memcpy(result.data, data, size);
        result.data[result.size] = 0;
    }
    return result;
}
