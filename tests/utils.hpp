#pragma once

#include <fmt/format.h>
#include <oxenc/hex.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "session/config/base.h"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using namespace oxenc::literals;
using namespace oxen::log::literals;

namespace session {

/// RAII class that resets the log level for the given category while the object is alive, then
/// resets it to what it was at construction when the object is destroyed.
struct log_level_override {
    oxen::log::Level previous;
    std::string category;

    log_level_override(oxen::log::Level l, std::string category) :
            previous{oxen::log::get_level(category)}, category{category} {
        oxen::log::set_level(category, l);
    }
    ~log_level_override() { oxen::log::set_level(category, previous); }
};

/// Same as above, but only raises the log level to a more serious cutoff (leaving it alone if
/// already higher).
struct log_level_raiser : log_level_override {
    log_level_raiser(oxen::log::Level l, std::string category) :
            log_level_override{std::max(l, oxen::log::get_level(category)), category} {}
};
/// Same as above, but only lowers the log level to a more frivolous cutoff (leaving it alone if
/// already lower).
struct log_level_lowerer : log_level_override {
    log_level_lowerer(oxen::log::Level l, std::string category) :
            log_level_override{std::min(l, oxen::log::get_level(category)), category} {}
};
}  // namespace session

inline std::vector<unsigned char> operator""_bytes(const char* x, size_t n) {
    auto begin = reinterpret_cast<const unsigned char*>(x);
    return {begin, begin + n};
}
inline std::vector<unsigned char> operator""_hexbytes(const char* x, size_t n) {
    std::vector<unsigned char> bytes;
    oxenc::from_hex(x, x + n, std::back_inserter(bytes));
    return bytes;
}

inline std::string to_hex(std::vector<unsigned char> bytes) {
    std::string hex;
    oxenc::to_hex(bytes.begin(), bytes.end(), std::back_inserter(hex));
    return hex;
}

inline constexpr auto operator""_kiB(unsigned long long kiB) {
    return kiB * 1024;
}

// Returns the current timestamp in milliseconds
inline int64_t get_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

// Returns the current timestamp in seconds
inline int64_t get_timestamp_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    ;
}

// Returns the current timestamp in microseconds
inline int64_t get_timestamp_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

inline std::string printable(std::span<const unsigned char> x) {
    std::string p;
    for (auto c : x) {
        if (c >= 0x20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}
inline std::string printable(std::string_view x) {
    return printable(session::to_span(x));
}
template <typename... T>
    requires(sizeof...(T) > 0)
inline std::string printable(fmt::format_string<T...> format, T&&... args) {
    return printable(session::to_span(fmt::format(format, std::forward<T>(args)...)));
}
std::string printable(const unsigned char* x) = delete;
inline std::string printable(const unsigned char* x, size_t n) {
    return printable({x, n});
}

template <typename Container>
std::set<typename Container::value_type> as_set(const Container& c) {
    return {c.begin(), c.end()};
}

template <typename... T>
std::set<std::common_type_t<T...>> make_set(T&&... args) {
    return {std::forward<T>(args)...};
}
