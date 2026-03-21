#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <type_traits>

namespace session {

/// A clock satisfying the C++ Clock named requirement whose time_point is identical to
/// std::chrono::system_clock::time_point.  Returns system time adjusted by a configurable offset,
/// making it suitable for both production use (where the offset is learned from the network) and
/// unit testing (where the offset can be set to any desired value).
struct AdjustedClock {
    using duration = std::chrono::system_clock::duration;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::system_clock::time_point;
    static constexpr bool is_steady = false;

    /// Returns the current time, adjusted by the current offset.
    static time_point now() noexcept {
        return std::chrono::system_clock::now() + duration{_offset.load(std::memory_order_relaxed)};
    }

    /// Sets the clock offset.  Accepts any duration implicitly convertible to
    /// system_clock::duration (e.g. std::chrono::milliseconds, seconds, nanoseconds).
    static void set_offset(duration offset) {
        _offset.store(offset.count(), std::memory_order_relaxed);
    }

    /// Returns the current clock offset.
    static duration get_offset() { return duration{_offset.load(std::memory_order_relaxed)}; }

  private:
    inline static std::atomic<rep> _offset{0};
};

// Returns the current time from AdjustedClock, optionally floored to the given precision.
// E.g. clock_now<std::chrono::seconds>() gives a timepoint with seconds precision (aka
// std::chrono::sys_seconds).
template <typename Precision = std::chrono::system_clock::duration>
inline std::chrono::sys_time<Precision> clock_now() {
    return std::chrono::floor<Precision>(AdjustedClock::now());
}
// Shortcut for clock_now<std::chrono::seconds>();
inline std::chrono::sys_seconds clock_now_s() {
    return clock_now<std::chrono::seconds>();
}
using sys_ms = std::chrono::sys_time<std::chrono::milliseconds>;
// Shortcut for clock_now<std::chrono::milliseconds>();
inline sys_ms clock_now_ms() {
    return clock_now<std::chrono::milliseconds>();
}

// Returns the duration count of the given duration cast into ToDuration.  Example:
//     duration_count<std::chrono::seconds>(30000ms)  // returns 30
// This function requires that the target type is no more precise than d, that is, it will not allow
// you to cast from seconds to milliseconds because such a cast indicates that the sub-second
// precision has already been lost.
template <typename ToDuration, typename Rep, typename Period>
    requires std::is_convertible_v<ToDuration, std::chrono::duration<Rep, Period>>
constexpr int64_t duration_count(const std::chrono::duration<Rep, Period>& d) {
    return std::chrono::duration_cast<ToDuration>(d).count();
}
// Returns the seconds count of the given duration
template <typename Rep, typename Period>
    requires std::is_convertible_v<std::chrono::seconds, std::chrono::duration<Rep, Period>>
constexpr int64_t duration_seconds(const std::chrono::duration<Rep, Period>& d) {
    return duration_count<std::chrono::seconds>(d);
}
// Returns the milliseconds count of the given duration
template <typename Rep, typename Period>
    requires std::is_convertible_v<std::chrono::milliseconds, std::chrono::duration<Rep, Period>>
constexpr int64_t duration_ms(const std::chrono::duration<Rep, Period>& d) {
    return duration_count<std::chrono::milliseconds>(d);
}

// Returns the time-since-epoch count of the given time point, cast into ToDuration.  The given time
// point must be at least as precise as ToDuration, i.e. this will not allow you to cast to a more
// precise time point as that would mean the intended precision has already been lost by an earlier
// cast.
template <class ToDuration, class Clock, class Duration>
    requires std::is_convertible_v<ToDuration, Duration>
constexpr int64_t epoch_count(const std::chrono::time_point<Clock, Duration>& t) {
    return duration_count<ToDuration>(t.time_since_epoch());
}
// Returns the seconds-since-epoch count of the given time point.  The given time point must be at
// least as precise as seconds.
template <class Clock, class Duration>
    requires std::is_convertible_v<std::chrono::seconds, Duration>
constexpr int64_t epoch_seconds(const std::chrono::time_point<Clock, Duration>& t) {
    return duration_seconds(t.time_since_epoch());
}
// Returns the milliseconds-since-epoch count of the given time point.  The given time point must
// have at least milliseconds precision.
template <class Clock, class Duration>
    requires std::is_convertible_v<std::chrono::milliseconds, Duration>
constexpr int64_t epoch_ms(const std::chrono::time_point<Clock, Duration>& t) {
    return duration_ms(t.time_since_epoch());
}

// Inverse of epoch_count/epoch_seconds/epoch_ms: reconstruct a sys_time with the given duration
// precision from a raw integer count of that duration since the epoch.
template <typename Duration>
inline std::chrono::sys_time<Duration> from_epoch(int64_t t) {
    return std::chrono::sys_time<Duration>{Duration{t}};
}
// Shortcuts for the common cases:
inline std::chrono::sys_seconds from_epoch_s(int64_t t) {
    return from_epoch<std::chrono::seconds>(t);
}
inline sys_ms from_epoch_ms(int64_t t) {
    return from_epoch<std::chrono::milliseconds>(t);
}

}  // namespace session
