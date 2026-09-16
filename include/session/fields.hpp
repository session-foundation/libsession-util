#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "util.hpp"

namespace session {

using namespace std::literals;

/// An uploaded file is its URL + decryption key
struct Uploaded {
    std::string url;
    std::string key;
};

/// A conversation disappearing messages setting
struct Disappearing {
    /// The possible modes of a disappearing messages setting.
    enum class Mode : int { None = 0, AfterSend = 1, AfterRead = 2 };

    /// The mode itself
    Mode mode = Mode::None;

    /// The timer value; this is only used when mode is not None.
    std::chrono::seconds timer = 0s;
};

}  // namespace session
