#pragma once
#include <cstring>
#include <string_view>

namespace session {

// Used by various C APIs with false returns to write a caught exception message into an error
// buffer (if provided) on the way out.  The error buffer is expected to have at least 256 bytes
// available (the exception message will be truncated if longer than 255).
inline bool set_error(char* error, const std::exception& e) {
    if (error) {
        std::string_view err{e.what()};
        if (err.size() > 255)
            err.remove_suffix(err.size() - 255);
        std::memcpy(error, err.data(), err.size());
        error[err.size()] = 0;
    }

    return false;
}

}  // namespace session
