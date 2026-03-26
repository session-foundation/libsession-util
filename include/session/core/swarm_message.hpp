#pragma once

#include <session/clock.hpp>
#include <span>
#include <string>

namespace session::core {

/// A single message retrieved from the swarm, as returned by a retrieve request.  The data,
/// hash, timestamp, and expiry fields are exactly the four values the server returns per
/// message; data is owned externally and must remain valid for the lifetime of this struct.
struct SwarmMessage {
    std::span<const unsigned char> data;
    std::string hash;
    sys_ms timestamp;
    sys_ms expiry;
};

}  // namespace session::core
