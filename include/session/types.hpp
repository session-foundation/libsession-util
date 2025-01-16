#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace session {

// Deprecated: we want to transition away from these to ecvecs/ucspans instead, because these break
// under libc++ 19.
using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

// Unsigned char vector
using uvec = std::vector<unsigned char>;
// Read-only unsigned char span:
using ucspan = std::span<const unsigned char>;
// Writeable unsigned char span:
using uspan = std::span<unsigned char>;

namespace config {

    using seqno_t = std::int64_t;

}  // namespace config

}  // namespace session
