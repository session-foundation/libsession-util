#pragma once

#include "session/network/session_network_types.h"
#include "session/network/session_network_types.hpp"

namespace session::network::detail {
session_request_params* convert_cpp_request_to_c(const session::network::Request& req);
}