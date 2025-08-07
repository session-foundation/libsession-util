#include "session/network/session_network_types.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "session/random.hpp"

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network {

Request::Request(
            std::string request_id,
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<unsigned char>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout,
            bool ephemeral_connection) :
            request_id{std::move(request_id)},
            destination{std::move(destination)},
            endpoint{std::move(endpoint)},
            body{std::move(body)},
            category{std::move(category)},
            request_timeout{std::move(request_timeout)},
            overall_timeout{std::move(overall_timeout)},
            ephemeral_connection{ephemeral_connection} {}

Request::Request(
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<unsigned char>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout,
            std::optional<std::string> request_id,
            bool ephemeral_connection) :
            request_id{std::move(request_id.value_or("R-{}"_format(random::random_base32(4))))},
            destination{std::move(destination)},
            endpoint{std::move(endpoint)},
            body{std::move(body)},
            category{std::move(category)},
            request_timeout{std::move(request_timeout)},
            overall_timeout{std::move(overall_timeout)},
            ephemeral_connection{ephemeral_connection} {}

}   // namespace session::network