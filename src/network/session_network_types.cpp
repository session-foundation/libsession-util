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
        std::optional<uint8_t> desired_path_index,
        RequestDetails details) :
        request_id{std::move(request_id)},
        destination{std::move(destination)},
        endpoint{std::move(endpoint)},
        body{std::move(body)},
        category{std::move(category)},
        request_timeout{std::move(request_timeout)},
        overall_timeout{std::move(overall_timeout)},
        desired_path_index{std::move(desired_path_index)},
        details{details} {}

Request::Request(
        network_destination destination,
        std::string endpoint,
        std::optional<std::vector<unsigned char>> body,
        RequestCategory category,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout,
        std::optional<uint8_t> desired_path_index,
        std::optional<std::string> request_id,
        RequestDetails details) :
        request_id{std::move(request_id.value_or(random::unique_id("R")))},
        destination{std::move(destination)},
        endpoint{std::move(endpoint)},
        body{std::move(body)},
        category{std::move(category)},
        request_timeout{std::move(request_timeout)},
        overall_timeout{std::move(overall_timeout)},
        desired_path_index{std::move(desired_path_index)},
        details{details} {}

static const std::unordered_map<std::string_view, std::pair<int16_t, bool>> error_map = {
        {"400 Bad Request", {400, false}},
        {"401 Unauthorized", {401, false}},
        {"403 Forbidden", {403, false}},
        {"404 Not Found", {404, false}},
        {"405 Method Not Allowed", {405, false}},
        {"406 Not Acceptable", {406, false}},
        {"408 Request Timeout", {408, false}},
        {"500 Internal Server Error", {500, false}},
        {"502 Bad Gateway", {502, false}},
        {"503 Service Unavailable", {503, false}},
        {"504 Gateway Timeout", {504, true}},
};

std::optional<std::pair<int16_t, bool>> response::parse_text_error(std::string_view body) {

    for (const auto& [prefix, result] : error_map)
        if (body.starts_with(prefix))
            return result;

    return std::nullopt;
}

std::optional<int16_t> response::find_uniform_batch_error(std::string_view body) {
    try {
        auto json = nlohmann::json::parse(body);

        // If it wasn't a batch response then just handle the non-batch status code
        if (json.contains("results") && json["results"].is_array() && !json["results"].empty()) {
            int16_t first_status_code = -1;

            for (const auto& result : json["results"]) {
                if (!result.contains("code") || !result["code"].is_number())
                    return std::nullopt;

                // If we got a success then we can just use the original status code
                int16_t code = result["code"].get<int16_t>();
                if (code >= 200 && code <= 299)
                    return std::nullopt;

                if (first_status_code == -1)
                    first_status_code = code;
                else if (first_status_code != code)
                    return std::nullopt;
            }

            return first_status_code;
        }
    } catch (...) { /* Do nothing */
    }

    return std::nullopt;
}

}  // namespace session::network
