#pragma once

#include <string_view>

namespace session::network::backends {

struct ParsedFilePart {
    std::string_view file_id;
    std::string_view fragment;  // everything after '#', empty if none
};

static ParsedFilePart split_file_part(std::string_view file_part) {
    auto pos = file_part.find('#');
    auto id = (pos == std::string_view::npos ? file_part : file_part.substr(0, pos));

    if (!id.empty() && id.back() == '/')
        id.remove_suffix(1);

    if (pos == std::string_view::npos)
        return {id, ""};

    return {id, file_part.substr(pos + 1)};
}

}  // namespace session::network::backends
