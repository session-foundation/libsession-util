#include <charconv>
#include <session/util.hpp>

namespace session {

std::vector<std::string_view> split(std::string_view str, const std::string_view delim, bool trim) {
    std::vector<std::string_view> results;
    // Special case for empty delimiter: splits on each character boundary:
    if (delim.empty()) {
        results.reserve(str.size());
        for (size_t i = 0; i < str.size(); i++)
            results.emplace_back(str.data() + i, 1);
        return results;
    }

    for (size_t pos = str.find(delim); pos != std::string_view::npos; pos = str.find(delim)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        str.remove_prefix(pos + delim.size());
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

std::tuple<std::string, std::string, std::optional<uint16_t>, std::optional<std::string>> parse_url(
        std::string_view url) {
    std::tuple<std::string, std::string, std::optional<uint16_t>, std::optional<std::string>>
            result{};
    auto& [proto, host, port, path] = result;
    if (auto pos = url.find("://"); pos != std::string::npos) {
        auto proto_name = url.substr(0, pos);
        url.remove_prefix(proto_name.size() + 3);
        if (string_iequal(proto_name, "http"))
            proto = "http://";
        else if (string_iequal(proto_name, "https"))
            proto = "https://";
    }
    if (proto.empty())
        throw std::invalid_argument{"Invalid URL: invalid/missing protocol://"};

    bool next_allow_dot = false;
    bool has_dot = false;
    while (!url.empty()) {
        auto c = url.front();
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '-') {
            host += c;
            next_allow_dot = true;
        } else if (c >= 'A' && c <= 'Z') {
            host += c + ('a' - 'A');
            next_allow_dot = true;
        } else if (next_allow_dot && c == '.') {
            host += '.';
            has_dot = true;
            next_allow_dot = false;
        } else {
            break;
        }
        url.remove_prefix(1);
    }
    if (host.size() < 4 || !has_dot || host.back() == '.')
        throw std::invalid_argument{"Invalid URL: invalid hostname"};

    if (!url.empty() && url.front() == ':') {
        url.remove_prefix(1);
        uint16_t target_port;
        if (auto [p, ec] = std::from_chars(url.data(), url.data() + url.size(), target_port);
            ec == std::errc{})
            url.remove_prefix(p - url.data());
        else
            throw std::invalid_argument{"Invalid URL: invalid port"};
        if (!(target_port == 80 && proto == "http://") && !(target_port == 443 && proto == "https:/"
                                                                                           "/"))
            port = target_port;
    }

    if (url.size() > 1 && url.front() == '/')
        path = url;
    else if (!url.empty() && url.front() == '/') {
        url.remove_prefix(1);
        path = std::nullopt;
    }

    return result;
}

}  // namespace session
