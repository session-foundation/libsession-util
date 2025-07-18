#include "session/network/service_node.hpp"

#include <fmt/ranges.h>

#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    /// Converts a string such as "1.2.3" to a vector of ints {1,2,3}.  Throws if something
    /// in/around the .'s isn't parseable as an integer.
    std::vector<int> parse_version(std::string_view vers, bool trim_trailing_zero = true) {
        auto v_s = session::split(vers, ".");
        std::vector<int> result;
        for (const auto& piece : v_s)
            if (!quic::parse_int(piece, result.emplace_back()))
                throw std::invalid_argument{"Invalid version"};

        // Remove any trailing `0` values (but ensure we at least end up with a "0" version)
        if (trim_trailing_zero)
            while (result.size() > 1 && result.back() == 0)
                result.pop_back();

        return result;
    }
}  // namespace

service_node service_node::from(const network_service_node& node) {
    std::vector<int> version;
    version.reserve(3);

    for (int i = 0; i < 3; ++i)
        version.push_back(node.version[i]);

    std::string ip = fmt::format("{}.{}.{}.{}",
        node.ip[0], node.ip[1], node.ip[2], node.ip[3]);

    return {
        oxenc::from_hex({node.ed25519_pubkey_hex, 64}),
        std::move(version),
        INVALID_SWARM_ID,
        ip,
        node.quic_port // TODO: Decide when we need HTTPS_port???
    };
}

service_node service_node::from_json(nlohmann::json json) {
    auto pk_ed = json["pubkey_ed25519"].get<std::string_view>();
    if (pk_ed.size() != 64 || !oxenc::is_hex(pk_ed))
        throw std::invalid_argument{
                "Invalid service node json: pubkey_ed25519 is not a valid, hex pubkey"};

    // When parsing a node from JSON it'll generally be from the 'get_swarm` endpoint or a 421
    // error neither of which contain the `storage_server_version` - luckily we don't need the
    // version for these two cases so can just default it to `0`
    std::vector<int> storage_server_version = {0};
    if (json.contains("storage_server_version")) {
        if (json["storage_server_version"].is_array()) {
            if (json["storage_server_version"].size() > 0) {
                // Convert the version to a string and parse it back into a version code to
                // ensure the version formats remain consistent throughout
                storage_server_version = json["storage_server_version"].get<std::vector<int>>();
                storage_server_version =
                        parse_version("{}"_format(fmt::join(storage_server_version, ".")));
            }
        } else
            storage_server_version =
                    parse_version(json["storage_server_version"].get<std::string>());
    }

    std::string ip;
    if (json.contains("public_ip"))
        ip = json["public_ip"].get<std::string>();
    else
        ip = json["ip"].get<std::string>();

    if (ip == "0.0.0.0")
        throw std::runtime_error{"Invalid IP address"};

    uint16_t port;
    if (json.contains("storage_lmq_port"))
        port = json["storage_lmq_port"].get<uint16_t>();
    else
        port = json["port_omq"].get<uint16_t>();

    if (port == 0)
        throw std::runtime_error{"Invalid lmq port"};

    swarm_id_t swarm_id = INVALID_SWARM_ID;
    if (json.contains("swarm_id"))
        swarm_id = json["swarm_id"].get<swarm_id_t>();

    return {oxenc::from_hex(pk_ed), storage_server_version, swarm_id, ip, port};
}

service_node service_node::from_disk(std::string_view str, bool can_ignore_version) {
    // Format is "{ip}|{port}|{version}|{ed_pubkey}|{swarm_id}"
    auto parts = split(str, "|");
    if (parts.size() != 5)
        throw std::invalid_argument("Invalid service node serialisation: {}"_format(str));
    if (parts[3].size() != 64 || !oxenc::is_hex(parts[3]))
        throw std::invalid_argument{
                "Invalid service node serialisation: pubkey is not hex or has wrong size"};

    uint16_t port;
    if (!quic::parse_int(parts[1], port))
        throw std::invalid_argument{"Invalid service node serialization: invalid port"};

    std::vector<int> storage_server_version = parse_version(parts[2]);
    if (!can_ignore_version && storage_server_version == std::vector<int>{0})
        throw std::invalid_argument{"Invalid service node serialization: invalid version"};

    swarm_id_t swarm_id = INVALID_SWARM_ID;
    quic::parse_int(parts[4], swarm_id);

    return {
            oxenc::from_hex(parts[3]),  // ed25519_pubkey
            storage_server_version,     // storage_server_version
            swarm_id,                   // swarm_id
            std::string(parts[0]),      // ip
            port,                       // port
    };
}

std::string service_node::to_disk() const {
    // Format is "{ip}|{port}|{version}|{ed_pubkey}|{swarm_id}"
    auto ed25519_pubkey_hex = oxenc::to_hex(view_remote_key());

    return fmt::format(
            "{}|{}|{}|{}|{}",
            host(),
            port(),
            "{}"_format(fmt::join(storage_server_version, ".")),
            ed25519_pubkey_hex,
            swarm_id);
}

}  // namespace session::network