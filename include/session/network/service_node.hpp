#pragma once

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>

#include "session/network/service_node.h"
#include "session/network/swarm.hpp"

namespace session::network {

using namespace session::network::swarm;

struct service_node : public oxen::quic::RemoteAddress {
  public:
    std::vector<int> storage_server_version;
    swarm_id_t swarm_id;

    service_node() = delete;

    template <typename... Opt>
    service_node(
            std::string_view remote_pk,
            std::vector<int> storage_server_version,
            swarm_id_t swarm_id,
            Opt&&... opts) :
            oxen::quic::RemoteAddress{remote_pk, std::forward<Opt>(opts)...},
            storage_server_version{storage_server_version},
            swarm_id{swarm_id} {}

    template <typename... Opt>
    service_node(
            std::span<const unsigned char> remote_pk,
            std::vector<int> storage_server_version,
            swarm_id_t swarm_id,
            Opt&&... opts) :
            oxen::quic::RemoteAddress{remote_pk, std::forward<Opt>(opts)...},
            storage_server_version{storage_server_version},
            swarm_id{swarm_id} {}

    service_node(const service_node& obj) :
            oxen::quic::RemoteAddress{obj},
            storage_server_version{obj.storage_server_version},
            swarm_id{obj.swarm_id} {}

    service_node& operator=(const service_node& obj) {
        storage_server_version = obj.storage_server_version;
        swarm_id = obj.swarm_id;
        oxen::quic::RemoteAddress::operator=(obj);
        _copy_internals(obj);
        return *this;
    }

    auto operator<=>(const service_node& other) const = delete;
    bool operator==(const service_node& other) const {
        return RemoteAddress::operator==(other) &&
               storage_server_version == other.storage_server_version && swarm_id == other.swarm_id;
    }

    static service_node from(const network_service_node& node);
    static service_node from_json(nlohmann::json json);
    static service_node from_disk(std::string_view str, bool can_ignore_version = false);

    std::string to_disk() const;
};

}  // namespace session::network
