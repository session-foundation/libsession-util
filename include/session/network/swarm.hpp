#pragma once

#include "session/network/key_types.hpp"

namespace session::network {
struct service_node;
}  // namespace session::network

namespace session::network::swarm {

using swarm_id_t = uint64_t;
constexpr swarm_id_t INVALID_SWARM_ID = std::numeric_limits<uint64_t>::max();

swarm_id_t pubkey_to_swarm_space(const session::network::x25519_pubkey& pk);
std::vector<std::pair<swarm_id_t, std::vector<service_node>>> generate_swarms(
        const std::vector<service_node> nodes);
std::pair<swarm_id_t, std::vector<service_node>> get_swarm(
        const session::network::x25519_pubkey swarm_pubkey,
        const std::vector<std::pair<swarm_id_t, std::vector<service_node>>> all_swarms);

}  // namespace session::network::swarm
