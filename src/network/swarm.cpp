#include "session/network/swarm.hpp"

#include <oxenc/endian.h>

#include "session/network/service_node.hpp"
#include "session/network/session_network.hpp"

namespace session::network::swarm {

swarm_id_t pubkey_to_swarm_space(const session::network::x25519_pubkey& pk) {
    swarm_id_t res = 0;
    for (size_t i = 0; i < 4; i++) {
        swarm_id_t buf;
        std::memcpy(&buf, pk.data() + i * 8, 8);
        res ^= buf;
    }
    oxenc::big_to_host_inplace(res);

    return res;
}

std::vector<std::pair<swarm_id_t, std::vector<service_node>>> generate_swarms(
        const std::vector<service_node> nodes) {
    std::vector<std::pair<swarm_id_t, std::vector<service_node>>> result;
    std::unordered_map<uint64_t, std::vector<service_node>> _grouped_nodes;

    for (const auto& node : nodes)
        _grouped_nodes[node.swarm_id].push_back(node);

    for (auto& [swarm_id, nodes] : _grouped_nodes)
        result.emplace_back(swarm_id, std::move(nodes));

    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    return result;
}

std::pair<swarm_id_t, std::vector<service_node>> get_swarm(
        const session::network::x25519_pubkey swarm_pubkey,
        const std::vector<std::pair<swarm_id_t, std::vector<service_node>>> all_swarms) {
    // If there is only a single swarm then return it
    if (all_swarms.size() == 1)
        return all_swarms.front();

    // Generate a swarm_id for the pubkey
    const swarm_id_t swarm_id = pubkey_to_swarm_space(swarm_pubkey);

    // Find the right boundary, i.e. first swarm with swarm_id >= res
    auto right_it = std::lower_bound(
            all_swarms.begin(), all_swarms.end(), swarm_id, [](const auto& s, uint64_t v) {
                return s.first < v;
            });

    if (right_it == all_swarms.end())
        // res is > the top swarm_id, meaning it is big and in the wrapping space between last
        // and first elements.
        right_it = all_swarms.begin();

    // Our "left" is the one just before that (with wraparound, if right is the first swarm)
    auto left_it = std::prev(right_it == all_swarms.begin() ? all_swarms.end() : right_it);

    uint64_t dright = right_it->first - swarm_id;
    uint64_t dleft = swarm_id - left_it->first;
    auto swarm = &*(dright < dleft ? right_it : left_it);

    return *swarm;
}

}  // namespace session::network::swarm
