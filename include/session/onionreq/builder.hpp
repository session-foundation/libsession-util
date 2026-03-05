#pragma once

#include <oxen/quic/address.hpp>
#include <string>
#include <string_view>
#include <variant>

#include "session/network/session_network_types.hpp"

namespace session::network {
struct service_node;
struct request_info;
struct Request;
}  // namespace session::network

namespace session::onionreq {

namespace detail {

    session::network::x25519_pubkey pubkey_for_destination(
            network::network_destination destination);
}

enum class EncryptType {
    aes_gcm,
    xchacha20,
};

// Takes the encryption type as a string, returns the EncryptType value (or throws if invalid).
// Supported values: aes-gcm and xchacha20.  gcm is accepted as an aliases for aes-gcm.
EncryptType parse_enc_type(std::string_view enc_type);

inline constexpr std::string_view to_string(EncryptType type) {
    switch (type) {
        case EncryptType::xchacha20: return "xchacha20"sv;
        case EncryptType::aes_gcm: return "aes-gcm"sv;
    }
    return ""sv;
}

// Builder class for preparing onion request payloads.
class Builder {
  public:
    Builder(const network::network_destination& destination,
            const std::string& endpoint,
            const std::vector<network::service_node>& nodes,
            const EncryptType enc_type_ = EncryptType::xchacha20);

    static Builder make(
            const network::network_destination& destination,
            const std::string& endpoint,
            const std::vector<network::service_node>& nodes,
            const EncryptType enc_type_ = EncryptType::xchacha20);

    EncryptType enc_type;
    bool is_v4_request;
    std::optional<network::x25519_keypair> final_hop_x25519_keypair = std::nullopt;

    Builder(EncryptType enc_type_ = EncryptType::xchacha20) : enc_type{enc_type_} {}

    void set_enc_type(EncryptType enc_type_) { enc_type = enc_type_; }
    std::optional<network::x25519_pubkey> get_destination_x25519_public_key() const {
        return destination_x25519_public_key_;
    };

    void set_destination(network::network_destination destination);
    void add_hop(std::span<const unsigned char> remote_key);
    void add_hop(std::pair<network::ed25519_pubkey, network::x25519_pubkey> keys) {
        hops_.push_back(keys);
    }

    std::vector<unsigned char> build(std::vector<unsigned char> payload);
    std::vector<unsigned char> generate_onion_blob(
            const std::optional<std::vector<unsigned char>>& plaintext_body);

  private:
    std::vector<std::pair<network::ed25519_pubkey, network::x25519_pubkey>> hops_ = {};
    std::string endpoint_;
    std::optional<network::x25519_pubkey> destination_x25519_public_key_ = std::nullopt;

    // Snode request values

    std::optional<network::ed25519_pubkey> ed25519_public_key_ = std::nullopt;

    // Proxied request values

    std::optional<std::string> host_ = std::nullopt;
    std::optional<std::string> protocol_ = std::nullopt;
    std::optional<std::string> method_ = std::nullopt;
    std::optional<uint16_t> port_ = std::nullopt;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers_ = std::nullopt;
    std::optional<std::vector<std::pair<std::string, std::string>>> query_params_ = std::nullopt;

    std::vector<unsigned char> _generate_payload(
            std::optional<std::vector<unsigned char>> body) const;
};

}  // namespace session::onionreq
