#pragma once

#include <oxen/quic/address.hpp>
#include <string>
#include <string_view>
#include <variant>

#include "key_types.hpp"

namespace session::network {
struct service_node;
struct request_info;
}  // namespace session::network

namespace session::onionreq {

struct ServerDestination {
    std::string protocol;
    std::string host;
    std::string endpoint;
    session::onionreq::x25519_pubkey x25519_pubkey;
    std::optional<uint16_t> port;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers;
    std::string method;

    ServerDestination(
            std::string protocol,
            std::string host,
            std::string endpoint,
            session::onionreq::x25519_pubkey x25519_pubkey,
            std::optional<uint16_t> port = std::nullopt,
            std::optional<std::vector<std::pair<std::string, std::string>>> headers = std::nullopt,
            std::string method = "GET") :
            protocol{std::move(protocol)},
            host{std::move(host)},
            endpoint{std::move(endpoint)},
            x25519_pubkey{std::move(x25519_pubkey)},
            port{std::move(port)},
            headers{std::move(headers)},
            method{std::move(method)} {}
};

using network_destination = std::variant<session::network::service_node, ServerDestination>;

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
    EncryptType enc_type;
    std::optional<x25519_pubkey> destination_x25519_public_key = std::nullopt;
    std::optional<x25519_keypair> final_hop_x25519_keypair = std::nullopt;

    Builder(EncryptType enc_type_ = EncryptType::xchacha20) : enc_type{enc_type_} {}

    void set_enc_type(EncryptType enc_type_) { enc_type = enc_type_; }

    void set_destination(network_destination destination);
    void set_destination_pubkey(session::onionreq::x25519_pubkey x25519_pubkey);
    void add_hop(std::pair<ed25519_pubkey, x25519_pubkey> keys) { hops_.push_back(keys); }

    ustring generate_payload(std::optional<ustring> body) const;
    ustring build(ustring payload);

  private:
    std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> hops_ = {};

    // Snode request values

    std::optional<ed25519_pubkey> ed25519_public_key_ = std::nullopt;

    // Proxied request values

    std::optional<std::string> host_ = std::nullopt;
    std::optional<std::string> endpoint_ = std::nullopt;
    std::optional<std::string> protocol_ = std::nullopt;
    std::optional<std::string> method_ = std::nullopt;
    std::optional<uint16_t> port_ = std::nullopt;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers_ = std::nullopt;
    std::optional<std::vector<std::pair<std::string, std::string>>> query_params_ = std::nullopt;
};

}  // namespace session::onionreq
