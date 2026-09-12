#pragma once

#include <session/types.hpp>

#include "hop_encryption.hpp"

namespace session::onionreq {

/// The default maximum size of an onion request accepted by the OnionReqParser constructor.
constexpr size_t DEFAULT_MAX_SIZE = 10'485'760;  // 10 MiB

class OnionReqParser {
  private:
    network::x25519_keypair keys;
    HopEncryption enc;
    EncryptType enc_type = EncryptType::aes_gcm;
    network::x25519_pubkey remote_pk;
    std::vector<std::byte> payload_;

  public:
    /// Constructs a parser, parsing the given request sent to us.  Throws if parsing or decryption
    /// fails.
    OnionReqParser(
            std::span<const std::byte, 32> x25519_pubkey,
            std::span<const std::byte, 32> x25519_privkey,
            std::span<const std::byte> req,
            size_t max_size = DEFAULT_MAX_SIZE);

    /// plaintext payload, decrypted from the incoming request during construction.
    std::span<const std::byte> payload() const { return payload_; }

    /// Extracts payload from this object (via a std::move); after the call the object's payload
    /// will be empty.
    std::vector<std::byte> move_payload() {
        std::vector<std::byte> ret{std::move(payload_)};
        payload_.clear();  // Guarantee empty, even if SSO active
        return ret;
    }

    std::span<const std::byte, 32> remote_pubkey() const { return remote_pk; }

    /// Encrypts a reply using the appropriate encryption as determined when parsing the
    /// request.
    std::vector<std::byte> encrypt_reply(std::span<const std::byte> reply) const;
};

}  // namespace session::onionreq
