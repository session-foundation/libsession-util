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
    std::vector<unsigned char> payload_;

  public:
    /// Constructs a parser, parsing the given request sent to us.  Throws if parsing or decryption
    /// fails.
    OnionReqParser(
            std::span<const unsigned char> x25519_pubkey,
            std::span<const unsigned char> x25519_privkey,
            std::span<const unsigned char> req,
            size_t max_size = DEFAULT_MAX_SIZE);

    /// plaintext payload, decrypted from the incoming request during construction.
    std::span<const unsigned char> payload() const { return to_span(payload_); }

    /// Extracts payload from this object (via a std::move); after the call the object's payload
    /// will be empty.
    std::vector<unsigned char> move_payload() {
        std::vector<unsigned char> ret{std::move(payload_)};
        payload_.clear();  // Guarantee empty, even if SSO active
        return ret;
    }

    std::span<const unsigned char> remote_pubkey() const { return to_span(remote_pk.view()); }

    /// Encrypts a reply using the appropriate encryption as determined when parsing the
    /// request.
    std::vector<unsigned char> encrypt_reply(std::span<const unsigned char> reply) const;
};

}  // namespace session::onionreq
