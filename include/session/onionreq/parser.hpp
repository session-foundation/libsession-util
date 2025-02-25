#pragma once

#include <session/types.hpp>

#include "hop_encryption.hpp"

namespace session::onionreq {

/// The default maximum size of an onion request accepted by the OnionReqParser constructor.
constexpr size_t DEFAULT_MAX_SIZE = 10'485'760;  // 10 MiB

class OnionReqParser {
  private:
    x25519_keypair keys;
    HopEncryption enc;
    EncryptType enc_type = EncryptType::aes_gcm;
    x25519_pubkey remote_pk;
    std::vector<unsigned char> payload_;

  public:
    /// Constructs a parser, parsing the given request sent to us.  Throws if parsing or decryption
    /// fails.
    OnionReqParser(
            uspan x25519_pubkey,
            uspan x25519_privkey,
            uspan req,
            size_t max_size = DEFAULT_MAX_SIZE);

    /// plaintext payload, decrypted from the incoming request during construction.
    uspan payload() const { return vec_to_span<unsigned char>(payload_); }

    /// Extracts payload from this object (via a std::move); after the call the object's payload
    /// will be empty.
    std::vector<unsigned char> move_payload() {
        std::vector<unsigned char> ret{std::move(payload_)};
        payload_.clear();  // Guarantee empty, even if SSO active
        return ret;
    }

    uspan remote_pubkey() const { return str_to_uspan(remote_pk.view()); }

    /// Encrypts a reply using the appropriate encryption as determined when parsing the
    /// request.
    std::vector<unsigned char> encrypt_reply(uspan reply) const;
};

}  // namespace session::onionreq
