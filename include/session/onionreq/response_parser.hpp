#pragma once

#include <string>

#include "hop_encryption.hpp"
#include "session/network/key_types.hpp"
#include "session/network/session_network_types.hpp"

namespace session::onionreq {

constexpr auto decryption_failed_error =
        "Decryption failed (both XChaCha20-Poly1305 and AES256-GCM)"sv;

struct DecryptedResponse {
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;
    std::optional<std::string> body;
};

class ResponseParser {
  public:
    /// Constructs a parser, parsing the given request sent to us.  Throws if parsing or decryption
    /// fails.
    ResponseParser(session::onionreq::Builder builder);
    ResponseParser(
            network::x25519_pubkey destination_x25519_public_key,
            network::x25519_keypair x25519_keypair,
            EncryptType enc_type = EncryptType::xchacha20,
            bool v4_request = false) :
            destination_x25519_public_key_{std::move(destination_x25519_public_key)},
            x25519_keypair_{std::move(x25519_keypair)},
            enc_type_{enc_type},
            v4_request_{v4_request} {}

    static bool response_long_enough(EncryptType enc_type, size_t response_size);

    std::vector<unsigned char> decrypt(std::vector<unsigned char> ciphertext) const;
    DecryptedResponse decrypted_response(const std::string& encrypted_response);

  private:
    network::x25519_pubkey destination_x25519_public_key_;
    network::x25519_keypair x25519_keypair_;
    EncryptType enc_type_;
    bool v4_request_;

    DecryptedResponse _decrypt_v3_response(const std::string& response);
    DecryptedResponse _decrypt_v4_response(const std::string& response);
};

}  // namespace session::onionreq
