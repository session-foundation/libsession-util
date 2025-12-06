#pragma once

#include <string>
#include <string_view>

#include "builder.hpp"
#include "key_types.hpp"

namespace session::onionreq {

// Encryption/decription class for encryption/decrypting outgoing/incoming messages.
class HopEncryption {
  public:
    HopEncryption(x25519_seckey private_key, x25519_pubkey public_key, bool server = true) :
            private_key_{std::move(private_key)},
            public_key_{std::move(public_key)},
            server_{server} {}

    // Returns true if the response is long enough to be a valid response.
    static bool response_long_enough(EncryptType type, size_t response_size);

    // Encrypts `plaintext` message using encryption `type`. `pubkey` is the recipients public key.
    // `reply` should be false for a client-to-snode message, and true on a returning
    // snode-to-client message.
    std::vector<unsigned char> encrypt(
            EncryptType type,
            std::vector<unsigned char> plaintext,
            const x25519_pubkey& pubkey) const;
    std::vector<unsigned char> decrypt(
            EncryptType type,
            std::vector<unsigned char> ciphertext,
            const x25519_pubkey& pubkey) const;

    // AES-GCM encryption.
    std::vector<unsigned char> encrypt_aesgcm(
            std::vector<unsigned char> plainText, const x25519_pubkey& pubKey) const;
    std::vector<unsigned char> decrypt_aesgcm(
            std::vector<unsigned char> cipherText, const x25519_pubkey& pubKey) const;

    // xchacha20-poly1305 encryption; for a message sent from client Alice to server Bob we use a
    // shared key of a Blake2B 32-byte (i.e. crypto_aead_xchacha20poly1305_ietf_KEYBYTES) hash of
    // H(aB || A || B), which Bob can compute when receiving as H(bA || A || B).  The returned value
    // always has the crypto_aead_xchacha20poly1305_ietf_NPUBBYTES nonce prepended to the beginning.
    //
    // When Bob (the server) encrypts a method for Alice (the client), he uses shared key
    // H(bA || A || B) (note that this is *different* that what would result if Bob was a client
    // sending to Alice the client).
    std::vector<unsigned char> encrypt_xchacha20(
            std::vector<unsigned char> plaintext, const x25519_pubkey& pubKey) const;
    std::vector<unsigned char> decrypt_xchacha20(
            std::vector<unsigned char> ciphertext, const x25519_pubkey& pubKey) const;

  private:
    const x25519_seckey private_key_;
    const x25519_pubkey public_key_;
    bool server_;  // True if we are the server (i.e. the snode).
};

}  // namespace session::onionreq
