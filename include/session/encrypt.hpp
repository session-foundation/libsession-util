#pragma once

#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/crypto_stream_xchacha20.h>

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>

#include "util.hpp"

namespace session::encryption {

// ─── Constants ───────────────────────────────────────────────────────────────

inline constexpr size_t XCHACHA20_KEYBYTES = 32;
inline constexpr size_t XCHACHA20_NONCEBYTES = 24;
inline constexpr size_t XCHACHA20_ABYTES = 16;  // authentication tag size

inline constexpr size_t BOX_PUBLICKEYBYTES = 32;
inline constexpr size_t BOX_SECRETKEYBYTES = 32;
inline constexpr size_t BOX_MACBYTES = 16;
inline constexpr size_t BOX_NONCEBYTES = 24;
inline constexpr size_t BOX_SEALBYTES = BOX_PUBLICKEYBYTES + BOX_MACBYTES;  // 48

inline constexpr size_t SECRETBOX_KEYBYTES = 32;
inline constexpr size_t SECRETBOX_NONCEBYTES = 24;
inline constexpr size_t SECRETBOX_MACBYTES = 16;

// ─── XChaCha20-Poly1305 AEAD ─────────────────────────────────────────────────

/// Encrypts `msg` with `key` and `nonce`, writing ciphertext (msg.size() + ABYTES bytes) into
/// `out`.
inline void xchacha20poly1305_encrypt(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key) {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ucdata(out), nullptr, ucdata(msg), msg.size(), nullptr, 0, nullptr,
            ucdata(nonce), ucdata(key));
}

/// Decrypts `ciphertext` with `key` and `nonce`, writing plaintext (ciphertext.size() - ABYTES
/// bytes) into `out`.  Returns false if authentication fails.
inline bool xchacha20poly1305_decrypt(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key) {
    return 0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                        ucdata(out), nullptr, nullptr,
                        ucdata(ciphertext), ciphertext.size(), nullptr, 0,
                        ucdata(nonce), ucdata(key));
}

// ─── XChaCha20 stream ────────────────────────────────────────────────────────

/// XOR-encrypts/decrypts `in` with the XChaCha20 keystream derived from `nonce` and `key`,
/// writing the result into `out`.  `out` and `in` must be the same size and may alias.
inline void xchacha20_xor(
        std::span<std::byte> out,
        std::span<const std::byte> in,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key) {
    crypto_stream_xchacha20_xor(ucdata(out), ucdata(in), in.size(), ucdata(nonce), ucdata(key));
}

// ─── HChaCha20 ───────────────────────────────────────────────────────────────

/// Derives a 32-byte subkey from a 32-byte key and a 16-byte nonce prefix using HChaCha20.
/// This is the subkey-derivation step used internally by XChaCha20.
inline void hchacha20(
        std::span<std::byte, crypto_core_hchacha20_OUTPUTBYTES> out,
        std::span<const std::byte, crypto_core_hchacha20_INPUTBYTES> nonce_prefix,
        std::span<const std::byte, crypto_core_hchacha20_KEYBYTES> key) {
    crypto_core_hchacha20(ucdata(out), ucdata(nonce_prefix), ucdata(key), nullptr);
}

// ─── Secretstream (streaming XChaCha20-Poly1305) ─────────────────────────────

/// Initialises a secretstream pull (decryption) state from a header and key.
inline void secretstream_init_pull(
        crypto_secretstream_xchacha20poly1305_state& st,
        std::span<const std::byte, crypto_secretstream_xchacha20poly1305_HEADERBYTES> header,
        std::span<const std::byte, crypto_secretstream_xchacha20poly1305_KEYBYTES> key) {
    crypto_secretstream_xchacha20poly1305_init_pull(&st, ucdata(header), ucdata(key));
}

/// Encrypts one chunk and appends it to the stream.  `out` must be at least
/// `in.size() + crypto_secretstream_xchacha20poly1305_ABYTES` bytes.  `ad` may be empty.
/// Returns the number of bytes written into `out`.
inline size_t secretstream_push(
        crypto_secretstream_xchacha20poly1305_state& st,
        std::span<std::byte> out,
        std::span<const std::byte> in,
        std::span<const std::byte> ad,
        unsigned char tag) {
    unsigned long long out_len;
    crypto_secretstream_xchacha20poly1305_push(
            &st, ucdata(out), &out_len, ucdata(in), in.size(), ucdata(ad), ad.size(), tag);
    return static_cast<size_t>(out_len);
}

/// Decrypts one chunk from the stream.  `out` must be at least
/// `in.size() - crypto_secretstream_xchacha20poly1305_ABYTES` bytes.  `ad` may be empty.
/// Returns the number of bytes written and sets `tag_out` on success, or returns std::nullopt if
/// authentication fails.
inline std::optional<size_t> secretstream_pull(
        crypto_secretstream_xchacha20poly1305_state& st,
        std::span<std::byte> out,
        unsigned char& tag_out,
        std::span<const std::byte> in,
        std::span<const std::byte> ad = {}) {
    unsigned long long out_len;
    if (0 !=
        crypto_secretstream_xchacha20poly1305_pull(
                &st, ucdata(out), &out_len, &tag_out, ucdata(in), in.size(), ucdata(ad), ad.size()))
        return std::nullopt;
    return static_cast<size_t>(out_len);
}

// ─── Box (X25519 + XSalsa20-Poly1305) ────────────────────────────────────────

/// Encrypts `msg` for `recipient_pk` from `sender_sk`, writing ciphertext into `out`.
/// `out` must be `msg.size() + BOX_MACBYTES` bytes.
inline void box_easy(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, BOX_NONCEBYTES> nonce,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> recipient_pk,
        std::span<const std::byte, BOX_SECRETKEYBYTES> sender_sk) {
    if (0 != crypto_box_easy(
                     ucdata(out),
                     ucdata(msg),
                     msg.size(),
                     ucdata(nonce),
                     ucdata(recipient_pk),
                     ucdata(sender_sk)))
        throw std::runtime_error{"crypto_box_easy failed (invalid public key?)"};
}

/// Seals `msg` for `pk` (anonymous sender), writing ciphertext into `out`.
/// `out` must be `msg.size() + BOX_SEALBYTES` bytes.
inline void box_seal(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> pk) {
    if (0 != crypto_box_seal(ucdata(out), ucdata(msg), msg.size(), ucdata(pk)))
        throw std::runtime_error{"crypto_box_seal failed (invalid public key?)"};
}

/// Decrypts a sealed box.  `out` must be `ciphertext.size() - BOX_SEALBYTES` bytes.
/// Returns false if authentication fails.
inline bool box_seal_open(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> pk,
        std::span<const std::byte, BOX_SECRETKEYBYTES> sk) {
    return 0 == crypto_box_seal_open(
                        ucdata(out), ucdata(ciphertext), ciphertext.size(), ucdata(pk), ucdata(sk));
}

// ─── Secretbox (XSalsa20-Poly1305 with shared key) ───────────────────────────

/// Decrypts a secretbox ciphertext using a shared key.  `out` must be
/// `ciphertext.size() - crypto_secretbox_MACBYTES` bytes.  Returns false if authentication fails.
inline bool secretbox_open_easy(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, SECRETBOX_NONCEBYTES> nonce,
        std::span<const std::byte, SECRETBOX_KEYBYTES> key) {
    return 0 ==
           crypto_secretbox_open_easy(
                   ucdata(out), ucdata(ciphertext), ciphertext.size(), ucdata(nonce), ucdata(key));
}

}  // namespace session::encryption
