#pragma once

#include <stdint.h>

#include <array>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "ed25519.hpp"

// Helper functions for the "Session Protocol" encryption mechanism.  This is the encryption used
// for DMs sent from one Session user to another.
//
// Suppose Alice with Ed25519 keys `a`/`A` and derived x25519 keys `x`/`X`, wants to send a mesage
// `M` to Brandy with Ed25519 keys `b`/`B` and derived x25519 keys `y`/`Y` (note that the x25519
// pubkeys in hex form are session ids, but without the `05` prefix).
//
// First she signs the message, her own *Ed25519* (not X) pubkey, and the recipients pubkey (X, not
// Ed):
//
//     SIG = Ed25519-sign(M || A || Y)
//
// Next a data message is composed of `M || A || SIG`, then encrypted for Brandy using:
//
//     CIPHERTEXT = crypto_box_seal(M || A || SIG)
//
// (see libsodium for details, but is effectively generating an ephemeral X25519 keypair, making a
// shared secret of that and the recipient key, then encrypting using XSalsa20-Poly1305 from the
// shared secret).
//
// On the decryption side, we do this in reverse and verify via the signature both the sender and
// intended (inner) recipient.  First, Brandy opens the ciphertext and extract the message, sender
// Ed pubkey, and signature:
//
//     M || A || SIG = crypto_box_seal_open(CIPHERTEXT)
//
// then constructs and verifies the expected signature DATA (recall Y = Brandy's X25519 pubkey):
//
//     Ed25519-verify(M || A || Y)
//
// Assuming this passes, we now know that `A` sent the message, and can convert this to a X25519
// pubkey to work out the Session ID:
//
//     X = Ed25519-pubkey-to-curve25519(A)
//
//     SENDER = '05' + hex(X)
//
// and thus Brandy now has decrypted, verified data sent by Alice.

namespace session {

/// API: crypto/encrypt_for_recipient
///
/// Performs session protocol encryption, typically for a DM sent between Session users.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key of the sender; accepts a 32-byte seed or
///   64-byte libsodium key (the latter avoids recomputing the public key from the seed).
/// - `recipient_pubkey` -- the recipient X25519 pubkey, either as a 0x05-prefixed session ID
///   (33 bytes) or an unprefixed pubkey (32 bytes).
/// - `message` -- the message to encrypt for the recipient.
///
/// Outputs:
/// - The encrypted ciphertext to send.
/// - Throw if encryption fails or (which typically means invalid keys provided)
std::vector<unsigned char> encrypt_for_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char> recipient_pubkey,
        std::span<const unsigned char> message);

/// API: crypto/encrypt_for_recipient_deterministic
///
/// Performs session protocol encryption, but using a deterministic version of crypto_box_seal.
///
/// Warning: this determinism completely undermines the point of crypto_box_seal (compared to a
/// regular encrypted crypto_box): someone with the same sender Ed25519 keys and message could later
/// regenerate the same ephemeral key and nonce which would allow them to decrypt the sent message,
/// which is intentionally impossible with a crypto_box_seal.  This function is thus only
/// recommended for backwards compatibility with decryption mechanisms using that scheme where this
/// specific property is not needed, such as self-directed config messages.
///
/// Inputs:
/// Identical to `encrypt_for_recipient`.
///
/// Outputs:
/// Identical to `encrypt_for_recipient`.
std::vector<unsigned char> encrypt_for_recipient_deterministic(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char> recipient_pubkey,
        std::span<const unsigned char> message);

/// API: crypto/session_encrypt_for_blinded_recipient
///
/// This function attempts to encrypt a message using the SessionBlindingProtocol.
///
/// Inputs:
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes.  Can also be
///   passed as a 32-byte seed, but the 64-byte value is preferrable (to avoid needing to
///   recompute the public key from the seed).
/// - `recipient_pubkey` -- the recipient blinded id, either 0x15-prefixed or 0x25-prefixed
///   (33 bytes).
/// - `message` -- the message to encrypt for the recipient.
///
/// Outputs:
/// - The encrypted ciphertext to send.
/// - Throw if encryption fails or (which typically means invalid keys provided)
std::vector<unsigned char> encrypt_for_blinded_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char, 32> server_pk,
        std::span<const unsigned char, 33> recipient_blinded_id,
        std::span<const unsigned char> message);

/// API: crypto/encrypt_for_recipient_v2
///
/// Encrypts a v2 Session DM (PFS + post-quantum) for a recipient.
///
/// The wire format of the returned ciphertext is:
///   0x00 0x02 | ki (2B) | E (32B) | mlkem_ct (1088B) | xchacha20poly1305_ciphertext
///
/// where:
/// - `ki` is an encrypted key indicator used by the recipient to cheaply identify which of
///   their current account keys was used, without revealing it to outside observers.
/// - `E` is an ephemeral X25519 pubkey.
/// - `mlkem_ct` is an ML-KEM-768 ciphertext.
/// - The xchacha20poly1305 ciphertext contains the signed, padded inner plaintext.
///
/// The inner plaintext is a bt-encoded dict with:
/// - "S": the sender's Ed25519 pubkey (32 bytes)
/// - "c": the message content (typically a serialized protobuf Content)
/// - "~": a 64-byte Ed25519 signature over a BLAKE2b-64 hash of the preceding content,
///        keyed with the recipient's 33-byte Session ID (personalized "SessionV2Message")
/// - "~P": optional Session Pro Ed25519 signature verifying the sender's Pro status.  The public
///         key for verifying this is embedded within the protobuf Content.  Present only when the
///         message uses Session Pro features; absent otherwise.
///
/// Inputs:
/// - `sender_ed25519_privkey` -- sender's 32-byte seed or 64-byte Ed25519 secret key
/// - `recipient_session_id` -- 33-byte 0x05-prefixed long-term X25519 pubkey (S with prefix)
/// - `recipient_account_x25519` -- 32-byte recently-fetched PFS account X25519 pubkey (X)
/// - `recipient_account_mlkem768` -- 1184-byte recently-fetched PFS account ML-KEM-768 pubkey (M)
/// - `content` -- the plaintext message content to encrypt (typically a serialized protobuf)
/// - `pro_signature` -- optional 64-byte Session Pro Ed25519 signature.  Pass nullopt when the
///                      sender is not using Session Pro features.
///
/// Outputs:
/// - The encrypted v2 ciphertext to send to the swarm.
/// - Throws on invalid keys or encryption failure.
std::vector<unsigned char> encrypt_for_recipient_v2(
        const Ed25519PrivKeySpan& sender_ed25519_privkey,
        std::span<const unsigned char, 33> recipient_session_id,
        std::span<const unsigned char, 32> recipient_account_x25519,
        std::span<const unsigned char, 1184> recipient_account_mlkem768,
        std::span<const unsigned char> content,
        std::optional<std::span<const unsigned char, 64>> pro_signature = std::nullopt);

/// Exception thrown when a v2 message could not be decrypted with a given account key.  The
/// caller should catch this and try the next candidate key.  Other exceptions (e.g.,
/// std::runtime_error for invalid message format, or std::invalid_argument for bad keys) are
/// unrecoverable and should not be caught per-key.
struct DecryptV2Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Result of decrypt_incoming_v2.
struct DecryptV2Result {
    std::vector<unsigned char> content;               ///< Decrypted message content.
    std::array<unsigned char, 33> sender_session_id;  ///< 05-prefixed Session ID of the sender.
    std::optional<std::array<unsigned char, 64>> pro_signature;  ///< Pro sig, if present.
};

/// API: crypto/decrypt_incoming_v2_prefix
///
/// Extracts and decrypts the 2-byte key indicator from a v2 Session DM ciphertext, returning
/// the first 2 bytes of the ML-KEM-768 public key that was used to encrypt the message.
///
/// This is a cheap pre-filter step: the caller uses the returned prefix to look up which of
/// their PFS account keys match, then passes the matching key(s) to `decrypt_incoming_v2`.
///
/// Inputs:
/// - `x25519_sec` -- 32-byte long-term X25519 secret key of the recipient (the raw key, *not*
///   the Ed25519 key).
/// - `x25519_pub` -- 32-byte long-term X25519 public key of the recipient (i.e. the Session ID
///   bytes without the `0x05` prefix).
/// - `ciphertext` -- wire-format v2 ciphertext as produced by `encrypt_for_recipient_v2`.
///
/// Outputs:
/// - The recovered 2-byte ML-KEM-768 public key prefix.
/// - Throws `std::runtime_error` if the ciphertext is too short or has the wrong prefix bytes.
std::array<unsigned char, 2> decrypt_incoming_v2_prefix(
        std::span<const unsigned char, 32> x25519_sec,
        std::span<const unsigned char, 32> x25519_pub,
        std::span<const unsigned char> ciphertext);

/// API: crypto/decrypt_incoming_v2
///
/// Inverse of `encrypt_for_recipient_v2`: decrypts a v2 Session DM using a single PFS account
/// key.  Verifies the X-Wing (ML-KEM-768 + X25519) shared secret derivation and the inner
/// Ed25519 message signature.
///
/// Typical usage: call `decrypt_incoming_v2_prefix` to get the 2-byte ML-KEM prefix, look up
/// all PFS account keys whose ML-KEM-768 public key begins with that prefix, then call this
/// function for each candidate, catching `DecryptV2Error` and trying the next key on failure:
///
///     auto prefix = decrypt_incoming_v2_prefix(x25519_sec, x25519_pub, ciphertext);
///     for (auto& key : pfs_keys_by_prefix(prefix)) {
///         try {
///             return decrypt_incoming_v2(session_id, key.x_sec, key.x_pub,
///                                        key.mlkem_sec, ciphertext);
///         } catch (const DecryptV2Error&) { continue; }
///     }
///     throw std::runtime_error{"no PFS account key could decrypt the message"};
///
/// Inputs:
/// - `recipient_session_id` -- 33-byte 0x05-prefixed Session ID of the recipient.  Used to
///   verify the inner Ed25519 message signature; no private key material is needed here.
/// - `account_pfs_x25519_sec` -- 32-byte X25519 secret key of the PFS account key to try.
/// - `account_pfs_x25519_pub` -- 32-byte X25519 public key of the PFS account key to try.
/// - `account_pfs_mlkem768_sec` -- 2400-byte ML-KEM-768 secret key of the PFS account key
///   to try.
/// - `ciphertext` -- wire-format v2 ciphertext as produced by `encrypt_for_recipient_v2`.
///
/// Outputs:
/// - `DecryptV2Result` with the decrypted content, 33-byte (05-prefixed) sender Session ID,
///   and an optional 64-byte Session Pro signature.
/// - Throws `DecryptV2Error` if the key did not decrypt the message (try the next candidate).
/// - Throws `std::runtime_error` for unrecoverable errors (invalid format, signature failure).
DecryptV2Result decrypt_incoming_v2(
        std::span<const unsigned char, 33> recipient_session_id,
        std::span<const unsigned char, 32> account_pfs_x25519_sec,
        std::span<const unsigned char, 32> account_pfs_x25519_pub,
        std::span<const unsigned char, 2400> account_pfs_mlkem768_sec,
        std::span<const unsigned char> ciphertext);

/// API: crypto/encrypt_for_recipient_v2_nopfs
///
/// Encrypts a v2 Session DM using the non-PFS fallback (long-term X25519 DH only).
///
/// Wire format is identical to `encrypt_for_recipient_v2`:
///   0x00 0x02 | ki (2B) | E (32B) | outer_ct (1088B) | xchacha20poly1305_ciphertext
///
/// but `ki` and `outer_ct` carry no key material — they are random bytes used only to make
/// non-PFS messages externally indistinguishable from PFS+PQ messages.  The actual shared
/// secret is derived as:
///   ss  = eR   (X25519 DH with ephemeral secret e and recipient long-term pubkey R)
///   ss  = SHA3-256(ss || R || E || "SessionV2NonPFS")
///   k,n = SHAKE256("SessionV2NonPFSSS", ss)   → 32-byte key + 24-byte nonce
///
/// Inputs:
/// - `sender_ed25519_privkey` -- sender's 32-byte seed or 64-byte Ed25519 secret key
/// - `recipient_session_id` -- 33-byte 0x05-prefixed long-term X25519 pubkey of the recipient
/// - `content` -- the plaintext message content to encrypt
/// - `pro_signature` -- optional 64-byte Session Pro signature
///
/// Outputs:
/// - Wire-format v2 ciphertext (non-PFS).
/// - Throws on key or encryption failure.
std::vector<unsigned char> encrypt_for_recipient_v2_nopfs(
        const Ed25519PrivKeySpan& sender_ed25519_privkey,
        std::span<const unsigned char, 33> recipient_session_id,
        std::span<const unsigned char> content,
        std::optional<std::span<const unsigned char, 64>> pro_signature = std::nullopt);

/// API: crypto/decrypt_incoming_v2_nopfs
///
/// Decrypts a v2 Session DM using the non-PFS fallback (long-term X25519 DH only).
///
/// Performs the inverse of `encrypt_for_recipient_v2_nopfs`.  The `ki` and ML-KEM fields in
/// the wire format are ignored; only the ephemeral pubkey E and the recipient's long-term
/// X25519 key pair are used.
///
/// Inputs:
/// - `recipient_session_id` -- 33-byte 0x05-prefixed Session ID of the recipient (used to
///   verify the inner Ed25519 message signature).
/// - `x25519_sec` -- 32-byte long-term X25519 secret key of the recipient.
/// - `x25519_pub` -- 32-byte long-term X25519 public key of the recipient.
/// - `ciphertext` -- wire-format v2 ciphertext.
///
/// Outputs:
/// - `DecryptV2Result` with the decrypted content, sender Session ID, and optional Pro sig.
/// - Throws `DecryptV2Error` if AEAD authentication fails (wrong key — try PFS path instead).
/// - Throws `std::runtime_error` for unrecoverable errors (invalid format, signature failure).
DecryptV2Result decrypt_incoming_v2_nopfs(
        std::span<const unsigned char, 33> recipient_session_id,
        std::span<const unsigned char, 32> x25519_sec,
        std::span<const unsigned char, 32> x25519_pub,
        std::span<const unsigned char> ciphertext);

static constexpr size_t GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE = 1'000'000;

/// API: crypto/encrypt_for_group
///
/// Compresses, signs, and encrypts group message content.
///
/// This function is passed a binary value containing a group message (typically a serialized
/// protobuf, but this method doesn't care about the specific data).  That data will be, in
/// order:
/// - compressed (but only if this actually reduces the data size)
/// - signed by the user's underlying session Ed25519 pubkey
/// - tagged with the user's underlying session Ed25519 pubkey (from which the session id can be
///   computed).
/// - all of the above encoded into a bt-encoded dict
/// - suffix-padded with null bytes so that the final output value will be a multiple of 256
///   bytes
/// - encrypted with the most-current group encryption key
///
/// Since compression and padding is applied as part of this method, it is not required that the
/// given message include its own padding (and in fact, such padding will typically be
/// compressed down to nothing (if non-random)).
///
/// This final encrypted value is then returned to be pushed to the swarm as-is (i.e. not
/// further wrapped).  For users downloading the message, all of the above is processed in
/// reverse by passing the returned message into `decrypt_message()`.
///
/// The current implementation uses XChaCha20-Poly1305 for encryption and zstd for compression;
/// the bt-encoded value is a dict consisting of keys:
/// - "": the version of this encoding, currently set to 1.  This *MUST* be bumped if this is
///   changed in such a way that older clients will not be able to properly decrypt such a
///   message.
/// - "a": the *Ed25519* pubkey (32 bytes) of the author of the message.  (This will be
///   converted to a x25519 pubkey to extract the sender's session id when decrypting).
/// - "s": signature by "a" of whichever of "d" or "z" are included in the data.
/// Exacly one of:
/// - "d": the uncompressed data (which must be non-empty if present)
/// - "z": the zstd-compressed data (which must be non-empty if present)
///
/// When compression is enabled (by omitting the `compress` argument or specifying it as true)
/// then ZSTD compression will be *attempted* on the plaintext message and will be used if the
/// compressed data is smaller than the uncompressed data.  If disabled, or if compression does
/// not reduce the size, then the message will not be compressed.
///
/// This function will throw on failure:
/// - if any of the keys passed in are invalidly sized or non-valid keys
/// - if there no encryption keys are available at all (which should not occur in normal use).
/// - if given a plaintext buffer larger than 1MB (even if the compressed version would be much
///   smaller).  It is recommended that clients impose their own limits much smaller than this
///   on data passed into encrypt_message; this limitation is in *this* function to match the
///   `decrypt_message` limit which is merely intended to guard against decompression memory
///   exhaustion attacks.
///
/// Inputs:
/// - `user_ed25519_privkey` -- the Ed25519 private key of the user; accepts a 32-byte seed or
///   64-byte libsodium key (the latter avoids recomputing the public key from the seed).
/// - `group_ed25519_pubkey` -- The 32 byte public key of the group
/// - group_enc_key -- The group's encryption key (32 bytes or 64-byte libsodium key) for groups v2
///   messages, typically the latest key for the group (e.g., Keys::group_enc_key).
/// - `plaintext` -- the binary message to encrypt.
/// - `compress` -- can be specified as `false` to forcibly disable compression.  Normally
///   omitted, to use compression if and only if it reduces the size.
/// - `padding` -- the padding multiple: padding will be added as needed to attain a multiple of
///   this value for the final result.  0 or 1 disables padding entirely.  Normally omitted to
///   use the default of next-multiple-of-256.
///
/// Outputs:
/// - `ciphertext` -- the encrypted, etc. value to send to the swarm
std::vector<unsigned char> encrypt_for_group(
        const Ed25519PrivKeySpan& user_ed25519_privkey,
        std::span<const unsigned char, 32> group_ed25519_pubkey,
        std::span<const unsigned char> group_enc_key,
        std::span<const unsigned char> plaintext,
        bool compress,
        size_t padding);

/// API: crypto/sign_for_recipient
///
/// Performs the signing steps for session protocol encryption.  This is responsible for producing
/// a packed authored, signed message of:
///
///     MESSAGE || SENDER_ED25519_PUBKEY || SIG
///
/// where SIG is the signed value of:
///
///     MESSAGE || SENDER_ED25519_PUBKEY || RECIPIENT_X25519_PUBKEY
///
/// thus allowing both sender identification, recipient verification, and authentication.
///
/// This function is mostly for internal use, but is exposed for debugging purposes: it is typically
/// not called directly but rather used by `encrypt_for_recipient` or
/// `encrypt_for_recipient_deterministic`, both of which call this function to construct the inner
/// signed message.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key of the sender; accepts a 32-byte seed or
///   64-byte libsodium key.
/// - `recipient_pubkey` -- the recipient X25519 pubkey, which may or may not be prefixed with the
///   0x05 session id prefix (33 bytes if prefixed, 32 if not prefixed).
/// - `message` -- the message to embed and sign.
std::vector<unsigned char> sign_for_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char> recipient_pubkey,
        std::span<const unsigned char> message);

/// API: crypto/decrypt_incoming
///
/// Inverse of `encrypt_for_recipient`: this decrypts the message, extracts the sender Ed25519
/// pubkey, and verifies that the sender Ed25519 signature on the message.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key of the recipient; accepts a 32-byte seed or
///   64-byte libsodium key.
/// - `ciphertext` -- the encrypted data
///
/// Outputs:
/// - `std::pair<std::vector<unsigned char>, std::vector<unsigned char>>` -- the plaintext binary
/// data that was encrypted and the
///   sender's ED25519 pubkey, *if* the message decrypted and validated successfully.  Throws on
///   error.
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> decrypt_incoming(
        const Ed25519PrivKeySpan& ed25519_privkey, std::span<const unsigned char> ciphertext);

/// API: crypto/decrypt_incoming
///
/// Inverse of `encrypt_for_recipient`: this decrypts the message, extracts the sender Ed25519
/// pubkey, and verifies that the sender Ed25519 signature on the message. This function is used
/// for decrypting legacy group messages which only have an x25519 key pair, the Ed25519 version
/// of this function should be preferred where possible.
///
/// Inputs:
/// - `ed25519_privkey` -- the private key of the recipient.  Can be a 32-byte seed, or a 64-byte
///   libsodium secret key.  The latter is a bit faster as it doesn't have to re-compute the pubkey
///   from the seed.
/// - `ciphertext` -- the encrypted data
///
/// Outputs:
/// - `std::pair<std::vector<unsigned char>, std::vector<unsigned char>>` -- the plaintext binary
/// data that was encrypted and the
///   sender's ED25519 pubkey, *if* the message decrypted and validated successfully.  Throws on
///   error.
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> decrypt_incoming(
        std::span<const unsigned char, 32> x25519_pubkey,
        std::span<const unsigned char, 32> x25519_seckey,
        std::span<const unsigned char> ciphertext);

/// API: crypto/decrypt_incoming
///
/// Inverse of `encrypt_for_recipient`: this decrypts the message, verifies that the sender Ed25519
/// signature on the message and converts the extracted sender's Ed25519 pubkey into a session ID.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key of the recipient; accepts a 32-byte seed or
///   64-byte libsodium key.
/// - `ciphertext` -- the encrypted data
///
/// Outputs:
/// - `std::pair<std::vector<unsigned char>, std::string>` -- the plaintext binary data that was
/// encrypted and the
///   session ID (in hex), *if* the message decrypted and validated successfully.  Throws on error.
std::pair<std::vector<unsigned char>, std::string> decrypt_incoming_session_id(
        const Ed25519PrivKeySpan& ed25519_privkey, std::span<const unsigned char> ciphertext);

/// API: crypto/decrypt_incoming
///
/// Inverse of `encrypt_for_recipient`: this decrypts the message, verifies that the sender Ed25519
/// signature on the message and converts the extracted sender's Ed25519 pubkey into a session ID.
/// This function is used for decrypting legacy group messages which only have an x25519 key pair,
/// the Ed25519 version of this function should be preferred where possible.
///
/// Inputs:
/// - `x25519_pubkey` -- the 32 byte x25519 public key of the recipient.
/// - `x25519_seckey` -- the 32 byte x25519 private key of the recipient.
/// - `ciphertext` -- the encrypted data
///
/// Outputs:
/// - `std::pair<std::vector<unsigned char>, std::string>` -- the plaintext binary data that was
/// encrypted and the
///   session ID (in hex), *if* the message decrypted and validated successfully.  Throws on error.
std::pair<std::vector<unsigned char>, std::string> decrypt_incoming_session_id(
        std::span<const unsigned char, 32> x25519_pubkey,
        std::span<const unsigned char, 32> x25519_seckey,
        std::span<const unsigned char> ciphertext);

/// API: crypto/decrypt_from_blinded_recipient
///
/// This function attempts to decrypt a message using the SessionBlindingProtocol. If the
/// `sender_id` matches the `blinded_id` generated from the `ed25519_privkey` this function assumes
/// the `ciphertext` is an outgoing message and decrypts it as such.
///
/// Inputs:
/// - `ed25519_privkey` -- the Ed25519 private key of the receiver; accepts a 32-byte seed or
///   64-byte libsodium key.
/// - `server_pk` -- the public key of the community server to route the blinded message through
/// (32 bytes).
/// - `sender_id` -- the blinded id of the sender including the blinding prefix (33 bytes),
///   'blind15' or 'blind25' decryption will be chosed based on this value.
/// - `recipient_id` -- the blinded id of the recipient including the blinding prefix (33 bytes),
///   must match the same 'blind15' or 'blind25' type of the `sender_id`.
/// - `ciphertext` -- Pointer to a data buffer containing the encrypted data.
///
/// Outputs:
/// - `std::pair<std::vector<unsigned char>, std::string>` -- the plaintext binary data that was
/// encrypted and the
///   session ID (in hex), *if* the message decrypted and validated successfully.  Throws on error.
std::pair<std::vector<unsigned char>, std::string> decrypt_from_blinded_recipient(
        const Ed25519PrivKeySpan& ed25519_privkey,
        std::span<const unsigned char, 32> server_pk,
        std::span<const unsigned char, 33> sender_id,
        std::span<const unsigned char, 33> recipient_id,
        std::span<const unsigned char> ciphertext);

struct DecryptGroupMessage {
    size_t index;            // Index of the key that successfully decrypted the message
    std::string session_id;  // In hex
    std::vector<unsigned char> plaintext;
};

/// API: crypto/decrypt_group_message
///
/// Decrypts group message content that was presumably encrypted with `encrypt_for_group`,
/// verifies the sender signature, decompresses the message (if necessary) and then returns the
/// author pubkey and the plaintext data.
///
/// To prevent against memory exhaustion attacks, this method will fail if the value is
/// a compressed value that would decompress to a value larger than 1MB.
///
/// Inputs:
/// - `decrypt_ed25519_privkey_list` -- the list of private keys to try to decrypt the message with.
///   Can be a 32-byte seed, or a 64-byte libsodium secret key. The public key component is not
///   used.
/// - `group_ed25519_pubkey` -- the 32 byte public key of the group
/// - `ciphertext` -- an encrypted, encoded, signed, (possibly) compressed message as produced
///   by `encrypt_message()`.
///
/// Outputs:
/// - `std::pair<std::string, std::vector<unsigned char>>` -- the session ID (in hex) and the
/// plaintext binary
///   data that was encrypted.
///
/// On failure this throws a std::exception-derived exception with a `.what()` string containing
/// some diagnostic info on what part failed.  Typically a production session client would catch
/// (and possibly log) but otherwise ignore such exceptions and just not process the message if
/// it throws.
DecryptGroupMessage decrypt_group_message(
        std::span<std::span<const unsigned char>> decrypt_ed25519_privkey_list,
        std::span<const unsigned char, 32> group_ed25519_pubkey,
        std::span<const unsigned char> ciphertext);

/// API: crypto/decrypt_ons_response
///
/// Decrypts the response of an ONS lookup.
///
/// Inputs:
/// - `lowercase_name` -- the lowercase name which was looked to up to retrieve this response.
/// - `ciphertext` -- ciphertext returned from the server.
/// - `nonce` -- the nonce returned from the server if provided.
///
/// Outputs:
/// - `std::string` -- the session ID (in hex) returned from the server, *if* the server returned
///   a session ID.  Throws on error/failure.
std::string decrypt_ons_response(
        std::string_view lowercase_name,
        std::span<const unsigned char> ciphertext,
        std::optional<std::span<const unsigned char, 24>> nonce);

/// API: crypto/decrypt_push_notification
///
/// Decrypts a push notification payload.
///
/// Inputs:
/// - `payload` -- the payload included in the push notification.
/// - `enc_key` -- the device encryption key used when subscribing for push notifications (32
/// bytes).
///
/// Outputs:
/// - `std::vector<unsigned char>` -- the decrypted push notification payload, *if* the decryption
/// was
///   successful.  Throws on error/failure.
std::vector<unsigned char> decrypt_push_notification(
        std::span<const unsigned char> payload, std::span<const unsigned char, 32> enc_key);

/// API: crypto/encrypt_xchacha20
///
/// Encrypts a value with a given key using xchacha20.
///
/// Inputs:
/// - `plaintext` -- the data to encrypt.
/// - `key` -- the 32-byte symmetric key.
///
/// Outputs:
/// - `std::vector<unsigned char>` -- the resulting ciphertext.
std::vector<unsigned char> encrypt_xchacha20(
        std::span<const unsigned char> plaintext, std::span<const unsigned char, 32> key);

/// API: crypto/decrypt_xchacha20
///
/// Decrypts a value that was encrypted with the `encrypt_xchacha20` function.
///
/// Inputs:
/// - `ciphertext` -- the data to decrypt.
/// - `key` -- the 32-byte symmetric key.
///
/// Outputs:
/// - `std::vector<unsigned char>` -- the resulting plaintext.
std::vector<unsigned char> decrypt_xchacha20(
        std::span<const unsigned char> ciphertext, std::span<const unsigned char, 32> key);

}  // namespace session
