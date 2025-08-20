#include <stdint.h>

#include "config/namespaces.h"
#include "config/pro.h"
#include "export.h"
#include "types.h"

/// The C header for session_protocol. See the CPP header for more indepth comments. Only the
/// differences between the C and CPP headers are documented to avoid duplication.

struct config_group_keys;

#ifdef __cplusplus
extern "C" {
#endif

enum {
    /// TODO: This comment needs to be updated to be _codepoints_ once libsession implements the
    /// character count for the platforms. Currently they use code units but it should be
    /// codepoints. This allows the platforms to use their native text representation up until the
    /// API boundary where they will convert to UTF8 to have it managed by libsession.

    /// Maximum number of UTF16 code units that a standard message can use. If the message exceeds
    /// this then the message must activate the higher character limit feature provided by Session
    /// Pro which allows messages up to 10k characters.
    PRO_STANDARD_CHARACTER_LIMIT = 2'000,

    /// Maximum number of UTF16 code units that a Session Pro entitled user can send in a message.
    /// This is not used in the codebase, but is provided for convenience to centralise protocol
    /// definitions for users of the library to consume.
    PRO_HIGHER_CHARACTER_LIMIT = 10'000,
};

// Bit flags for features that are not currently able to be determined by the state stored in
// Libsession. They are to be passed in by the client into `get_pro_msg_for_features` to return the
// bitset of `PRO_FEATURES` that a message will use.
typedef uint64_t PRO_EXTRA_FEATURES;
enum PRO_EXTRA_FEATURES_ {
    PRO_EXTRA_FEATURES_NIL = 0,
    PRO_EXTRA_FEATURES_PRO_BADGE = 1 << 0,
    PRO_EXTRA_FEATURES_ANIMATED_AVATAR = 1 << 1,
};

// Bitset of Session Pro features that a message uses. This bitset is stored in the protobuf
// `Content.proMessage` when a message is sent for other clients to consume.
typedef uint64_t PRO_FEATURES;
enum PRO_FEATURES_ {
    PRO_FEATURES_NIL = 0,
    PRO_FEATURES_10K_CHARACTER_LIMIT = 1 << 0,
    PRO_FEATURES_PRO_BADGE = 1 << 1,
    PRO_FEATURES_ANIMATED_AVATAR = 1 << 2,
    PRO_FEATURES_ALL =
            PRO_FEATURES_10K_CHARACTER_LIMIT | PRO_FEATURES_PRO_BADGE | PRO_FEATURES_ANIMATED_AVATAR
};

typedef enum PRO_STATUS {  // See session::ProStatus
    PRO_STATUS_NIL,
    PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    PRO_STATUS_INVALID_USER_SIG,
    PRO_STATUS_VALID,
    PRO_STATUS_EXPIRED,
} PRO_STATUS;

typedef enum DESTINATION_TYPE {  // See session::DestinationType
    DESTINATION_TYPE_CONTACT,
    DESTINATION_TYPE_SYNC_MESSAGE,
    DESTINATION_TYPE_GROUP,
    DESTINATION_TYPE_COMMUNITY,
    DESTINATION_TYPE_COMMUNITY_INBOX,
} DESTINATION_TYPE;

typedef struct session_protocol_destination {  // See session::Destination
    DESTINATION_TYPE type;

    // The pro signature is optional, set this flag to true to make the encryption function take
    // into account the signature or otherwise the signature is ignored.
    bool has_pro_sig;
    uint8_t pro_sig[64];
    uint8_t recipient_pubkey[33];
    uint64_t sent_timestamp_ms;
    uint8_t community_inbox_server_pubkey[32];
    uint8_t group_ed25519_pubkey[33];
    uint8_t group_ed25519_privkey[32];
} session_protocol_destination;

// Indicates which optional fields in the envelope has been populated out of the optional fields in
// an envelope after it has been parsed off the wire.
typedef uint32_t ENVELOPE_FLAGS;
enum ENVELOPE_FLAGS_ {
    ENVELOPE_FLAGS_SOURCE = 1 << 0,
    ENVELOPE_FLAGS_SOURCE_DEVICE = 1 << 1,
    ENVELOPE_FLAGS_SERVER_TIMESTAMP = 1 << 2,
    ENVELOPE_FLAGS_PRO_SIG = 1 << 3,
};

typedef struct session_protocol_envelope {
    ENVELOPE_FLAGS flags;
    uint64_t timestamp_ms;
    uint8_t source[33];
    uint32_t source_device;
    uint64_t server_timestamp;
    uint8_t pro_sig[64];
} session_protocol_envelope;

typedef struct session_protocol_decrypt_envelope_keys {
    span_u8 group_ed25519_pubkey;
    const span_u8* ed25519_privkeys;
    size_t ed25519_privkeys_len;
} session_protocol_decrypt_envelope_keys;

typedef struct session_protocol_decrypted_envelope {
    // Indicates if the decryption was successful. If the decryption step failed and threw an
    // exception, this is false.
    bool success;
    session_protocol_envelope envelope;
    span_u8 content_plaintext;
    uint8_t sender_ed25519_pubkey[32];
    uint8_t sender_x25519_pubkey[32];
    PRO_STATUS pro_status;
    pro_proof pro_proof;
    PRO_FEATURES pro_features;
    size_t error_len_incl_null_terminator;
} session_protocol_decrypted_envelope;

typedef struct session_protocol_encrypted_for_destination {
    // Indicates if the encryption was successful. If any step failed and threw an exception, this
    // is false.
    bool success;
    bool encrypted;
    span_u8 ciphertext;
    size_t error_len_incl_null_terminator;
} session_protocol_encrypted_for_destination;

/// API: session_protocol/session_protocol_get_pro_features_for_msg
///
/// Determine the Pro features that are used in a given conversation message.
///
/// Inputs:
/// - `msg_size` -- the size of the message in bytes to determine if the message requires access to
///   the higher character limit available in Session Pro
/// - `flags` -- extra pro features that are known by clients that they wish to be activated on
///   this message
///
/// Outputs:
/// - Session Pro feature flags suitable for writing directly into the protobuf `ProMessage` in
///   `Content`
LIBSESSION_EXPORT
PRO_FEATURES session_protocol_get_pro_features_for_msg(size_t msg_size, PRO_EXTRA_FEATURES flags);

/// API: session_protocol/session_protocol_encrypt_for_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// See: session_protocol/encrypt_for_destination for more information
///
/// The encryption result must be freed with `session_protocol_encrypt_for_destination_free` when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- the protobuf serialised payload containing the protobuf encoded stream,
///   `Content`. It must not be already be encrypted.
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes. Can also be
///   passed as a 32-byte seed. Used to encrypt the plaintext.
/// - `dest` -- the extra metadata indicating the destination of the message and the necessary data
///   to encrypt a message for that destination.
/// - `space` -- the namespace to encrypt the message for
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned `success` was false, untouched otherwise. If this is set to `NULL`, then on failure,
///   the returned `error_len_incl_null_terminator` is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that `error` is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   `error` is NULL. This function will fill the buffer up to `error_len - 1` characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encryption was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `encrypted` -- True if any encryption was performed. If the combination of the namespace and
///   destination does not require encryption, this flag is false. In this case, `ciphertext` will
///   not be assigned. The caller should proceed with the `plaintext` they initially passed in.
/// - `ciphertext` -- Encryption result for the plaintext. If the destination and namespace
///   combination did not require encryption, no payload is returned in the ciphertext and the user
///   should proceed with the plaintext. This should be validated by checking the `encrypted` flag
///   on the result to determine if the ciphertext or plaintext is to be used.
///
///   The retured payload is suitable for sending on the wire (i.e: it has been protobuf
///   encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length, including the null-terminator in order for the error message
///   to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encrypted_for_destination session_protocol_encrypt_for_destination(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const session_protocol_destination* dest,
        NAMESPACE space,
        char* error,
        size_t error_len);

/// API: session_protocol/session_protocol_encrypt_for_destination_free
///
/// Free the encryption result for a destination produced by
/// `session_protocol_encrypt_for_destination`. It is safe to pass a `NULL` or any result returned
/// by the encrypt function irrespective of if the function succeeded or failed.
///
/// Inputs:
/// - `encrypt` -- Encryption result to free. This object is zeroed out on free and should no longer
///   be used after it is freed.
LIBSESSION_EXPORT void session_protocol_encrypt_for_destination_free(
        session_protocol_encrypted_for_destination* encrypt);

/// API: session_protocol/session_protocol_decrypt_envelope
///
/// Given an envelope payload (i.e.: protobuf encoded stream of `Envelope` or encrypted `Envelope`
/// using a Groups v2 key) parse (or decrypt) the envelope and return the envelope content decrypted
/// if necessary.
///
/// A groups v2 envelope will get decrypted with the group keys. A non-groups v2 envelope will get
/// decrypted with the specified Ed25519 private key in the `keys` object. Only one of these keys
/// need to be set depending on the type of envelope payload passed into the function.
///
/// See: session_protocol/decrypt_envelope for more information
///
/// The encryption result must be freed with `session_protocol_decrypt_envelope_free` when the
/// caller is done with the result.
///
/// Inputs:
/// - `keys` -- the keys to decrypt either the envelope or the envelope contents. Groups v2
///   envelopes where the envelope is encrypted must set the group key. Envelopes with an encrypted
///   content must set the the libsodium-style secret key of the receiver, 64 bytes. Can also be
///   passed as a 32-byte seed.
///
///   If a group decryption key is specified, the recipient key is ignored and vice versa. Only one
///   of the keys should be set depending on the type of envelope.
///
/// - `envelope_payload` -- the envelope payload either encrypted (groups v2 style) or unencrypted
///   (1o1 or legacy groups).
/// - `unix_ts` -- pass in the current system time in seconds which is used to determine, whether or
///   not the Session Pro proof has expired or not if it is in the payload. Ignored if there's no
///   proof in the message.
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer. Ignored if there's no proof in the message.
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned `success` was false, untouched otherwise. If this is set to `NULL`, then on failure,
///   the returned `error_len_incl_null_terminator` is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that `error` is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   `error` is NULL. This function will fill the buffer up to `error_len - 1` characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encryption was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   in the result are to be ignored on failure.
/// - `envelope` -- Envelope structure that was decrypted/parsed from the `envelope_plaintext`
/// - `content_plaintext` -- Decrypted contents of the envelope structure. This is the protobuf
///   encoded stream that can be parsed into a protobuf `Content` structure.
///
///   The plaintext must be freed by the CRT's `free` after the caller is done with the memory.
/// - `sender_ed25519_pubkey` -- The sender's ed25519 public key embedded in the encrypted payload.
///   This is only set for session message envelopes. Groups envelopes only embed the sender's
///   x25519 public key in which case this field is set to the zero public key.
/// - `sender_x25519_pubkey` -- The sender's x25519 public key. It's always set on successful
///   decryption either by extracting the key from the encrypted groups envelope, or, by deriving
///   the x25519 key from the sender's ed25519 key in the case of a session message envelope.
/// - `pro_status` -- The pro status associated with the envelope, if any, that the sender has
///   embedded into the envelope being parsed. This field is set to nil if there was no pro metadata
///   associated with the envelope.
///
///   This field should be used to determine the presence of pro and whether or not the caller
///   can respect the contents of the pro proof and features. A valid pro proof that can be used
///   effectively after parsing is indicated by this value being set to the Valid enum.
/// - `pro_proof` -- The pro proof in the envelope. This field is set to all zeros if `pro_status`
///   was nil, otherwise it's populated with proof data.
/// - `pro_features` -- Pro features that were activated in this envelope by the sender. This field
///   is only set if `pro_status` is not nil. It should only be enforced if the `pro_status` was
///   the Valid enum.
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length, including the null-terminator in order for the error message
///   to be preserved in full.
LIBSESSION_EXPORT
session_protocol_decrypted_envelope session_protocol_decrypt_envelope(
        const session_protocol_decrypt_envelope_keys* keys,
        const void* envelope_plaintext,
        size_t envelope_plaintext_len,
        uint64_t unix_ts,
        const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        char* error,
        size_t error_len);

/// API: session_protocol/session_protocol_decrypt_envelope_free
///
/// Free the decryption result produced by `session_protocol_decrypt_envelope`. It is safe to pass a
/// `NULL` or any result returned by the decrypt function irrespective of if the function succeeded
/// or failed.
///
/// Inputs:
/// - `envelope` -- Decryption result to free. This object is zeroed out on free and should no
/// longer
///   be used after it is freed.
LIBSESSION_EXPORT void session_protocol_decrypt_envelope_free(
        session_protocol_decrypted_envelope* envelope);

#ifdef __cplusplus
}
#endif
