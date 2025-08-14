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
    /// Number of characters that a standard message can use. If the message exceeds this then the
    /// message must activate the higher character limit feature provided by Session Pro which
    /// allows messages up to 10k characters.
    PRO_STANDARD_CHARACTER_LIMIT = 2'000,
};

typedef uint64_t PRO_EXTRA_FEATURES;
enum PRO_EXTRA_FEATURES_ {
    PRO_EXTRA_FEATURES_NIL = 0,
    PRO_EXTRA_FEATURES_PRO_BADGE = 1 << 0,
    PRO_EXTRA_FEATURES_ANIMATED_AVATAR = 1 << 1,
};

typedef uint64_t PRO_FEATURES;
enum PRO_FEATURES_ {
    PRO_FEATURES_NIL = 0,
    PRO_FEATURES_10K_CHARACTER_LIMIT = 1 << 0,
    PRO_FEATURES_PRO_BADGE = 1 << 1,
    PRO_FEATURES_ANIMATED_AVATAR = 1 << 2,
    PRO_FEATURES_ALL =
            PRO_FEATURES_10K_CHARACTER_LIMIT | PRO_FEATURES_PRO_BADGE | PRO_FEATURES_ANIMATED_AVATAR
};

enum PRO_STATUS {
    PRO_STATUS_NIL,
    PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    PRO_STATUS_INVALID_USER_SIG,
    PRO_STATUS_VALID,
    PRO_STATUS_EXPIRED,
};

enum DESTINATION_TYPE {
    DESTINATION_TYPE_CONTACT,
    DESTINATION_TYPE_SYNC_MESSAGE,
    DESTINATION_TYPE_CLOSED_GROUP,
    DESTINATION_TYPE_OPEN_GROUP,
    DESTINATION_TYPE_OPEN_GROUP_INBOX,
};

struct session_protocol_destination {
    DESTINATION_TYPE type;

    // The pro signature is optional, set this flag to true to make the encryption function take
    // into account the signature or otherwise the signature is ignored.
    bool has_pro_sig;
    uint8_t pro_sig[64];
    uint8_t recipient_pubkey[33];
    uint64_t sent_timestamp_ms;
    uint8_t open_group_inbox_server_pubkey[32];
    uint8_t closed_group_pubkey[33];
    const config_group_keys* closed_group_keys;
};

enum ENVELOPE_TYPE {
    ENVELOPE_TYPE_SESSION_MESSAGE,
    ENVELOPE_TYPE_CLOSED_GROUP_MESSGE,
};

typedef uint32_t ENVELOPE_FLAGS;
enum ENVELOPE_FLAGS_ {
    ENVELOPE_FLAGS_SOURCE = 1 << 0,
    ENVELOPE_FLAGS_SOURCE_DEVICE = 1 << 1,
    ENVELOPE_FLAGS_SERVER_TIMESTAMP = 1 << 2,
    ENVELOPE_FLAGS_PRO_SIG = 1 << 3,
};

struct session_protocol_envelope {
    ENVELOPE_FLAGS flags;
    ENVELOPE_TYPE type;
    uint64_t timestamp_ms;
    uint8_t source[33];
    uint32_t source_device;
    uint64_t server_timestamp;
    uint8_t pro_sig[64];
};

struct session_protocol_decrypt_envelope_keys {
    // Indicate to the envelope decrypting function that it should use the group keys to decrypt the
    // envelope (e.g.: for groups v2 envelopes where the envelope is encrypted and the body
    // unencrypted). The `group_keys` must be set if this flag is true. The recipient ed25519
    // private key field is ignored if this flag is set.
    bool use_group_keys;

    // Keys to use to decrypt the envelope.
    const config_group_keys* group_keys;

    // The libsodium-style secret key of the sender, 64 bytes. Can also be passed as a 32-byte seed.
    // Used to decrypt the encrypted content. This field is used if `use_group_keys` is false in
    // which case the group keys are ignored. This is for envelopes where the envelope itself is
    // unencrypted and the contents is encrypted for this secret key.
    std::span<const uint8_t> recipient_ed25519_privkey;
};

struct session_protocol_decrypted_envelope {
    // Indicates if the decryption was successful. If the decryption step failed and threw an
    // exception, this is false.
    bool success;
    session_protocol_envelope envelope;
    span_u8 content_plaintext;
    uint8_t sender_ed25519_pubkey[32];
    PRO_STATUS pro_status;
    pro_proof pro_proof;
    PRO_FEATURES pro_features;
};

struct session_protocol_encrypted_for_destination {
    // Indicates if the decryption was successful. If the decryption step failed and threw an
    // exception, this is false.
    bool success;
    bool encrypted;
    span_u8 ciphertext;
};

/// API: session_protocol/session_protocol_get_pro_features_for_msg
///
/// Determine the Pro features that are used in a given conversation message.
///
/// Inputs:
/// - `msg` -- the conversation message to determine if the message is requires access to the 10k
///   character limit available in Session Pro
/// - `flags` -- extra pro features that are known by clients that they wish to be activated on
///   this message
///
/// Outputs:
/// - Session Pro feature flags suitable for writing directly into the protobuf `ProMessage` in
///   `Content`
LIBSESSION_EXPORT
PRO_FEATURES session_protocol_get_pro_features_for_msg(size_t msg_size, PRO_FEATURES flags);

/// API: session_protocol/session_protocol_encrypt_for_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// See: session_protocol/encrypt_for_destination for more information
///
/// Inputs:
/// - `plaintext` -- the protobuf serialised payload containing the protobuf encoded stream,
///   `Content`. It must not be already be encrypted.
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes. Can also be
///   passed as a 32-byte seed. Used to encrypt the plaintext.
/// - `dest` -- the extra metadata indicating the destination of the message and the necessary data
///   to encrypt a message for that destination.
/// - `space` -- the namespace to encrypt the message for
///
/// Outputs:
/// - The encryption result for the plaintext. If the destination and namespace combination did not
///   require encryption, no payload is returned in the ciphertext and the user should proceed with
///   the plaintext. This should be validated by checking the `encrypted` flag on the result.
///
///   The retured payload is suitable for sending on the wire (i.e: it has been protobuf
///   encoded/wrapped if necessary).
///
///   The success flag is set if encryption was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false.
LIBSESSION_EXPORT
session_protocol_encrypted_for_destination session_protocol_encrypt_for_destination(
        const span_u8 plaintext,
        const span_u8 ed25519_privkey,
        const session_protocol_destination* dest,
        NAMESPACE space);

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
///   issuer
///
/// Outputs:
/// - The decrypted envelope. It contains the fields of the envelope and the Session Pro metadata
///   within the envelope if there were any.
///
///   The success flag is set if encryption was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false.
LIBSESSION_EXPORT
session_protocol_decrypted_envelope session_protocol_decrypt_envelope(
        const session_protocol_decrypt_envelope_keys* keys,
        const span_u8 envelope_payload,
        uint64_t unix_ts,
        const span_u8 pro_backend_pubkey);

#ifdef __cplusplus
}
#endif
