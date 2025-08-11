#include <stdint.h>

#include "config/namespaces.h"
#include "config/pro.h"
#include "export.h"
#include "types.h"

struct config_group_keys;

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRO_10K_CHARACTER_LIMIT = 10'000,
};

typedef uint64_t PRO_EXTRA_FEATURES;
enum PRO_EXTRA_FEATURES_ {
    PRO_EXTRA_FEATURES_NIL = 0,
    PRO_EXTRA_FEATURES_PRO_BADGE = 0 << 1,
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
    PRO_STATUS_NIL,      // Pro proof was not set
    PRO_STATUS_INVALID,  // Pro proof was set; signature validation failed
    PRO_STATUS_VALID,    // Pro proof was set, is verified; has not expired
    PRO_STATUS_EXPIRED,  // Pro proof was set, is verified; has expired
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

    // Signature over the plaintext with the user's Session Pro rotating public key if they have
    // Session Pro and opt into sending a message with pro features. If this is specified, the pro
    // message component in `Content` must have been set with the corresponding proof for this
    // signature.
    uint8_t pro_sig[64];
    bool has_pro_sig;

    // Set to the recipient of the message if it requires one. Ignored otherwise (for example
    // ignored in OpenGroup)
    uint8_t recipient_pubkey[32];

    // The timestamp to assign to the message envelope if the message requires one. Ignored
    // otherwise
    uint64_t sent_timestamp_ms;

    // When type => OpenGroupInbox: set this pubkey to the server's key
    uint8_t open_group_inbox_server_pubkey[32];

    // When type => ClosedGroup: set the following 'closed_group' prefixed fields
    uint8_t closed_group_pubkey[33];
    const config_group_keys* closed_group_keys;

    // Set to the closed group's swarm public key (needed for Android) for a non 0x03 prefixed
    // `closed_group_pubkey`. Ignored otherwise. This will be set as the envelope source. See:
    // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L469
    uint8_t closed_group_swarm_public_key[33];
    bool has_closed_group_swarm_public_key;
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
    uint64_t timestamp;

    /// Optional fields. These fields are set if the appropriate flag has been set in `flags`
    /// otherwise the corresponding values are to be ignored and those fields will be
    /// zero-initialised.
    uint8_t source[33];
    uint32_t source_device;
    uint64_t server_timestamp;
    uint8_t pro_sig[64];
};

struct session_protocol_decrypted_envelope {
    bool success;

    // The envelope parsed from the plaintext
    session_protocol_envelope envelope;

    // Decrypted envelope content into plaintext
    span_u8 content_plaintext;

    // Sender public key extracted from the encrypted content payload
    uint8_t sender_ed25519_pubkey[32];

    // Status flag for validity of the Session Pro proof embedded in the envelope if it has one.
    // The status is set to `Nil` if there is no Session Pro proof in the message. Otherwise it's
    // set to one of the other values to which the remaining pro fields will be populated with data
    // parsed from the envelope.
    PRO_STATUS pro_status;

    // The embedded Session Pro proof, only set if the status was not `Nil`.
    pro_proof pro_proof;

    // Session Pro features that were used in the embedded message, only set if the status was not
    // `Nil`.
    PRO_FEATURES pro_features;
};

struct session_protocol_encrypted_for_destination {
    bool success;

    // Indicates if the ciphertext was encrypted or not. This can be false if the message sent to
    // the destination and namespace does not require encryption. In this case `ciphertext` is not
    // set and the user should proceed with the original plaintext.
    bool encrypted;

    // The plaintext encrypted in a manner suitable for the desired destination and namespace. This
    // is not set if `encrypted` is false.
    span_u8 ciphertext;
};

LIBSESSION_EXPORT
PRO_FEATURES session_protocol_get_pro_features_for_msg(const span_u8 msg, PRO_FEATURES flags);

LIBSESSION_EXPORT
session_protocol_encrypted_for_destination session_protocol_encrypt_for_destination(
        const span_u8 plaintext,
        const span_u8 ed25519_privkey,
        const session_protocol_destination* dest,
        NAMESPACE space);

LIBSESSION_EXPORT
session_protocol_decrypted_envelope session_protocol_decrypt_envelope(
        const span_u8 ed25519_privkey, const span_u8 envelope_plaintext, uint64_t unix_ts);

#ifdef __cplusplus
}
#endif
