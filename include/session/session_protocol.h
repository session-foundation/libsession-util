#pragma once

#include <stdint.h>

#include "export.h"
#include "types.h"

/// The C header for session_protocol. See the CPP header for more indepth comments. Only the
/// differences between the C and CPP headers are documented to avoid duplication.

#ifdef __cplusplus
extern "C" {
#endif

enum {
    /// Maximum number of UTF16 code points that a standard message can use. If the message exceeds
    /// this then the message must activate the higher character limit feature provided by Session
    /// Pro which allows messages up to 10k characters.
    SESSION_PROTOCOL_PRO_STANDARD_CHARACTER_LIMIT = 2000,

    /// Maximum number of UTF16 code points that a Session Pro entitled user can send in a message.
    /// This is not used in the codebase, but is provided for convenience to centralise protocol
    /// definitions for users of the library to consume.
    SESSION_PROTOCOL_PRO_HIGHER_CHARACTER_LIMIT = 10000,

    /// Amount of conversations that a user without Session Pro can pin
    SESSION_PROTOCOL_PRO_STANDARD_PINNED_CONVERSATION_LIMIT = 5,

    /// Amount of bytes that a community or 1o1 message `Content` must be padded by before wrapping
    /// in an envelope.
    SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING = 160,
};

// clang-format off
/// Session Pro personalisation bytes for hashing. Must match
///  https://github.com/Doy-lee/session-pro-backend/blob/fca5e10c9c5014d394cf15934cd2af8e911607b9/backend.py#L21
///  https://github.com/Doy-lee/session-pro-backend/blob/fca5e10c9c5014d394cf15934cd2af8e911607b9/server.py#L571
static const char SESSION_PROTOCOL_GENERATE_PROOF_HASH_PERSONALISATION[]               = "ProGenerateProof";
static const char SESSION_PROTOCOL_BUILD_PROOF_HASH_PERSONALISATION[]                  = "ProProof________";
static const char SESSION_PROTOCOL_ADD_PRO_PAYMENT_HASH_PERSONALISATION[]              = "ProAddPayment___";
static const char SESSION_PROTOCOL_SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION[] = "ProSetRefundReq_";
static const char SESSION_PROTOCOL_GET_PRO_DETAILS_HASH_PERSONALISATION[]              = "ProGetProDetReq_";
// clang-format on

/// Bundle of hard-coded strings that an implementing application may use for various scenarios.
typedef struct session_protocol_strings session_protocol_strings;
struct session_protocol_strings {
    string8 build_variant_apk;
    string8 build_variant_fdroid;
    string8 build_variant_huawei;
    string8 build_variant_ipa;
    string8 url_donations;
    string8 url_donations_app;
    string8 url_download;
    string8 url_faq;
    string8 url_feedback;
    string8 url_network;
    string8 url_privacy_policy;
    string8 url_pro_access_not_found;
    string8 url_pro_faq;
    string8 url_pro_page;
    string8 url_pro_privacy_policy;
    string8 url_pro_roadmap;
    string8 url_pro_support;
    string8 url_pro_terms_of_service;
    string8 url_pro_upgrade;
    string8 url_staking;
    string8 url_support;
    string8 url_survey;
    string8 url_terms_of_service;
    string8 url_token;
    string8 url_translate;
};
extern const session_protocol_strings SESSION_PROTOCOL_STRINGS;

typedef enum SESSION_PROTOCOL_PRO_STATUS {  // See session::ProStatus
    SESSION_PROTOCOL_PRO_STATUS_NIL,
    SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    SESSION_PROTOCOL_PRO_STATUS_INVALID_USER_SIG,
    SESSION_PROTOCOL_PRO_STATUS_VALID,
    SESSION_PROTOCOL_PRO_STATUS_EXPIRED,
} SESSION_PROTOCOL_PRO_STATUS;

typedef struct session_protocol_pro_signed_message session_protocol_pro_signed_message;
struct session_protocol_pro_signed_message {
    span_u8 sig;
    span_u8 msg;
};

typedef struct session_protocol_pro_proof session_protocol_pro_proof;
struct session_protocol_pro_proof {
    uint8_t version;
    bytes32 gen_index_hash;
    bytes32 rotating_pubkey;
    uint64_t expiry_unix_ts_ms;
    bytes64 sig;
};

// Feature flags for profile features where each enum value indicates the bit position in the
// corresponding bitset, e.g. (1 << ENUM_VAL)
typedef enum SESSION_PROTOCOL_PRO_PROFILE_FEATURES {
    SESSION_PROTOCOL_PRO_PROFILE_FEATURES_PRO_BADGE,
    SESSION_PROTOCOL_PRO_PROFILE_FEATURES_ANIMATED_AVATAR,
    SESSION_PROTOCOL_PRO_PROFILE_FEATURES_COUNT,
} SESSION_PROTOCOL_PRO_PROFILE_FEATURES;

// Strongly typed bitset for profile features. Each profile enum value corresponds to the bit
// position to set on the bitset (e.g. 1 << ENUM_VALUE). This bitset is wrapped in a struct and has
// helper functions (`session_protocol_pro_profile_bitset_*` family of functions) that accepts the
// typed-enum to mitigate against mixing up the profile features with the message features.
//
// The enums are kept as bit positions (ENUM_VAL = 1 << N) instead of bit values (ENUM_VAL = 1)
// for ergonomic usage in the way we sync and store these bitsets on the protocol swarms. These
// bitsets are stored as sets which allows us to do diffs and deltas on the set of values. The
// syncing scheme does not allow bit-level deltas which makes handling conflicts between competing
// synced configurations, awkward.
typedef struct session_protocol_pro_profile_bitset session_protocol_pro_profile_bitset;
struct session_protocol_pro_profile_bitset {
    uint64_t data;
};

// Feature flags for message features where each enum value indicates the bit position in the
// corresponding bitset.
typedef enum SESSION_PROTOCOL_PRO_MESSAGE_FEATURES {
    SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT,
} SESSION_PROTOCOL_PRO_MESSAGE_FEATURES;

// Strongly typed bitset for Session Pro message features (see
// `session_protocol_pro_profile_bitset`)
typedef struct session_protocol_pro_message_bitset session_protocol_pro_message_bitset;
struct session_protocol_pro_message_bitset {
    uint64_t data;
};

typedef enum SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS {  // See session::ProFeaturesForMsgStatus
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS,
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_UTF_DECODING_ERROR,
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_EXCEEDS_CHARACTER_LIMIT,
} SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS;

typedef enum SESSION_PROTOCOL_DESTINATION_TYPE {  // See session::DestinationType
    SESSION_PROTOCOL_DESTINATION_TYPE_SYNC_OR_1O1,
    SESSION_PROTOCOL_DESTINATION_TYPE_GROUP,
    SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY_INBOX,
    SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY,
} SESSION_PROTOCOL_DESTINATION_TYPE;

typedef struct session_protocol_destination session_protocol_destination;
struct session_protocol_destination {  // See session::Destination
    SESSION_PROTOCOL_DESTINATION_TYPE type;
    const void* pro_rotating_ed25519_privkey;
    size_t pro_rotating_ed25519_privkey_len;
    bytes33 recipient_pubkey;
    uint64_t sent_timestamp_ms;
    bytes32 community_inbox_server_pubkey;
    bytes33 group_ed25519_pubkey;
    bytes32 group_enc_key;
};

// Indicates which optional fields in the envelope has been populated out of the optional fields in
// an envelope after it has been parsed off the wire.
typedef uint32_t SESSION_PROTOCOL_ENVELOPE_FLAGS;
enum ENVELOPE_FLAGS_ {
    SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE = 1 << 0,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE_DEVICE = 1 << 1,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_SERVER_TIMESTAMP = 1 << 2,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG = 1 << 3,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_TIMESTAMP = 1 << 4,
};

typedef struct session_protocol_envelope session_protocol_envelope;
struct session_protocol_envelope {
    SESSION_PROTOCOL_ENVELOPE_FLAGS flags;
    uint64_t timestamp_ms;
    bytes33 source;
    uint32_t source_device;
    uint64_t server_timestamp;
    bytes64 pro_sig;
};

typedef struct session_protocol_decode_envelope_keys session_protocol_decode_envelope_keys;
struct session_protocol_decode_envelope_keys {
    span_u8 group_ed25519_pubkey;
    const span_u8* decrypt_keys;
    size_t decrypt_keys_len;
};

typedef struct session_protocol_decoded_pro session_protocol_decoded_pro;
struct session_protocol_decoded_pro {
    SESSION_PROTOCOL_PRO_STATUS status;
    session_protocol_pro_proof proof;
    session_protocol_pro_message_bitset msg_bitset;
    session_protocol_pro_profile_bitset profile_bitset;
};

typedef struct session_protocol_decoded_envelope session_protocol_decoded_envelope;
struct session_protocol_decoded_envelope {
    // Indicates if the decryption was successful. If the decryption step failed and threw an
    // exception, this is false.
    bool success;
    session_protocol_envelope envelope;
    span_u8 content_plaintext;
    bytes32 sender_ed25519_pubkey;
    bytes32 sender_x25519_pubkey;
    session_protocol_decoded_pro pro;
    size_t error_len_incl_null_terminator;
};

typedef struct session_protocol_encoded_for_destination session_protocol_encoded_for_destination;
struct session_protocol_encoded_for_destination {
    // Indicates if the encryption was successful. If any step failed and threw an exception, this
    // is false.
    bool success;
    span_u8 ciphertext;
    size_t error_len_incl_null_terminator;
};

typedef struct session_protocol_decoded_community_message
        session_protocol_decoded_community_message;
struct session_protocol_decoded_community_message {
    bool success;
    bool has_envelope;
    session_protocol_envelope envelope;
    span_u8 content_plaintext;
    bool has_pro;
    bytes64 pro_sig;
    session_protocol_decoded_pro pro;
    size_t error_len_incl_null_terminator;
};

/// API: session_protocol/session_protocol_pro_profile_bitset_is_set
///
/// Check if the feature flag is set on the bitset
LIBSESSION_EXPORT bool session_protocol_pro_profile_bitset_is_set(
        session_protocol_pro_profile_bitset value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_set
///
/// Set the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_profile_bitset_set(
        session_protocol_pro_profile_bitset* value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_unset
///
/// Unset the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_profile_bitset_unset(
        session_protocol_pro_profile_bitset* value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_is_set
///
/// Check if the feature flag is set on the bitset
LIBSESSION_EXPORT bool session_protocol_pro_message_bitset_is_set(
        session_protocol_pro_message_bitset value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_set
///
/// Set the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_message_bitset_set(
        session_protocol_pro_message_bitset* value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_unset
///
/// Unset the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_message_bitset_unset(
        session_protocol_pro_message_bitset* value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);

/// API: session_protocol/session_protocol_pro_proof_hash
///
/// Generate the 32 byte hash that is to be signed by the rotating key or Session Pro Backend key to
/// embed in the envelope or proof respectively which other clients use to authenticate the validity
/// of a proof.
///
/// Inputs:
/// - `proof` -- Proof to calculate the hash from
///
/// Outputs:
/// - `bytes32` -- The 32 byte hash calculated from the proof
LIBSESSION_EXPORT bytes32 session_protocol_pro_proof_hash(session_protocol_pro_proof const* proof)
        NON_NULL_ARG(1);

/// API: session_protocol/session_protocol_pro_proof_verify_signature
///
/// Verify the proof was signed by the `verify_pubkey`
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- Array of bytes containing the public key to (typically the Session Pro
///   Backend public key) verify the proof against.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` this must be 32 bytes, but is
///   parameterised to detect errors about incorrectly sized arrays by the caller.
///
/// Outputs:
/// - `bool` -- True if verified, false otherwise
LIBSESSION_EXPORT bool session_protocol_pro_proof_verify_signature(
        session_protocol_pro_proof const* proof,
        uint8_t const* verify_pubkey,
        size_t verify_pubkey_len) NON_NULL_ARG(1, 2);

/// API: session_protocol/session_protocol_pro_proof_verify_message
///
/// Check if the `rotating_pubkey` in the proof was the signatory of the message and signature
/// passed in. This function throws if an signature is passed in that isn't 64 bytes.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `sig` -- Signature to verify with the `rotating_pubkey`. The signature should have
///   originally been signed over `msg` passed in.
/// - `sig_len` -- Length of the signature, should be 64 bytes
/// - `msg` -- Message that the signature signed over with. It will be verified using the
///   embedded `rotating_pubkey`.
/// - `msg_len` -- Length of the message
///
/// Outputs:
/// - `bool` -- True if verified, false otherwise (bad signature, or, invalid arguments).
LIBSESSION_EXPORT bool session_protocol_pro_proof_verify_message(
        session_protocol_pro_proof const* proof,
        uint8_t const* sig,
        size_t sig_len,
        uint8_t const* msg,
        size_t msg_len) NON_NULL_ARG(1, 2, 4);

/// API: session_protocol/session_protocol_pro_proof_is_active
///
/// Check if the Pro proof is currently entitled to Pro given the `unix_ts_ms` with respect to the
/// proof's `expiry_unix_ts`
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `unix_ts_ms` -- The unix timestamp to check the proof expiry time against
///
/// Outputs:
/// - `bool` -- True if expired, false otherwise
LIBSESSION_EXPORT bool session_protocol_pro_proof_is_active(
        session_protocol_pro_proof const* proof, uint64_t unix_ts_ms) NON_NULL_ARG(1);

/// API: session_protocol/session_protocol_pro_proof_status
///
/// Evaluate the status of the pro proof by checking it is signed by the `verify_pubkey`, it has
/// not expired via `unix_ts_ms` and optionally verify that the `signed_msg` was signed by the
/// `rotating_pubkey` embedded in the proof.
///
/// Internally this function calls `pro_proof_verify_signature`, `pro_proof_verify_message` and
/// optionally `pro_proof_is_active` in sequence. This function fails if an invalidly sized public
/// key or signature are passed in. They must be 32 and 64 bytes respectively, the appropriate
/// invalid status will be returned.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
///   they are the original signatory of the proof.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` should be 32 bytes
///   they are the original signatory of the proof.
/// - `unix_ts_ms` -- Unix timestamp to compared against the embedded `expiry_unix_ts`
///   to determine if the proof has expired or not
/// - `signed_msg` -- Optionally set the payload to the message with the signature to verify if
///   the embedded `rotating_pubkey` in the proof signed the given message.
///
/// Outputs:
/// - `status` - The derived status given the components of the message. If `signed_msg` is
///   not set then this function can never return `PRO_STATUS_INVALID_USER_SIG` from the set of
///   possible enum values. Otherwise this funtion can return all possible values.
LIBSESSION_EXPORT SESSION_PROTOCOL_PRO_STATUS session_protocol_pro_proof_status(
        session_protocol_pro_proof const* proof,
        const uint8_t* verify_pubkey,
        size_t verify_pubkey_len,
        uint64_t unix_ts_ms,
        OPTIONAL const session_protocol_pro_signed_message* signed_msg) NON_NULL_ARG(1, 2);

/// API: session_protocol/session_protocol_get_pro_features_for_msg
typedef struct session_protocol_pro_features_for_msg {
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS status;
    string8 error;
    session_protocol_pro_message_bitset bitset;
    size_t codepoint_count;
} session_protocol_pro_features_for_msg;

/// API: session_protocol/session_protocol_get_pro_features_for_utf8
///
/// Determine the Pro features that are used in a given UTF8 message.
///
/// Inputs:
/// - `utf` -- the UTF8 string to count the number of codepoints in to determine if it needs the
///   higher character limit available in Session Pro
/// - `utf_size` -- the number of code units (aka. bytes) the string has
///
/// Outputs:
/// - `success` -- True if the message was evaluated successfully for PRO features false otherwise.
///   When false, all fields except for `error` should be ignored from the result object.
/// - `error` -- If `success` is false, this is populated with an error code describing the error,
///   otherwise it's empty. This string is read-only and should not be modified.
/// - `features` -- Feature flags suitable for writing directly into the protobuf
///   `ProMessage.messageFeatures`
/// - `codepoint_count` -- Counts the number of unicode codepoints that were in the message.
LIBSESSION_EXPORT
session_protocol_pro_features_for_msg session_protocol_pro_features_for_utf8(
        char const* utf, size_t utf_size) NON_NULL_ARG(1);

/// API: session_protocol/session_protocol_get_pro_features_for_utf16
///
/// Determine the Pro features that are used in a given UTF16 message.
///
/// Inputs:
/// - `utf` -- the UTF16 string to count the number of codepoints in to determine if it needs the
///   higher character limit available in Session Pro
/// - `utf_size` -- the number of code units (aka. bytes) the string has
///
/// Outputs:
/// - `success` -- True if the message was evaluated successfully for PRO features false otherwise.
///   When false, all fields except for `error` should be ignored from the result object.
/// - `error` -- If `success` is false, this is populated with an error code describing the error,
///   otherwise it's empty.
/// - `features` -- Feature flags suitable for writing directly into the protobuf
///   `ProMessage.messageFeatures`
/// - `codepoint_count` -- Counts the number of unicode codepoints that were in the message.
LIBSESSION_EXPORT
session_protocol_pro_features_for_msg session_protocol_pro_features_for_utf16(
        uint16_t const* utf, size_t utf_size) NON_NULL_ARG(1);

/// API: session_protocol_encode_for_1o1
///
/// Encode a plaintext message for a one-on-one (1o1) conversation or sync message in the Session
/// Protocol. This function wraps the plaintext in the necessary structures and encrypts it for
/// transmission to a single recipient.
///
/// See: session_protocol/encode_for_1o1 for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- The protobuf serialized payload containing the Content to be encrypted
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `ed25519_privkey` -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - `ed25519_privkey_len` -- The length of the ed25519_privkey buffer in bytes (32 or 64).
/// - `sent_timestamp_ms` -- The timestamp to assign to the message envelope, in milliseconds. This
///   should match the protobuf encoded Content's `sigtimestamp` in the given `plaintext`.
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the last
///   character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_1o1(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* recipient_pubkey,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 3, 6);

/// API: session_protocol_encode_for_community_inbox
///
/// Encode a plaintext message for a community inbox in the Session Protocol. This function wraps
/// the plaintext in the necessary structures and encrypts it for transmission to a community inbox
/// server.
///
/// See: session_protocol/encode_for_community_inbox for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext `-- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted.
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `ed25519_privkey` -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - `ed25519_privkey_len` -- The length of the ed25519_privkey buffer in bytes (32 or 64).
/// - `sent_timestamp_ms` -- The timestamp to assign to the message envelope, in milliseconds.
/// - `recipient_pubkey` -- The recipient's Session public key (33 bytes).
/// - `community_pubkey` -- The community inbox server's public key (32 bytes).
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length in order for the error message to be preserved in full.

LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_community_inbox(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* recipient_pubkey,
        const bytes32* community_pubkey,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 3, 6, 7);

/// API: session_protocol_encode_for_community
///
/// Encode a plaintext `Content` message for a community in the Session Protocol. This function
/// encodes Session Pro metadata including generating and embedding the Session Pro signature, when
/// given a Session Pro rotating Ed25519 key into the final payload suitable for transmission on the
/// wire.
///
/// See: session_protocol/encode_for_community for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext `-- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted.
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length in order for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_community(
        const void* plaintext,
        size_t plaintext_len,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* err,
        size_t error_len) NON_NULL_ARG(1);

/// API: session_protocol_encode_for_group
///
/// Encode a plaintext message for a group in the Session Protocol. This function wraps the
/// plaintext in the necessary structures and encrypts it for transmission to a group, using the
/// group's encryption key. Only v2 groups, (0x03) prefixed keys are supported. Passing a legacy
/// group (0x05) prefixed key will cause the function to return a failure with an error message.
///
/// See: session_protocol/encode_for_group for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted.
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `ed25519_privkey` -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - `ed25519_privkey_len` -- The length of the ed25519_privkey buffer in bytes (32 or 64).
/// - `sent_timestamp_ms` -- The timestamp to assign to the message envelope, in milliseconds.
/// - `group_ed25519_pubkey` -- The group's public key (33 bytes) for encryption with a 0x03 prefix.
/// - `group_enc_key` -- The group's encryption key (32 bytes) for groups v2 messages, typically the
//    latest key for the group (e.g., Keys::group_enc_key).
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length in order for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_group(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* group_ed25519_pubkey,
        const bytes32* group_enc_key,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 3, 6, 7);

/// API: session_protocol/session_protocol_encrypt_for_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// See: session_protocol/encrypt_for_destination for more information
///
/// The encoded result must be freed with `session_protocol_encrypt_for_destination_free` when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- the protobuf serialised payload containing the protobuf encoded stream,
///   `Content`. It must not be already be encrypted.
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes. Can also be
///   passed as a 32-byte seed. Used to encrypt the plaintext.
/// - `dest` -- the extra metadata indicating the destination of the message and the necessary data
///   to encrypt a message for that destination.
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
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The retured payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_destination(
        const void* plaintext,
        size_t plaintext_len,
        OPTIONAL const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const session_protocol_destination* dest,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 5);

/// API: session_protocol/session_protocol_encrypt_for_destination_free
///
/// Free the encryption result for a destination produced by
/// `session_protocol_encrypt_for_destination`. It is safe to pass a `NULL` or any result returned
/// by the encrypt function irrespective of if the function succeeded or failed.
///
/// Inputs:
/// - `encrypt` -- Encryption result to free. This object is zeroed out on free and should no longer
///   be used after it is freed.
LIBSESSION_EXPORT void session_protocol_encode_for_destination_free(
        session_protocol_encoded_for_destination* encrypt);

/// API: session_protocol/session_protocol_decode_envelope
///
/// Given an envelope payload (i.e.: protobuf encoded stream of `WebsocketRequestMessage` which
/// wraps an `Envelope` for 1o1 messages/sync messages, or `Envelope` encrypted using a Groups v2
/// key) parse (or decrypt) the envelope and return the envelope content decrypted if necessary.
///
/// See: session_protocol/decode_envelope for more information
///
/// The decoded result must be freed with `session_protocol_decode_for_community_free` when the
/// caller is done with the result.
///
/// Inputs:
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
/// - `success` -- True if encoding was successful, if the underlying implementation threw
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
///   at minimum the requested length for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_decoded_envelope session_protocol_decode_envelope(
        const session_protocol_decode_envelope_keys* keys,
        const void* envelope_plaintext,
        size_t envelope_plaintext_len,
        OPTIONAL const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 2);

/// API: session_protocol/session_protocol_decode_envelope_free
///
/// Free the decoded result produced by `session_protocol_decode_envelope`. It is safe to pass a
/// `NULL` or any result returned by the decode function irrespective of if the function succeeded
/// or failed.
///
/// Inputs:
/// - `envelope` -- decoded result to free. This object is zeroed out on free and should no
///   longer be used after it is freed.
LIBSESSION_EXPORT void session_protocol_decode_envelope_free(
        session_protocol_decoded_envelope* envelope);

/// API: session_protocol/session_protocol_decode_for_community
///
/// Given an unencrypted content or envelope payload extract the plaintext to the content and any
/// associated pro metadata if there was any in the message.
///
/// Inputs:
/// - `content_or_envelope_payload` -- the unencrypted content or envelope payload containing the
///   community message
/// - `unix_ts_ms` -- pass in the current system time which is used to determine, whether or
///   not the Session Pro proof has expired or not if it is in the payload. Ignored if there's no
///   proof in the message.
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer
///
/// Outputs:
/// - `envelope` -- Envelope structure that was parsed from the `content_or_envelope_payload` if the
///   payload was an envelope. Nil otherwise.
/// - `content_plaintext` -- The protobuf encoded stream that can be parsed into a protobuf
///   `Content` structure that was extracted from the `content_or_envelope_payload`
/// - `has_pro` -- Flag that indicates if the `pro` struct was populated or not.
/// - `pro_sig` -- Optional pro signature if there was one located in the
///   `content_or_envelope_payload`. This is the same signature as the one located in the `envelope`
///   object if the original payload was an envelope.
/// - `pro` -- Optional object that is set if there was pro metadata associatd with the envelope, if
///   any. The `status` field in the decrypted pro object should be used to determine whether or not
///   the caller can respect the contents of the `proof` and `features`.
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested lengthin order for the error message to be preserved in full.
///
///   If the `status` is set to valid the the caller can proceed with entitling the envelope with
///   access to pro features if it's using any.
LIBSESSION_EXPORT session_protocol_decoded_community_message session_protocol_decode_for_community(
        const void* content_or_envelope_payload,
        size_t content_or_envelope_payload_len,
        uint64_t unix_ts_ms,
        OPTIONAL const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1);

/// API: session_protocol/session_protocol_decode_for_community_free
///
/// Free the decoded result produced by `session_protocol_decode_for_community`. It is safe to pass
/// a `NULL` or any result returned by the decode function irrespective of if the function
/// succeeded or failed.
///
/// Inputs:
/// - `community_msg` -- decoded result to free. This object is zeroed out on free and should no
///   longer be used after it is freed.
LIBSESSION_EXPORT void session_protocol_decode_for_community_free(
        session_protocol_decoded_community_message* community_msg);

#ifdef __cplusplus
}
#endif
