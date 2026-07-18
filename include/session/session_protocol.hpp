#pragma once

#include <session/session_protocol.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <session/clock.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/hash.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>
#include <span>
#include <string_view>

/// A complimentary file to session encrypt (which has the low level encryption function for Session
/// protocol types). This file contains high-level helper functions for decoding payloads on the
/// Session protocol. Prefer functions here before resorting to the lower-level cryptography.
///
/// The general overview is that this file introduces functionality to abstract away protobufs types
/// on the Session Protocol from client implementations by wrapping the data structures where
/// necessary in libsession. In general clients will use the functions in this file as follows:
///
/// - Derive Session Pro feature flags from a message for populating the new Pro fields for messages
///
/// - Wrap and/or encrypt a plaintext content message into an Envelope or Websocket message
///   (depending on the configured namespace and destination) ready to be sent on the wire with
///   `encode_for_destination`.
///
/// - Decrypt an incoming message in its websocket wrapped, and or encrypted envelope form with
///   `decode_envelope`
///
/// TODO: In future the goal is to begin abstracting more protobuf types away from client
/// implementations such that the only dependency clients need to encode and decode Session Protocol
/// messages is libsession itself and that it will provide wrapper/proxy types for and handle
/// converting those into the wire format.

// NOTE: In the CPP file we use C-style enums for bitfields and CPP-style enums for non-bitfield
// enums where we can to benefit from the type-safety of strong enums.
//
// CPP doesn't support named bitfields without casting or operator overloads but C-style
// enums support it very well. The only issue is that using a native C-style enum enforces some type
// restrictions that compilers dislike when attempting to manipulate bit fields. For example:
//
//   enum Feature {x = 1 << 0, y = 1 << 1}
//   Feature f = x | y
//
// Causes the compiler to complain about trying to do bit ops/assign an unsigned integer to an enum
// `Feature`. We use a common C pattern/trick by suffixing an underscore to the the original enum,
// then type define the non-suffixed enum to an unsigned integer:
//
//   enum Feature_ {x = 1 << 0, y = 1 << 1}
//   typedef U64 Feature
//   Feature f = x | y
//
// Does not trigger errors as the underlying type of `f` is actually an unsigned integer. The type
// define is merely a hint to the user to what flags are to be used when manipulating the variable.

namespace session {

enum ProProofVersion { ProProofVersion_v0 };

/// Session Pro personalisation bytes for hashing; must match the personalisation strings in
/// pro-wire-protocol.md §2 (proof) and §3 (signed requests).
inline constexpr auto GENERATE_PROOF_PERS = "ProGenerateProof"_b2b_pers;
inline constexpr auto BUILD_PROOF_PERS = "ProProof________"_b2b_pers;
inline constexpr auto ADD_PRO_PAYMENT_PERS = "ProAddPayment___"_b2b_pers;
inline constexpr auto SET_PAYMENT_REFUND_REQUESTED_PERS = "ProSetRefundReq_"_b2b_pers;
inline constexpr auto GET_PRO_DETAILS_PERS = "ProGetProDetReq_"_b2b_pers;

enum class ProStatus {
    // Pro proof sig was not signed by the Pro backend key
    InvalidProBackendSig = SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    // Pro sig in the envelope was not signed by the Rotating key
    InvalidUserSig = SESSION_PROTOCOL_PRO_STATUS_INVALID_USER_SIG,
    Valid = SESSION_PROTOCOL_PRO_STATUS_VALID,      // Proof is verified; has not expired
    Expired = SESSION_PROTOCOL_PRO_STATUS_EXPIRED,  // Proof is verified; has expired
};

struct ProSignedMessage {
    std::span<const std::byte, 64> sig;
    std::span<const std::byte> msg;
};

class ProProof {
  public:
    /// Version of the proof set by the Session Pro Backend
    std::uint8_t version;

    /// Opaque revocation tag identifying this proof (from the Session Pro backend)
    b32 revocation_tag;

    /// The public key that the Session client registers their Session Pro entitlement under.
    /// Session clients must sign messages with this key along side the sending of this proof for
    /// the network to authenticate their usage of the proof
    b32 rotating_pubkey;

    /// Unix epoch timestamp to which this proof's entitlement to Session Pro features is valid to
    std::chrono::sys_seconds expiry_unix_ts;

    /// Signature over the contents of the proof. It is signed by the Session Pro Backend key which
    /// is the entity responsible for issueing tamper-proof Sesison Pro certificates for Session
    /// clients.
    b64 sig;

    /// API: pro/Proof::verify_signature
    ///
    /// Verify that the proof's contents was not tampered with by hashing the proof and checking
    /// that the hash was signed by the secret key of the given Ed25519 public key.
    ///
    /// For Session Pro intents and purposes, we expect proofs to be signed by the Session Pro
    /// Backend public key. This function throws if an incorrectly sized key is passed in.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
    /// they are the original signatory of the proof.
    ///
    /// Outputs:
    /// - `bool` - True if the given key was the signatory of the proof, false otherwise
    bool verify_signature(std::span<const std::byte, 32> verify_pubkey) const;

    /// API: pro/Proof::verify_message
    ///
    /// Check if the `rotating_pubkey` in the proof was the signatory of the message and signature
    /// passed in. This function throws if an signature is passed in that isn't 64 bytes.
    ///
    /// Inputs:
    /// - `sig` -- Signature to verify with the `rotating_pubkey`. The signature should have
    ///   originally been signed over `msg` passed in.
    /// - `msg` -- Message that the signature signed over with. It will be verified using the
    ///   embedded `rotating_pubkey`.
    ///
    /// Outputs:
    /// - `bool` - True if the message was signed by the embedded `rotating_pubkey` false otherwise.
    bool verify_message(std::span<const std::byte, 64> sig, std::span<const std::byte> msg) const;

    /// API: pro/Proof::is_active
    ///
    /// Check if Pro proof is currently entitled to Pro given the `unix_ts` with respect to the
    /// proof's `expiry_unix_ts`
    ///
    /// Inputs:
    /// - `unix_ts` -- Unix timestamp to compare against the embedded `expiry_unix_ts`
    ///   to determine if the proof has expired or not
    ///
    /// Outputs:
    /// - `bool` - True if proof is active (i.e. has not expired), false otherwise.
    bool is_active(std::chrono::sys_seconds unix_ts) const;

    /// API: pro/Proof::status
    ///
    /// Evaluate the status of the pro proof by checking it is signed by the `verify_pubkey`, it has
    /// not expired via `unix_ts` and optionally verify that the `signed_msg` was signed by the
    /// `rotating_pubkey` embedded in the proof.
    ///
    /// Internally this function calls `verify_signature`, `verify_message` and optionally
    /// `is_active` in sequence. This function throws if an invalidly sized public key or signature
    /// are passed in. They must be 32 and 64 bytes respectively.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
    ///   they are the original signatory of the proof.
    /// - `unix_ts` -- Unix timestamp to compared against the embedded `expiry_unix_ts`
    ///   to determine if the proof has expired or not
    /// - `signed_msg` -- Optionally set the payload to the message with the signature to verify if
    ///   the embedded `rotating_pubkey` in the proof signed the given message.
    ///
    /// Outputs:
    /// - `ProStatus` - The derived status given the components of the message. If `signed_msg` is
    ///   not set then this function can never return `ProStatus::InvalidUserSig` from the set of
    ///   possible enum values. Otherwise this funtion can return all possible values.
    ProStatus status(
            std::span<const std::byte, 32> verify_pubkey,
            std::chrono::sys_seconds unix_ts,
            const std::optional<ProSignedMessage>& signed_msg);

    /// API: pro/Proof::hash
    ///
    /// Create a 32-byte hash from the proof. This hash is the payload that is signed in the proof.
    b32 hash() const;

    bool operator==(const ProProof& other) const {
        return version == other.version && revocation_tag == other.revocation_tag &&
               rotating_pubkey == other.rotating_pubkey && expiry_unix_ts == other.expiry_unix_ts &&
               sig == other.sig;
    }
};

enum class ProFeaturesForMsgStatus {
    Success = SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS,

    /// Message byte stream to classify could not be decoded into a valid UTF8/16 string
    UTFDecodingError = SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_UTF_DECODING_ERROR,

    /// Decoded UTF8/16 string exceeded the maximum character limit allowed for Session Pro
    ExceedsCharacterLimit = SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_EXCEEDS_CHARACTER_LIMIT,
};

struct ProProfileBitset {
    uint64_t data;
    void set(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);
    void unset(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);
    bool is_set(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) const;
};

struct ProMessageBitset {
    uint64_t data;
    void set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);
    void unset(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);
    bool is_set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) const;
};

struct ProFeaturesForMsg {
    ProFeaturesForMsgStatus status;
    std::string_view error;
    ProMessageBitset bitset;
    size_t codepoint_count;
};

struct Envelope {
    SESSION_PROTOCOL_ENVELOPE_FLAGS flags;
    std::chrono::milliseconds timestamp;

    // Optional fields. These fields are set if the appropriate flag has been set in `flags`
    // otherwise the corresponding values are to be ignored and those fields will be
    // zero-initialised.
    b33 source;
    uint32_t source_device;
    uint64_t server_timestamp;

    // Signature by the sending client's rotating key
    b64 pro_sig;
};

struct DecodedPro {
    ProStatus status;  // Validity of the proof embedded in the envelope
    // Session Pro proof that was embedded in the envelope, this is always populated irrespective of
    // the status but the validity of the contents should be verified by checking `status`
    ProProof proof;
    ProMessageBitset msg_bitset;
    ProProfileBitset profile_bitset;
};

struct DecodedEnvelope {
    // The envelope parsed from the plaintext
    Envelope envelope;

    // Decoded envelope content into plaintext with padding stripped
    std::vector<std::byte> content_plaintext;

    // Sender public key extracted from the encrypted content payload. This is not set if the
    // envelope was a groups v2 envelope where the envelope was encrypted and only the x25519 pubkey
    // was available.
    b32 sender_ed25519_pubkey;

    // The x25519 pubkey, always populated on successful parse. Either it's present from decrypting
    // a Groups v2 envelope or it's re-derived from the Ed25519 pubkey.
    b32 sender_x25519_pubkey;

    // Set if the envelope included a pro payload. The caller must check the status to determine if
    // the embedded pro data/proof was valid, invalid or whether or not the proof has expired.
    std::optional<DecodedPro> pro;
};

struct DecodedCommunityMessage {
    // The envelope parsed from the plaintext. Set if the plaintext was originally an envelope blob.
    // This is optional because the protocol is undergoing a migration period to start sending
    // community messages as an `Envelope` instead of `Content` so we will receive one or the other
    // kind of blob on the wire during that period.
    std::optional<Envelope> envelope;

    // The protobuf encoded `Content` with padding stripped
    std::vector<std::byte> content_plaintext;

    // The signature if it was present in the payload. If the envelope is set and the envelope has
    // the pro signature flag set, then this signature was extracted from the envelope. When the
    // signature is sourced from the envelope, the envelope's `pro_sig` field is also set to the
    // same signature as this instance for consistency. Otherwise the signature, if set was
    // extracted from the community-exclusive pro signature field in the content message.
    std::optional<b64> pro_sig;

    // Set if the envelope included a pro payload. The caller must check the status to determine if
    // the embedded pro data/proof was valid, invalid or whether or not the proof has expired.
    std::optional<DecodedPro> pro;
};

/// API: session_protocol/pro_features_for_utf8
///
/// Determine the Pro features that are used in a given conversation message.
///
/// Inputs:
/// - `msg` -- the UTF-8 string view to count the number of codepoints in to determine if it needs
///   the higher character limit available in Session Pro
///
/// Outputs:
/// - `success` -- True if the message was evaluated successfully for PRO features false otherwise.
///   When false, all fields except for `error` should be ignored from the result object.
/// - `error` -- If `success` is false, this is populated with an error code describing the error,
///   otherwise it's empty. This string is read-only and should not be modified.
/// - `features` -- Feature flags suitable for writing directly into the protobuf
///   `ProMessage.messageFeatures`
/// - `codepoint_count` -- Counts the number of unicode codepoints that were in the message.
ProFeaturesForMsg pro_features_for_utf8(std::u8string_view msg);
ProFeaturesForMsg pro_features_for_utf8(std::string_view msg);
ProFeaturesForMsg pro_features_for_utf8(std::span<const std::byte> msg);

/// API: session_protocol/pro_features_for_utf16
///
/// Determine the Pro features that are used in a given conversation message.
///
/// Inputs:
/// - `msg` -- the UTF-16 string view to count the number of codepoints in to determine if it needs
///   the higher character limit available in Session Pro
///
/// Outputs:
/// - `success` -- True if the message was evaluated successfully for PRO features false otherwise.
///   When false, all fields except for `error` should be ignored from the result object.
/// - `error` -- If `success` is false, this is populated with an error code describing the error,
///   otherwise it's empty. This string is read-only and should not be modified.
/// - `bitset` -- Feature flags suitable for writing directly into the protobuf
///   `ProMessage.messageFeatures`
/// - `codepoint_count` -- Counts the number of unicode codepoints that were in the message.
ProFeaturesForMsg pro_features_for_utf16(std::u16string_view msg);

/// API: session_protocol/pad_message
///
/// Pad a message to the required alignment for 1o1/community messages (160 bytes) including space
/// for the padding-terminating byte.
std::vector<std::byte> pad_message(std::span<const std::byte> payload);

/// API: session_protocol/encode_dm_v1
///
/// Encode a plaintext "v1" message for a one-on-one conversation message (either text message, or
/// conversation metadata) in the Session Protocol. This function wraps the plaintext in the
/// necessary structures and encrypts it for transmission to a single recipient.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes).
///
/// Inputs:
/// - plaintext -- The protobuf serialized Content plaintext, unpadded payload of the message.
/// - ed25519_privkey -- The sender's Ed25519 private key; accepts a 32-byte seed or 64-byte
///   libsodium "secret".  Used to identify the sender and sign the payload.
/// - sent_timestamp -- The timestamp to assign to the message envelope, in unix epoch milliseconds.
///   This must match the protobuf encoded Content's `sigTimestamp` in the given `plaintext`.
/// - recipient_pubkey -- The recipient's Session ID (33 bytes: 0x05 prefix + X25519 pubkey).
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) or seed (32
///   bytes) of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to entitle
///   the message with Pro features by signing it.  Can also be passed as a 32-byte seed.  Omit
///   (or pass std::nullopt) to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encrypted, encoded payload, with all required protobuf encoding and wrapping.
std::vector<std::byte> encode_dm_v1(
        std::span<const std::byte> plaintext,
        const ed25519::PrivKeySpan& ed25519_privkey,
        sys_ms sent_timestamp,
        std::span<const std::byte, 33> recipient_pubkey,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey = std::nullopt);

/// API: session_protocol/encode_for_community_inbox
///
/// Encode a plaintext message for a community-handled direct message in the Session Protocol.  Such
/// DMs are used to initiate contact with blinded users without needing to expose their Session ID
/// unless they accept the contact.  This function wraps the plaintext in the necessary structures
/// and encrypts it for transmission to a community inbox server.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes).
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - ed25519_privkey -- The sender's Ed25519 private key; accepts a 32-byte seed or 64-byte
///   libsodium key. Used to encrypt the plaintext.
/// - sent_timestamp -- The timestamp to assign to the message envelope, in milliseconds.
/// - recipient_pubkey -- The recipient's Session public key (33 bytes).
/// - community_pubkey -- The community inbox server's public key (32 bytes).
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<std::byte> encode_for_community_inbox(
        std::span<const std::byte> plaintext,
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        std::span<const std::byte, 33> recipient_pubkey,
        std::span<const std::byte, 32> community_pubkey,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey);

/// API: session_protocol/encode_community_message
///
/// Encode a plaintext `Content` message for sending to a community in the Session Protocol. This
/// function encodes Session Pro metadata including generating and embedding the Session Pro
/// signature, when given a Session Pro rotating Ed25519 key into the final payload suitable for
/// transmission on the wire.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes). It also
/// throws if the pro signature is already set in the plaintext `Content` or the `plaintext` cannot
/// be interpreted as a `Content` message.
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<std::byte> encode_for_community(
        std::span<const std::byte> plaintext,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey);

/// API: session_protocol/encode_for_group
///
/// Encode a plaintext message for a group in the Session Protocol. This function wraps the
/// plaintext in the necessary structures and encrypts it for transmission to a group, using the
/// group's encryption key. Only v2 groups (with 0x03 prefixed keys) are supported. Passing a legacy
/// group (0x05 prefix) will cause the function to throw.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes).
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - ed25519_privkey -- The sender's Ed25519 private key; accepts a 32-byte seed or 64-byte
///   libsodium key. Used to encrypt the plaintext.
/// - sent_timestamp -- The timestamp to assign to the message envelope, in milliseconds.
/// - group_ed25519_pubkey -- The group's public key (33 bytes) for encryption with a 0x03 prefix
/// - group_enc_key -- The group's encryption key (32 bytes) for groups v2 messages, typically the
///   latest key for the group (e.g., Keys::group_enc_key).
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<std::byte> encode_for_group(
        std::span<const std::byte> plaintext,
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        std::span<const std::byte, 33> group_ed25519_pubkey,
        std::span<const std::byte, 32> group_enc_key,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey);

/// API: session_protocol/decode_envelope
///
/// Given an envelope payload (i.e.: protobuf encoded stream of `WebsocketRequestMessage` which
/// wraps an `Envelope` for 1o1 messages/sync messages, or `Envelope` encrypted using a Groups v2
/// key) parse (or decrypt) the envelope and return the envelope content decrypted if necessary.
///
/// A groups v2 envelope will get decrypted with the group keys. A non-groups v2 envelope will get
/// decrypted with the specified Ed25519 private key in the `keys` object. Only one of these keys
/// need to be set depending on the type of envelope payload passed into the function.
///
/// If the message does not use Session Pro features, the `pro` object will be set to nil. Otherwise
/// the pro fields will be populated with data about the Session Pro proof embedded in the envelope
/// including the features used and if the proof was valid/expired e.t.c.
///
/// The sent timestamp of the protobuf encoded content is the timestamp that the Session Pro proof
/// is checked against to ensure that it was not expired at the time the message was constructed.
/// Once a proof is decoded successfully and was not deemed expired (e.g. pro status returned
/// success) any additional timestamp can be checked against the proof by comparing the timestamp on
/// the proof itself directly (since the proof has been cryptographically verified at that point).
///
/// This function will throw if parsing failed such as a required field is missing, the field is
/// smaller or larger than expected, decryption failed, or an invariant failed. Notably this
/// function does not throw if the Session Pro proof failed to verify. Always check the pro status
/// field to verify if the Session Pro was present and/or valid or invalid.
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
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer
///
/// Outputs:
/// - `envelope` -- Envelope structure that was decrypted/parsed from the `envelope_plaintext`
/// - `content_plaintext` -- Decrypted contents of the envelope structure. This is the protobuf
///   encoded stream that can be parsed into a protobuf `Content` structure.
/// - `sender_ed25519_pubkey` -- The sender's ed25519 public key embedded in the encrypted payload.
///   This is only set for session message envelopes. Groups envelopes only embed the sender's
///   x25519 public key in which case this field is set to the zero public key.
/// - `sender_x25519_pubkey` -- The sender's x25519 public key. It's always set on successful
///   decryption either by extracting the key from the encrypted groups envelope, or, by deriving
///   the x25519 key from the sender's ed25519 key in the case of a session message envelope.
/// - `pro` -- Optional object that is set if there was pro metadata associatd with the envelope, if
///   any. The `status` field in the decrypted pro object should be used to determine whether or not
///   the caller can respect the contents of the `proof` and `features`.
///
///   If the `status` is set to valid the the caller can proceed with entitling the envelope with
///   access to pro features if it's using any.
/// Decodes a 1-on-1 or legacy group envelope.  The envelope payload is a WebSocket-wrapped
/// protobuf whose inner content is encrypted with the Session protocol (Ed25519 DH).
///
/// Throws on parse or decryption failure.
DecodedEnvelope decode_dm_envelope(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> envelope_payload,
        std::span<const std::byte, 32> pro_backend_pubkey);

/// Decodes a groups v2 envelope.  The envelope payload is encrypted with a group symmetric key
/// and decrypted via `decrypt_group_message`.  The inner content is plaintext.
///
/// `group_keys` is a list of recent symmetric group encryption keys to try; multiple keys are
/// needed because the key rotates periodically, and retrieved messages may still be encrypted
/// with a pre-rotation key if they were sent before the rotation occurred.
///
/// Throws on parse or decryption failure.
DecodedEnvelope decode_group_envelope(
        std::span<std::span<const std::byte, 32>> group_keys,
        std::span<const std::byte, 32> group_ed25519_pubkey,
        std::span<const std::byte> envelope_payload,
        std::span<const std::byte, 32> pro_backend_pubkey);

/// API: session_protocol/decode_for_community
///
/// Given an unencrypted content or envelope payload extract the plaintext to the content and any
/// associated pro metadata if there was any in the message.
///
/// Inputs:
/// - `content_or_envelope_payload` -- the padded unencrypted content or envelope payload containing
///   the community message
/// - `unix_ts` -- pass in the current system time which is used to determine, whether or
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
/// - `pro_sig` -- Optional pro signature if there was one located in the
///   `content_or_envelope_payload`. This is the same signature as the one located in the `envelope`
///   object if the original payload was an envelope.
/// - `pro` -- Optional object that is set if there was pro metadata associatd with the envelope, if
///   any. The `status` field in the decrypted pro object should be used to determine whether or not
///   the caller can respect the contents of the `proof` and `features`.
///
///   If the `status` is set to valid the the caller can proceed with entitling the envelope with
///   access to pro features if it's using any.
DecodedCommunityMessage decode_for_community(
        std::span<const std::byte> content_or_envelope_payload,
        std::chrono::sys_seconds unix_ts,
        std::span<const std::byte, 32> pro_backend_pubkey);

}  // namespace session
