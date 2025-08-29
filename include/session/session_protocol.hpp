#pragma once

#include <session/session_protocol.h>

#include <session/config/pro.hpp>
#include <session/types.hpp>
#include <span>

/// A complimentary file to session encrypt (which has the low level encryption function for Session
/// protocol types). This file contains high-level helper functions for decoding payloads on the
/// Session protocol. Prefer functions here before resorting to the lower-level cryptography.

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

namespace config::groups {
    class Keys;
}

enum class DestinationType {
    ContactOrSyncMessage = DESTINATION_TYPE_CONTACT_OR_SYNC_MESSAGE,
    /// Both legacy and non-legacy groups are to be identified as `Group`. A non-legacy
    /// group is detected by the (0x03) prefix byte on the given `dest_group_pubkey` specified in
    /// Destination.
    Group = DESTINATION_TYPE_GROUP,
    CommunityInbox = DESTINATION_TYPE_COMMUNITY_INBOX,
};

struct Destination {
    DestinationType type;

    // Signature over the unencrypted plaintext with the user's Session Pro rotating public key if
    // they have Session Pro and opt into sending a message with pro features. If this is specified,
    // the pro message component in `Content` must have been set with the corresponding proof for
    // this signature.
    std::optional<array_uc64> pro_sig;

    // The timestamp to assign to the message envelope
    std::chrono::milliseconds sent_timestamp_ms;
    //
    // When type => (CommunityInbox || SyncMessage || Contact): set to the recipient's Session
    // public key
    array_uc33 recipient_pubkey;

    // When type => CommunityInbox: set this pubkey to the server's key
    array_uc32 community_inbox_server_pubkey;

    // When type => Group: set to the group public keys for a 0x03 prefix (e.g. groups v2)
    // `group_pubkey` to encrypt the message for.
    array_uc33 group_ed25519_pubkey;

    // When type => Group: Set the private key of the group for groups v2 messages. Typically
    // the latest encryption key for the group, e.g: `Keys::group_enc_key` or
    // `groups_keys_group_enc_key`
    cleared_uc32 group_ed25519_privkey;
};

struct Envelope {
    ENVELOPE_FLAGS flags;
    std::chrono::milliseconds timestamp;

    // Optional fields. These fields are set if the appropriate flag has been set in `flags`
    // otherwise the corresponding values are to be ignored and those fields will be
    // zero-initialised.
    array_uc33 source;
    uint32_t source_device;
    uint64_t server_timestamp;

    // Signature by the sending client's rotating key
    array_uc64 pro_sig;
};

struct DecryptedPro {
    config::ProStatus status;  // Validity of the proof embedded in the envelope
    // Session Pro proof that was embedded in the envelope, this is always populated irrespective of
    // the status but the validity of the contents should be verified by checking `status`
    config::ProProof proof;
    PRO_FEATURES features;  // Bit flag features that were used in the embedded message
};

struct DecryptedEnvelope {
    // The envelope parsed from the plaintext
    Envelope envelope;

    // Decrypted envelope content into plaintext
    std::vector<uint8_t> content_plaintext;

    // Sender public key extracted from the encrypted content payload. This is not set if the
    // envelope was a groups v2 envelope where the envelope was encrypted and only the x25519 pubkey
    // was available.
    array_uc32 sender_ed25519_pubkey;

    // The x25519 pubkey, always populated on successful parse. Either it's present from decrypting
    // a Groups v2 envelope or it's re-derived from the Ed25519 pubkey.
    array_uc32 sender_x25519_pubkey;

    // Set if the envelope included a pro payload. The caller must check the status to determine if
    // the embedded pro data/proof was valid, invalid or whether or not the proof has expired.
    std::optional<DecryptedPro> pro;
};

struct DecryptEnvelopeKey {
    // Set the key to decrypt the envelope. If this key is set then it's assumed that the envelope
    // payload is encrypted (e.g. groups v2) and that the contents are unencrypted. If this key is
    // not set the it's assumed the envelope is not encrypted but the contents are encrypted (e.g.:
    // 1o1 or legacy group).
    std::optional<std::span<const uint8_t>> group_ed25519_pubkey;

    // List of libsodium-style secret key to decrypt the envelope from. Can also be passed as a 32
    // byte secret key. The public key component is not used.
    //
    // If the `group_ed25519_pubkey` is set then a list of keys is accepted to attempt to decrypt
    // the envelope. For envelopes generated by a group message, we assume that the envelope is
    // encrypted and must be decrypted by the group keys associated with it (of which there may be
    // many candidate keys depending on how many times the group has been rekeyed). It's recommended
    // to pass `Keys::group_keys()` or in the C API use the `groups_keys_size` and
    // `group_keys_get_key` combo to retrieve the keys to attempt to use to decrypt this message.
    //
    // If `group_ed25519_pubkey` is _not_ set then this function assumes the envelope is unencrypted
    // but the content is encrypted (e.g.: 1o1 and legacy group messages). The function will attempt
    // to decrypt the envelope's contents with the given keys. Typically in these cases you will
    // pass exactly 1 key for decryption but this function makes no pre-existing assumptions on the
    // number of keys and will attempt all given keys specified regardless until it finds one that
    // successfully decrypts the envelope contents.
    std::span<std::span<const uint8_t>> ed25519_privkeys;
};

struct EncryptedForDestination {
    // Indicates if the ciphertext was encrypted or not. This can be false if the message sent to
    // the destination and namespace does not require encryption. In this case `ciphertext` is not
    // set and the user should proceed with the original plaintext.
    bool encrypted;

    // The plaintext encrypted in a manner suitable for the desired destination and namespace. This
    // is not set if `encrypted` is false.
    std::vector<uint8_t> ciphertext;
};

/// API: session_protocol/get_pro_features_for_msg
///
/// Determine the Pro features that are used in a given conversation message.
///
/// Inputs:
/// - `msg_size` -- the size of the message in UTF16 code units to determine if the message requires
///   access to the higher character limit available in Session Pro
/// - `flags` -- extra pro features that are known by clients that they wish to be activated on
///   this message
///
/// Outputs:
/// - Session Pro feature flags suitable for writing directly into the protobuf `ProMessage` in
///   `Content`
PRO_FEATURES get_pro_features_for_msg(size_t msg_size, PRO_EXTRA_FEATURES flags);

EncryptedForDestination encrypt_and_wrap_for_1o1(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& recipient_pubkey,
        const std::optional<array_uc64>& pro_sig);

EncryptedForDestination encrypt_and_wrap_for_community_inbox(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& recipient_pubkey,
        const array_uc32& community_pubkey,
        const std::optional<array_uc64>& pro_sig);

EncryptedForDestination encrypt_and_wrap_for_group(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& group_ed25519_pubkey,
        const cleared_uc32& group_ed25519_privkey,
        const std::optional<array_uc64>& pro_sig);

/// API: session_protocol/encrypt_for_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// This function supports all combinatoric combinations of the destination type and namespace
/// including returning plaintext if the message is not meant to be encrypted and or wrapping in the
/// additional websocket wrapper or encrypting the envelope with the group keys if necessary
/// e.t.c.
///
/// Calling this function requires filling out the options in the `Destination` struct with the
/// appropriate values for the desired combination of destination type and namespace. Check the
/// annotation on `Destination` for more information.
///
/// This function throws if the API is misused (i.e.: A field was not set, but was required to be
/// set for the given destination and namespace. For example the group keys not being set
/// when sending to a group prefixed [0x3] key in a group into the group message namespace)
/// but otherwise returns a struct with values.
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
EncryptedForDestination encrypt_for_destination(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        const Destination& dest,
        config::Namespace space);

/// API: session_protocol/decrypt_envelope
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
/// - `unix_ts` -- pass in the current system time in seconds which is used to determine, whether or
///   not the Session Pro proof has expired or not if it is in the payload. Ignored if there's no
///   proof in the message.
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer
///
/// Outputs:
/// - `success` -- True if encryption was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   in the result are to be ignored on failure.
/// - `envelope` -- Envelope structure that was decrypted/parsed from the `envelope_plaintext`
/// - `content_plaintext` -- Decrypted contents of the envelope structure. This is the protobuf
///   encoded stream that can be parsed into a protobuf `Content` structure.
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
DecryptedEnvelope decrypt_envelope(
        const DecryptEnvelopeKey& keys,
        std::span<const uint8_t> envelope_payload,
        std::chrono::sys_seconds unix_ts,
        const array_uc32& pro_backend_pubkey);
}  // namespace session
