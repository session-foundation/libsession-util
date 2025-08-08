#pragma once

#include <session/session_protocol.h>

#include <session/config/pro.hpp>
#include <session/types.hpp>
#include <span>

/// A complimentary file to session encrypt which has the low level encryption function for Session
/// protocol types. This file contains high-level helper functions for decoding payloads on the
/// Session protocol. Prefer functions here before resorting to the lower-level cryptography.
namespace session {

namespace config::groups {
    class Keys;
}

enum class ProStatus {
    Nil,      // Pro proof was not set
    Invalid,  // Pro proof was set; signature validation failed
    Valid,    // Pro proof was set, is verified; has not expired
    Expired,  // Pro proof was set, is verified; has expired
};

enum class DestinationType {
    Contact,
    SyncMessage,
    ClosedGroup,
    OpenGroup,
    OpenGroupInbox,
};

struct Destination {
    DestinationType type;

    // Signature over the plaintext with the user's Session Pro rotating public key if they have
    // Session Pro and opt into sending a message with pro features. If this is specified, the pro
    // message component in `Content` must have been set with the corresponding proof for this
    // signature.
    std::optional<array_uc64> pro_sig;

    // Set to the recipient of the message if it requires one. Ignored otherwise (for example
    // ignored in OpenGroup)
    array_uc32 recipient_pubkey;

    // The timestamp to assign to the message envelope if the message requires one. Ignored
    // otherwise
    std::chrono::milliseconds sent_timestamp_ms;

    // When type => OpenGroupInbox: set this pubkey to the server's key
    array_uc32 open_group_inbox_server_pubkey;

    // When type => ClosedGroup: set the following 'closed_group' prefixed fields
    array_uc33 closed_group_pubkey;
    const session::config::groups::Keys* closed_group_keys;

    // Set to the closed group's swarm public key (needed for Android) for a non 0x03 prefixed
    // `closed_group_pubkey`. Ignored otherwise. This will be set as the envelope source. See:
    // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L469
    std::optional<array_uc33> closed_group_swarm_public_key;
};

enum class EnvelopeType {
    SessionMessage,
    ClosedGroupMessage,
};

typedef uint32_t EnvelopeFlags;
enum EnvelopeFlags_ {
    EnvelopeFlags_Source = 1 << 0,
    EnvelopeFlags_SourceDevice = 1 << 1,
    EnvelopeFlags_ServerTimestamp = 1 << 2,
    EnvelopeFlags_ProSig = 1 << 3,
};

struct Envelope {
    EnvelopeFlags flags;
    EnvelopeType type;
    uint64_t timestamp;

    /// Optional fields. These fields are set if the appropriate flag has been set in `flags`
    /// otherwise the corresponding values are to be ignored and those fields will be
    /// zero-initialised.
    array_uc33 source;
    uint32_t source_device;
    uint64_t server_timestamp;
    array_uc64 pro_sig;
};

using ProFeatures = session_pro_features;
using ProExtraFeatures = session_pro_extra_features;

struct DecryptedEnvelope {
    // The envelope parsed from the plaintext
    Envelope envelope;

    // Decrypted envelope content into plaintext
    std::vector<uint8_t> content_plaintext;

    // Sender public key extracted from the encrypted content payload
    std::vector<uint8_t> sender_ed25519_pubkey;

    // Status flag for validity of the Session Pro proof embedded in the envelope if it has one.
    // The status is set to `Nil` if there is no Session Pro proof in the message. Otherwise it's
    // set to one of the other values to which the remaining pro fields will be populated with data
    // parsed from the envelope.
    ProStatus pro_status;

    // The embedded Session Pro proof, only set if the status was not `Nil`.
    config::ProProof pro_proof;

    // Session Pro features that were used in the embedded message, only set if the status was not
    // `Nil`.
    ProFeatures pro_features;
};

struct EncryptedForNamespaceDest
{
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
/// - `msg` -- the conversation message to determine if the message is requires access to the 10k
///   character limit available in Session Pro
/// - `flags` -- extra pro features that are known by clients that they wish to be activated on
///   this message
///
/// Outputs:
/// - Session Pro feature flags suitable for writing directly into the protobuf `ProMessage` in
///   `Content`
ProFeatures get_pro_features_for_msg(std::span<const unsigned char> msg, ProExtraFeatures flags);

/// API: session_protocol/encrypt_for_namespaced_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// This function supports all combinatoric combinations of the destination type and namespace
/// including returning plaintext if the message is not meant to be encrypted and or wrapping in the
/// additional websocket wrapper or encrypting the envelope with the closed group keys if necessary
/// e.t.c.
///
/// Calling this function requires filling out the options in the `Destination` struct with the
/// appropriate values for the desired combination of destination type and namespace. Check the
/// annotation on `Destination` for more information.
///
/// This function throws if the API is misused (i.e.: A field was not set, but was required to be
/// set for the given destination and namespace. For example the closed group keys not being set
/// when sending to a group prefixed [0x3] key in a closed group into the group message namespace)
/// but otherwise always returns a struct with values.
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
EncryptedForNamespaceDest encrypt_for_namespaced_destination(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        const Destination& dest,
        config::Namespace space);

/// API: session_protocol/decrypt_envelope
///
/// Given an unencrypted plaintext representation of an envelope (i.e.: protobuf encoded stream of
/// `Envelope`) parse the envelope and return the envelope content decrypted to plaintext with the
/// passed in key.
///
/// If the message does not use Session Pro features, the pro status will be set to nil and all
/// other pro fields are to be ignored. If the pro status is non-nil then the pro fields will be
/// populated with data about the Session Pro proof embedded in the envelope including the features
/// used and if the proof was valid/expired e.t.c.
///
/// This function will throw if parsing failed such as a required field is missing, the field is
/// smaller or larger than expected, decryption failed, or an invariant failed. Notably this
/// function does not throw if the Session Pro proof failed to verify. Always check the pro status
/// field to verify if the Session Pro was present and/or valid or invalid.
///
/// Inputs:
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes. Can also be
///   passed as a 32-byte seed. Used to decrypt the encrypted content.
/// - `envelope_plaintext` -- the protobuf serialised payload containing the message envelope. The
///   envelope must already be decrypted if it was originally encrypted (i.e.: closed group
///   envelopes).
/// - `unix_ts` -- pass in the current system time which is used to determine, if present in the
///   envelope, whether or not the Session Pro proof has expired or not.
///
/// Outputs:
/// - The decrypted envelope. It contains the fields of the envelope and the Session Pro metadata
///   within the envelope if there were any.
DecryptedEnvelope decrypt_envelope(
        std::span<const uint8_t> ed25519_privkey,
        std::span<const uint8_t> envelope_plaintext,
        std::chrono::sys_seconds unix_ts);
}  // namespace session
