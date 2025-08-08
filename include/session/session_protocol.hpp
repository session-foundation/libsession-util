#pragma once

#include <session/config/pro.hpp>
#include <session/session_protocol.h>
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
    // Session Pro and opt into sending a message with pro features.
    std::optional<array_uc64> pro_sig;

    // Set to the recipient of the message if it requires one. Ignored otherwise (for example
    // ignored in OpenGroup)
    array_uc32 recipient_pubkey;

    // The timestamp to assign to the message envelope if the message requires one. Ignored otherwise
    std::chrono::milliseconds sent_timestamp_ms;

    // When type => OpenGroupInbox: set this pubkey to the server's key
    array_uc32 open_group_inbox_server_pubkey;

    // When type => ClosedGroup: set the following 'closed_group' prefixed fields
    array_uc33 closed_group_pubkey;
    const session::config::groups::Keys *closed_group_keys;

    // Set to the closed group's swarm public key (needed for Android) for a non 0x03 prefixed
    // `closed_group_pubkey`. Ignored otherwise. This will be set as the envelope source. See:
    // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L469
    std::optional<array_uc33> closed_group_swarm_public_key;
};

using ProFeatures = session_pro_features;
using ProExtraFeatures = session_pro_extra_features;

enum class EnvelopeType
{
  SessionMessage,
  ClosedGroupMessage,
};

typedef uint32_t EnvelopeFlags;
enum EnvelopeFlags_
{
    EnvelopeFlags_Source = 1 << 0,
    EnvelopeFlags_SourceDevice = 1 << 1,
    EnvelopeFlags_ServerTimestamp = 1 << 2,
    EnvelopeFlags_ProSig = 1 << 3,
};

struct Envelope
{
    EnvelopeFlags flags;
    EnvelopeType type;
    uint64_t timestamp;

    // Optional fields
    array_uc33 source;
    uint32_t source_device;
    uint64_t server_timestamp;
    array_uc64 pro_sig;
};

struct DecryptedEnvelope
{
    Envelope envelope;
    std::vector<uint8_t> content_plaintext;
    std::vector<uint8_t> sender_ed25519_pubkey;

    config::ProProof pro_proof;
    ProStatus pro_status;
    ProFeatures pro_flags;
    array_uc64 pro_sig;
};

ProFeatures get_pro_features_for_msg(std::span<const unsigned char> msg, ProExtraFeatures flags);

array_uc64 sign_msg_for_pro(
        std::span<const unsigned char> msg, const array_uc64& rotating_priv_key);

std::vector<uint8_t> encrypt_for_namespaced_destination(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        const Destination& dest,
        config::Namespace space);

DecryptedEnvelope decrypt_envelope(
        std::span<const uint8_t> ed25519_privkey,
        std::span<const uint8_t> envelope_plaintext,
        std::chrono::sys_seconds unix_ts);
} // namespace session
