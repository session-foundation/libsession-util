#pragma once
#include <array>
#include <chrono>
#include <functional>
#include <optional>
#include <session/config/namespaces.hpp>
#include <session/core/devices.hpp>
#include <session/core/swarm_message.hpp>
#include <span>
#include <string_view>
#include <vector>

namespace session::core {

class Core;

/// Return value of prefetch_pfs_keys() describing the current cache state at the time of the call.
enum class PfsKeyStatus {
    fresh,     ///< A fresh cached key exists; no fetch was initiated
    stale,     ///< A usable but stale key exists; a background re-fetch was initiated.
               ///< The pfs_keys_fetched callback will fire when the fetch completes.
    fetching,  ///< No usable key is cached; a background fetch was initiated.
               ///< The pfs_keys_fetched callback will fire when the fetch completes.
    nak,       ///< An unexpired NAK suppresses fetching; no usable key exists
};

/// Result passed to the pfs_keys_fetched callback when a background fetch completes.
enum class PfsKeyFetch {
    new_key,    ///< A key was retrieved and stored (new or changed from the previous cache entry)
    unchanged,  ///< Keys were retrieved but match what was already cached
    not_found,  ///< The fetch succeeded but the remote account pubkey namespace held no valid keys
    failed,     ///< The network request failed (swarm lookup or send_request)
};

/// Reason code passed to the message_decrypt_failed callback.
enum class MessageDecryptFailure {
    no_pfs_key,      ///< Version 2 message: no PFS account key matched the key indicator AND the
                     ///< non-PFS fallback decryption also failed; the message cannot be read.
    decrypt_failed,  ///< Decryption failed (either version); key was found but did not work
    bad_format,      ///< Message is structurally malformed (e.g. invalid bencode, truncated fields)
    unknown_version,  ///< Message starts with 0x00 but carries an unrecognised version byte;
                      ///< likely a future protocol version this build does not understand
};

/// A successfully decrypted one-to-one message from Namespace::Default.
struct ReceivedMessage {
    std::string hash;                                 ///< Swarm-assigned message hash
    sys_ms timestamp;                                 ///< Server-reported upload timestamp
    sys_ms expiry;                                    ///< Server-reported expiry timestamp
    std::array<unsigned char, 33> sender_session_id;  ///< 0x05-prefixed sender session ID
    int version;                                      ///< Protocol version: 1 or 2
    std::vector<unsigned char> content;               ///< Decrypted protobuf-encoded payload
    std::optional<std::array<unsigned char, 64>>
            pro_signature;       ///< Session Pro signature, if present
    bool pfs_encrypted = false;  ///< True iff decrypted via PFS+PQ (X-Wing) key derivation;
                                 ///< false for v1 messages and v2 non-PFS fallback messages.
};

/// Status of a send operation initiated by Core::send_dm().
enum class MessageSendStatus {
    awaiting_keys,   ///< Waiting for a PFS+PQ pubkey fetch to complete before encrypting.
    sending,         ///< Encryption complete; the store request has been dispatched.
    retrying,        ///< A previous send attempt failed; retrying.  (Not yet implemented:
                     ///< currently a failed send goes directly to network_error.  TODO:
                     ///< implement automatic retry with a maximum retry count.)
    success,         ///< The store request was accepted by a swarm node.
    network_error,   ///< The swarm lookup or store request failed (terminal).
    no_network,      ///< No send_to_swarm callback is set and no network object is attached.
    encrypt_failed,  ///< Encryption failed (should not normally happen).
};

/// Struct holding application callbacks to fire when libsession Core events happen to allow the
/// Core object to fire into the application front-end.
struct callbacks {

    /// Callback that is invoked when a device linking request is received for entry into the device
    /// group.  This is expected to notify the user of the linking request, and ask them to confirm
    /// it.  Generally this should be followed (after user interaction) by a call to one of the
    /// core.devices methods: ignore_request(), accept_request(), delete_request() with the reqid
    /// value.
    ///
    /// This may fire multiple times: it generally fires when the request first comes in, but
    /// will also fire during startup if there is a still-active request that has not been
    /// accepted, ignored, or deleted.  (This is so that Session a shutdown or crash does not
    /// lose a device request).
    ///
    /// It may also not fire at all if the request has been superceded (such as being accepted
    /// by a third device).
    ///
    /// This request is not fired for the devices own linking request, i.e. when this device is the
    /// one requesting entry into a device group.
    ///
    /// If this callback is not set then new device link requests are ignored by this device.
    ///
    /// Parameters:
    /// - reqid -- a unique identifier for this request that persists across Core restarts and can
    ///   be used to correlate this request with a subsequent device_added callback.
    /// - new_device -- the new device metadata included in the link request.
    /// - sas -- a span of 21 string_views representing the short authentication string for this
    ///   request.  The first 7 are the standard display; all 21 are available for the extended
    ///   view.  Formatting and joining is left to the caller.
    std::function<void(
            int reqid, const device::Info& new_device, std::span<const std::string_view, 21> sas)>
            device_link_request;

    /// Callback that is invoked when a new device has been linked to the account.  If a batch
    /// of messages being processed includes both a device link request *and* an acceptance
    /// (such as could happen if third device accepts the request) then only this, not the
    /// request, will be fired.
    ///
    /// This callback is not fired if *this* is the device that has been added: see
    /// device_self_added instead for that case.
    ///
    /// Note that this is fired once the new device is confirmed via stored swarm message, i.e.
    /// it does not fire instantly upon calling `accept_request()`.
    ///
    /// Paramters:
    /// - reqid -- if `on_device_link_request` had previously been called for this device, this
    ///   value will be the same value, allowing the application to correlate linking requests and
    ///   acceptance.  If there was no previous link request (such as when catching up on device
    ///   updates performed by other account devices) then the value will be 0.
    /// - new_device -- the metadata about the new device.
    std::function<void(int reqid, const device::Info& new_device)> device_added;

    /// Callback invoked when *this* device has been confirmed linked to the account by another
    /// device.
    std::function<void()> device_self_added;

    /// Callback that is invoked if we determine that a device has been kicked out of the device
    /// group, either initiated by this device or another device.  This does not, however, fire if
    /// the *current* device gets kicked out; see device_self_removed for that.
    ///
    /// Parameters:
    /// - removed_device -- the most recent info we have (locally) for the removed device.
    std::function<void(const device::Info& removed_device)> device_removed;

    /// Callback invoked when *this* device has been confirmed removed from the account (typically
    /// from another device) from an incoming device group update.
    std::function<void()> device_self_removed;

    /// Callback invoked when a background PFS key fetch initiated by prefetch_pfs_keys() completes.
    /// Not invoked for cache hits or NAK suppressions (i.e. only fires when prefetch_pfs_keys()
    /// returns stale or fetching).
    ///
    /// Parameters:
    /// - session_id -- 33-byte session ID (0x05 prefix + X25519 pubkey) of the remote user
    /// - result -- the outcome of the fetch: new_key, unchanged, not_found, or failed
    std::function<void(std::span<const std::byte, 33> session_id, PfsKeyFetch result)>
            pfs_keys_fetched;

    /// Callback invoked when a one-to-one message from Namespace::Default is successfully
    /// decrypted.  The message is passed as an rvalue reference: the callback may move from it
    /// (e.g. to take ownership of the content vector) or simply read it in place.
    ///
    /// Parameters:
    /// - msg -- the decrypted message data
    std::function<void(ReceivedMessage&& msg)> message_received;

    /// Callback invoked when a one-to-one message from Namespace::Default could not be decrypted
    /// or parsed.  The raw swarm message and a reason code are provided so the caller can decide
    /// how to handle it (e.g. log, queue for retry, surface to the user).
    ///
    /// When receive_messages() is called directly by the application, `msg` is a reference to one
    /// of the SwarmMessage elements passed in, which the caller can identify exactly by comparing
    /// pointers.  When triggered by internal polling, `msg` refers to an internally-owned object.
    ///
    /// Parameters:
    /// - msg    -- the raw swarm message that could not be decrypted
    /// - reason -- why decryption failed
    std::function<void(const SwarmMessage& msg, MessageDecryptFailure reason)>
            message_decrypt_failed;

    /// Application-provided swarm store function.  If set, Core calls this to deliver outgoing
    /// messages instead of using its attached network object.
    ///
    /// The implementation MUST call on_stored with success (true) or failure (false) when the
    /// store operation completes or fails.
    ///
    /// Parameters:
    /// - recipient_pubkey -- 33-byte (0x05-prefixed) session ID whose swarm should receive the
    ///   message
    /// - ns -- the swarm namespace to store into (e.g. Namespace::Default for DMs)
    /// - payload -- the fully-encoded message bytes (envelope-wrapped, encrypted)
    /// - ttl -- requested time-to-live for the stored message
    /// - on_stored -- callback that MUST be invoked with the outcome
    std::function<void(
            std::span<const std::byte, 33> recipient_pubkey,
            config::Namespace ns,
            std::vector<std::byte> payload,
            std::chrono::milliseconds ttl,
            std::function<void(bool success)> on_stored)>
            send_to_swarm;

    /// Callback fired as a send operation initiated by Core::send_dm() progresses.  This is
    /// typically invoked multiple times for a single message — once or more for intermediate
    /// states (awaiting_keys, sending, retrying) followed by a terminal state (success,
    /// network_error, no_network, or encrypt_failed).
    ///
    /// Parameters:
    /// - message_id -- the value returned by the originating send_dm() call
    /// - status -- the current state of the send
    std::function<void(int64_t message_id, MessageSendStatus status)> message_send_status;
};

}  // namespace session::core
