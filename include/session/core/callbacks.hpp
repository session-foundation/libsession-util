#pragma once
#include <functional>
#include <session/core/devices.hpp>

namespace session::core {

class Core;

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
    /// - reqid -- a unique identifier for this request; this is only used within the current
    ///   Core object, and is used to uniquely identify the request.  It will *not* work across
    ///   Core teardown and restart.
    /// - new_device -- the new device metadata included in the link request.  Crucial in this info
    ///   is the link_emoji sequence: a vector of 8 emoji (each in a separate utf8 string, leaving
    ///   separation, display, etc. up to the front-end) that provides a visual identifier of the
    ///   account device identifier, and is used to visually verify that the device making the
    ///   request is in fact the same device that is being confirmed.
    std::function<void(int reqid, const device::Info& new_device)> device_link_request;

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
};

}  // namespace session::core
