#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include "pro.h"
#include "profile_pic.h"

/// API: user_profile/user_profile_init
///
/// Constructs a user profile config object and sets a pointer to it in `conf`.
///
/// When done with the object the `config_object` must be destroyed by passing the pointer to
/// config_free() (in `session/config/base.h`).
///
/// Declaration:
/// ```cpp
/// INT user_profile_init(
///     [out]   config_object**         conf,
///     [in]    const unsigned char*    ed25519_secretkey,
///     [in]    const unsigned char*    dump,
///     [in]    size_t                  dumplen,
///     [out]   char*                   error
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `ed25519_secretkey` -- [in] must be the 32-byte secret key seed value.  (You can also pass the
/// pointer to the beginning of the 64-byte value libsodium calls the "secret key" as the first 32
/// bytes of that are the seed).  This field cannot be null.
/// - `dump` -- [in] if non-NULL this restores the state from the dumped byte string produced by a
/// past instantiation's call to `dump()`.  To construct a new, empty profile this should be NULL.
/// - `dumplen` -- [in] the length of `dump` when restoring from a dump, or 0 when `dump` is NULL.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `int` -- Returns 0 on success; returns a non-zero error code and write the exception message
/// as a C-string into `error` (if not NULL) on failure.
LIBSESSION_EXPORT int user_profile_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey,
        const unsigned char* dump,
        size_t dumplen,
        char* error) LIBSESSION_WARN_UNUSED;

/// API: user_profile/user_profile_get_name
///
/// Returns a pointer to the currently-set name (null-terminated), or NULL if there is no name at
/// all.  Should be copied right away as the pointer may not remain valid beyond other API calls.
///
/// Declaration:
/// ```cpp
/// CONST CHAR* user_profile_get_name(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `char*` -- Pointer to the currently-set name as a null-terminated string, or NULL if there is
/// no name
LIBSESSION_EXPORT const char* user_profile_get_name(const config_object* conf);

/// API: user_profile/user_profile_set_name
///
/// Sets the user profile name to the null-terminated C string.  Returns 0 on success, non-zero on
/// error (and sets the config_object's error string).
///
/// Declaration:
/// ```cpp
/// INT user_profile_set_name(
///     [in]    config_object*  conf,
///     [in]    const char*     name
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `name` -- [in] Pointer to the name as a null-terminated C string
///
/// Outputs:
/// - `int` -- Returns 0 on success, non-zero on error
LIBSESSION_EXPORT int user_profile_set_name(config_object* conf, const char* name);

/// API: user_profile/user_profile_get_pic
///
/// Obtains the current profile pic.  The pointers in the returned struct will be NULL if a profile
/// pic is not currently set, and otherwise should be copied right away (they will not be valid
/// beyond other API calls on this config object).  The returned value will be the latest profile
/// pic between when the user last set their profile and when it was last re-uploaded.
///
/// Declaration:
/// ```cpp
/// USER_PROFILE_PIC user_profile_get_pic(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `user_profile_pic` -- Pointer to the currently-set profile pic
LIBSESSION_EXPORT user_profile_pic user_profile_get_pic(const config_object* conf);

/// API: user_profile/user_profile_set_pic
///
/// Sets a user profile pic
///
/// Declaration:
/// ```cpp
/// INT user_profile_set_pic(
///     [in]    config_object*      conf,
///     [in]    user_profile_pic    pic
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pic` -- [in] Pointer to the pic
///
/// Outputs:
/// - `int` -- Returns 0 on success, non-zero on error
LIBSESSION_EXPORT int user_profile_set_pic(config_object* conf, user_profile_pic pic);

/// API: user_profile/user_profile_set_reupload_pic
///
/// Sets a user profile pic when reuploading
///
/// Declaration:
/// ```cpp
/// INT user_profile_set_reupload_pic(
///     [in]    config_object*      conf,
///     [in]    user_profile_pic    pic
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pic` -- [in] Pointer to the pic
///
/// Outputs:
/// - `int` -- Returns 0 on success, non-zero on error
LIBSESSION_EXPORT int user_profile_set_reupload_pic(config_object* conf, user_profile_pic pic);

/// API: user_profile/user_profile_get_nts_priority
///
/// Gets the current note-to-self priority level. Will be negative for hidden, 0 for unpinned, and >
/// 0 for pinned (with higher value = higher priority).
///
/// Declaration:
/// ```cpp
/// INT user_profile_get_nts_priority(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- Returns the priority level
LIBSESSION_EXPORT int user_profile_get_nts_priority(const config_object* conf);

/// API: user_profile/user_profile_set_nts_priority
///
/// Sets the current note-to-self priority level. Set to -1 for hidden; 0 for unpinned, and > 0 for
/// higher priority in the conversation list.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_nts_priority(
///     [in]    config_object*      conf,
///     [in]    int                 priority
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `priority` -- [in] Integer of the priority
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void user_profile_set_nts_priority(config_object* conf, int priority);

/// API: user_profile/user_profile_get_nts_expiry
///
/// Gets the Note-to-self message expiry timer (seconds).  Returns 0 if not set.
///
/// Declaration:
/// ```cpp
/// INT user_profile_get_nts_expiry(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- Returns the expiry timer in seconds. Returns 0 if not set
LIBSESSION_EXPORT int user_profile_get_nts_expiry(const config_object* conf);

/// API: user_profile/user_profile_set_nts_expiry
///
/// Sets the Note-to-self message expiry timer (seconds).  Setting 0 (or negative) will clear the
/// current timer.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_nts_expiry(
///     [in]    config_object*      conf,
///     [in]    int                 expiry
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `expiry` -- [in] Integer of the expiry timer in seconds
LIBSESSION_EXPORT void user_profile_set_nts_expiry(config_object* conf, int expiry);

/// API: user_profile/user_profile_get_blinded_msgreqs
///
/// Returns true if blinded message requests should be retrieved (from SOGS servers), false if they
/// should be ignored.
///
/// Declaration:
/// ```cpp
/// INT user_profile_get_blinded_msgreqs(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- Will be -1 if the config does not have the value explicitly set, 0 if the setting is
///   explicitly disabled, and 1 if the setting is explicitly enabled.
LIBSESSION_EXPORT int user_profile_get_blinded_msgreqs(const config_object* conf);

/// API: user_profile/user_profile_set_blinded_msgreqs
///
/// Sets whether blinded message requests should be retrieved from SOGS servers.  Set to 1 (or any
/// positive value) to enable; 0 to disable; and -1 to clear the setting.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_blinded_msgreqs(
///     [in]    config_object*      conf,
///     [in]    int                 enabled
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `enabled` -- [in] true if they should be enabled, false if disabled
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void user_profile_set_blinded_msgreqs(config_object* conf, int enabled);

/// API: user_profile/user_profile_get_profile_updated
///
/// Returns the timestamp that the user last updated their profile information; or `0` if it's
/// never been updated.  This value will return the latest timestamp between when the user last
/// set their profile and when it was last re-uploaded.
///
/// Inputs: None
///
/// Outputs:
/// - `int64_t` - timestamp (unix seconds) that the user last updated their public profile
/// information.  Will be `0` if it's never been updated.
LIBSESSION_EXPORT int64_t user_profile_get_profile_updated(config_object* conf);

/// API: user_profile/user_profile_get_pro_config
///
/// Get the Pro data for the user profile if it exists which includes the users rotating private key
/// and their last authorised proof.
///
/// Declaration:
/// ```cpp
/// BOOL user_profile_get_pro_config(
///     [in]    const config_object* conf
///     [out]   pro_pro*             pro
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pro` -- [out] Pointer to the pro object where the retrieved details are written
///
/// Outputs:
/// - `bool` -- True if the user profile had Pro data associated with it. Otherwise false and the
///   pro structure will remain untouched.
LIBSESSION_EXPORT bool user_profile_get_pro_config(const config_object* conf, pro_pro_config* pro);

/// API: user_profile/user_profile_set_pro_config
///
/// Update the pro data associated with the user profile.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_pro_config(
///     [in]    config_object* conf,
///     [in]    pro_pro*       pro
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pro` -- [in] Pointer to the Pro data to write to the user profile
///
/// Outputs:
/// - `void` -- Returns nothing
LIBSESSION_EXPORT void user_profile_set_pro_config(config_object* conf, const pro_pro_config* pro);

/// API: user_profile/user_profile_remove_pro_config
///
/// Remove the Session Pro components from the user profile.
///
/// Declaration:
/// ```cpp
/// BOOL user_profile_remove_pro_config(
///     [in]    config_object* conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `bool` - A flag indicating whether the config had Session Pro components which were removed.
LIBSESSION_EXPORT bool user_profile_remove_pro_config(config_object* conf);

/// API: user_profile/user_profile_get_pro_features
///
/// Retrieves the bitset indicating which pro features the user currently has enabled.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `session_protocol_pro_profile_bitset` - bitset indicating which profile features are enabled.
LIBSESSION_EXPORT session_protocol_pro_profile_bitset
user_profile_get_pro_features(const config_object* conf);

/// API: user_profile/user_profile_set_pro_badge
///
/// Updates the bitset to specify whether the user wants their profile to show the pro badge.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `enabled` -- Flag which specifies whether the user wants the pro badge to appear on their
/// profile or not.
LIBSESSION_EXPORT void user_profile_set_pro_badge(config_object* conf, bool enabled);

/// API: user_profile/user_profile_set_animated_avatar
///
/// Updates the bitset to specify whether the user has an animated profile picture, should be
/// set when uploading a profile picture. Note: This doesn't prevent a users profile picture
/// from animating, it's just a way to more easily synchronise the state between devices when
/// sending messages so we don't need the device to have successfully download the current
/// display picture in order to be able to determine this.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `enabled` -- Flag which specifies whether the users display picture is animated or not.
LIBSESSION_EXPORT void user_profile_set_animated_avatar(config_object* conf, bool enabled);

/// API: user_profile/user_profile_get_pro_access_expiry_ms
///
/// Retrieves the Session Pro access expiry unix timestamp if it has been set, this should generally
/// be the expiry value returned from /get_pro_details.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `uint64_t` - The unix timestamp in milliseconds that the users pro access will expire, or 0 if
/// unset.
LIBSESSION_EXPORT uint64_t user_profile_get_pro_access_expiry_ms(const config_object* conf);

/// API: user_profile/user_profile_set_pro_access_expiry_ms
///
/// Updates the Session Pro access expiry unix timestamp.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `access_expiry_ts_ms` -- The timestamp that the users Session Pro access will expire, or 0 to
/// remove the value.
LIBSESSION_EXPORT void user_profile_set_pro_access_expiry_ms(
        config_object* conf, uint64_t access_expiry_ts_ms);

#ifdef __cplusplus
}  // extern "C"
#endif
