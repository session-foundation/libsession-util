#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include "notify.h"
#include "theme.h"

/// API: local/local_init
///
/// Constructs a local config object and sets a pointer to it in `conf`.
///
/// When done with the object the `config_object` must be destroyed by passing the pointer to
/// config_free() (in `session/config/base.h`).
///
/// Declaration:
/// ```cpp
/// INT local_init(
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
LIBSESSION_EXPORT int local_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey,
        const unsigned char* dump,
        size_t dumplen,
        char* error) LIBSESSION_WARN_UNUSED;

/// API: local/local_get_notification_content
///
/// Returns the locally stored setting indicating what notification content should be displayed.
///
/// Declaration:
/// ```cpp
/// CLIENT_NOTIFY_CONTENT local_get_notification_content(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `CLIENT_NOTIFY_CONTENT` -- enum indicating the content that should be shown within a
/// notification.
LIBSESSION_EXPORT CLIENT_NOTIFY_CONTENT local_get_notification_content(const config_object* conf);

/// API: local/local_set_notification_content
///
/// Sets the setting indicating what notification content should be displayed.
///
/// Declaration:
/// ```cpp
/// void local_set_notification_content(
///     [in]    const config_object*    conf
///     [in[    CLIENT_NOTIFY_CONTENT   value
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `value` -- [in] Updated notification content setting
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void local_set_notification_content(
        config_object* conf, CLIENT_NOTIFY_CONTENT value);

/// API: local/local_get_ios_notification_sound
///
/// Returns the setting indicating which sound should play when receiving a notification on iOS.
///
/// Declaration:
/// ```cpp
/// CLIENT_NOTIFY_SOUND local_get_ios_notification_sound(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int64_t` -- enum indicating the sound that should be played when receiving a
/// notification on iOS.
LIBSESSION_EXPORT int64_t local_get_ios_notification_sound(const config_object* conf);

/// API: local/local_set_ios_notification_sound
///
/// Sets the setting indicating which sound should be played when receiving receiving a
/// notification on iOS.
///
/// Declaration:
/// ```cpp
/// void local_set_ios_notification_sound(
///     [in]    const config_object*    conf
///     [in[    int64_t                 value
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `value` -- [in] Updated notification sound setting
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void local_set_ios_notification_sound(config_object* conf, int64_t value);

/// API: local/local_get_theme
///
/// Returns the setting indicating which theme the client should use.
///
/// Declaration:
/// ```cpp
/// CLIENT_THEME local_get_theme(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `CLIENT_THEME` -- enum indicating which theme the client should use.
LIBSESSION_EXPORT CLIENT_THEME local_get_theme(const config_object* conf);

/// API: local/local_set_theme
///
/// Sets the setting indicating which theme the client should use.
///
/// Declaration:
/// ```cpp
/// void local_set_theme(
///     [in]    const config_object*    conf
///     [in[    CLIENT_THEME   value
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `value` -- [in] Updated theme setting
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void local_set_theme(config_object* conf, CLIENT_THEME value);

/// API: local/local_get_theme_primary_color
///
/// Returns the setting indicating which primary color the client should use.
///
/// Declaration:
/// ```cpp
/// CLIENT_THEME_PRIMARY_COLOR local_get_theme_primary_color(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `CLIENT_THEME` -- enum indicating which primary color the client should use.
LIBSESSION_EXPORT CLIENT_THEME_PRIMARY_COLOR
local_get_theme_primary_color(const config_object* conf);

/// API: local/local_set_theme_primary_color
///
/// Sets the setting indicating which primary color the client should use.
///
/// Declaration:
/// ```cpp
/// void local_set_theme_primary_color(
///     [in]    const config_object*    conf
///     [in[    CLIENT_THEME_PRIMARY_COLOR   value
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `value` -- [in] Updated primary color setting
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void local_set_theme_primary_color(
        config_object* conf, CLIENT_THEME_PRIMARY_COLOR value);

/// API: local/local_get_setting
///
/// Returns the setting for the provided key.
///
/// Declaration:
/// ```cpp
/// INT local_get_setting(
///     [in]    const config_object*    conf,
///     [in]    const char*             key
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `key` -- [in] Pointer to the key as a null-terminated C string
///
/// Outputs:
/// - `int` -- Will be -1 if the config does not have the value explicitly set, 0 if the setting is
///   explicitly disabled, and 1 if the setting is explicitly enabled.
LIBSESSION_EXPORT int local_get_setting(const config_object* conf, const char* key);

/// API: local/local_set_setting
///
/// Sets a setting for the provided key.
///
/// Declaration:
/// ```cpp
/// VOID local_set_setting(
///     [in]    config_object*      conf,
///     [in]    const char*         key,
///     [in]    int                 enabled
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `key` -- [in] Pointer to the key as a null-terminated C string
/// - `enabled` -- [in] the value which should be stored
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void local_set_setting(config_object* conf, const char* key, int enabled);

/// API: local/local_size_settings
///
/// Returns the number of settings.
///
/// Declaration:
/// ```cpp
/// SIZE_T local_size_settings(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to config_object object
///
/// Outputs:
/// - `size_t` -- Returns the number of settings
LIBSESSION_EXPORT size_t local_size_settings(const config_object* conf);

#ifdef __cplusplus
}  // extern "C"
#endif
