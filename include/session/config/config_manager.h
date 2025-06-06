#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../config.h"
#include "../export.h"
#include "base.h"
#include "notify.h"
#include "groups/keys.h"

// Config manager base type: this type holds the internal object and is initialized by the various
// config-dependent settings (e.g. config_manager_init) then passed to the various functions.
typedef struct config_manager {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} config_manager;

typedef enum CONVERSATION_TYPE {
    CONVERSATION_TYPE_ONE_TO_ONE = 0,
    CONVERSATION_TYPE_COMMUNITY = 1,
    CONVERSATION_TYPE_GROUP = 2,
    CONVERSATION_TYPE_LEGACY_GROUP = 100,
} CONVERSATION_TYPE;

typedef struct config_convo {
    char id[409];  // needs to be large enough to fit a full community url (base_url: 267, '/': 1, room: 64, '?public_key=': 12, pubkey_hex: 64, null terminator: 1 ) with null terminator.
    CONVERSATION_TYPE type;
    char name[101];

    //     display_pic pic; // TODO: Need to add a C API version

    int64_t first_active;   // ms since unix epoch
    int64_t last_active;    // ms since unix epoch
    int priority;
    CONVO_NOTIFY_MODE notifications;
    int64_t mute_until;

    union {
        struct {
            bool is_message_request;
            bool is_blocked;
        } one_to_one;

        struct {
            bool read;
            bool write;
            bool upload;
        } community;

        struct {
            bool is_message_request;
        } group;
    } specific_data;
} config_convo;

/// API: config_manager/config_manager_init
///
/// Constructs a config manager object and sets a pointer to it in `manager`.
///
/// When done with the object the `config_manager` must be destroyed by passing the pointer to
/// config_manager_free().
///
/// Declaration:
/// ```cpp
/// BOOL config_manager_init(
///     [out]   config_manager**        manager,
///     [in]    const unsigned char*    ed25519_secretkey,
///     [out]   char*                   error
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [out] Pointer to the config object
/// - `ed25519_secretkey` -- [in] must be the 32-byte secret key seed value.  (You can also pass the
/// pointer to the beginning of the 64-byte value libsodium calls the "secret key" as the first 32
/// bytes of that are the seed).  This field cannot be null.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- Returns true on success; returns false and writes the exception message as a
/// C-string into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool config_manager_init(
        config_manager** manager, const unsigned char* ed25519_secretkey_bytes, char* error);

/// API: base/config_manager_free
///
/// Frees a config manager object created with config_manager_init.  This will also free any configs
/// the manager is storing so any previously returned `config_object` or `config_group_keys` will be
/// invalid once this is called.
///
/// Declaration:
/// ```cpp
/// VOID config_free(
///     [in, out]   config_manager*      manager
/// );
/// ```
///
/// Inputs:
/// - `manager` -- [in] Pointer to config_manager object
LIBSESSION_EXPORT void config_manager_free(config_manager* manager);

LIBSESSION_EXPORT bool config_manager_load(
    config_manager* manager,
    int16_t namespace_,
    const char* group_ed25519_pubkey,
    const unsigned char* dump,
    size_t dumplen,
    char* error);

LIBSESSION_EXPORT bool config_manager_get_config(
    config_manager* manager,
    const uint16_t namespace_,
    const char* pubkey_hex,
    config_object** config,
    char* error);

LIBSESSION_EXPORT bool config_manager_get_keys_config(
    config_manager* manager,
    const char* pubkey_hex,
    config_group_keys** config,
    char* error);

LIBSESSION_EXPORT void config_manager_free_config(config_object* config);
LIBSESSION_EXPORT void config_manager_free_keys_config(config_group_keys* config);

LIBSESSION_EXPORT bool config_manager_get_conversations(
    const config_manager* manager,
    config_convo** conversations,
    size_t* conversations_len,
    char* error);

#ifdef __cplusplus
}  // extern "C"
#endif
