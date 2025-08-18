#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum NAMESPACE {
    // Messages sent to an updated group which should be able to be retrieved by revoked
    // members are stored in this namespace
    NAMESPACE_REVOKED_RETRIEVABLE_GROUP_MESSAGES = -11,

    // Messages sent to one-to-one conversations are stored in this namespace
    NAMESPACE_DEFAULT = 0,
    NAMESPACE_USER_PROFILE = 2,
    NAMESPACE_CONTACTS = 3,
    NAMESPACE_CONVO_INFO_VOLATILE = 4,
    NAMESPACE_USER_GROUPS = 5,

    // Messages sent to a group:
    NAMESPACE_GROUP_MESSAGES = 11,
    // Groups config namespaces (i.e. for shared config of the group itself, not one user's group
    // settings)
    NAMESPACE_GROUP_KEYS = 12,
    NAMESPACE_GROUP_INFO = 13,
    NAMESPACE_GROUP_MEMBERS = 14,

    // The local config should never be pushed but this gives us a nice identifier for each config
    // type
    NAMESPACE_LOCAL = 9999,
} NAMESPACE;

#ifdef __cplusplus
}  // extern "C"
#endif
