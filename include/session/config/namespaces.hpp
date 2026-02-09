#pragma once

#include <cstdint>

#include "namespaces.h"

namespace session::config {

enum class Namespace : std::int16_t {
    RevokedRetrievableGroupMessages = NAMESPACE_REVOKED_RETRIEVABLE_GROUP_MESSAGES,

    // Messages sent to one-to-one conversations are stored in this namespace
    Default = NAMESPACE_DEFAULT,
    UserProfile = NAMESPACE_USER_PROFILE,
    Contacts = NAMESPACE_CONTACTS,
    ConvoInfoVolatile = NAMESPACE_CONVO_INFO_VOLATILE,
    UserGroups = NAMESPACE_USER_GROUPS,

    // Messages sent to a group:
    GroupMessages = NAMESPACE_GROUP_MESSAGES,
    // Groups config namespaces (i.e. for shared config of the group itself, not one user's group
    // settings)
    GroupKeys = NAMESPACE_GROUP_KEYS,
    GroupInfo = NAMESPACE_GROUP_INFO,
    GroupMembers = NAMESPACE_GROUP_MEMBERS,

    // The local config should never be pushed but this gives us a nice identifier for each config
    // type
    Local = NAMESPACE_LOCAL,
};

}  // namespace session::config
