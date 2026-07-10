#pragma once

namespace session::config {

enum class notify_mode {
    defaulted = 0,
    all = 1,
    disabled = 2,
    mentions_only = 3,  // Only for groups; for DMs this becomes `all`
};

enum class notify_content {
    defaulted = 0,
    name_and_preview = 1,
    name_no_preview = 2,
    no_name_no_preview = 3,
};

}  // namespace session::config
