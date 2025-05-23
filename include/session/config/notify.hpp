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

typedef enum notify_sound {
    defaulted = 0,
    none = 1,
    aurora = 2,
    bamboo = 3,
    chord = 4,
    circles = 5,
    complete = 6,
    hello = 7,
    input = 8,
    keys = 9,
    note = 10,
    popcorn = 11,
    pulse = 12,
    synth = 13,
};

}  // namespace session::config
