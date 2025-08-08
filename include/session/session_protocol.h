#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SESSION_PRO_10k_CHARACTER_LIMIT = 10'000,
};

typedef uint64_t session_pro_extra_features;
enum session_pro_extra_features_ {
    session_pro_extra_nil = 0,
    session_pro_extra_features_pro_badge = 0 << 1,
    session_pro_extra_features_animated_avatar = 1 << 1,
};

typedef uint64_t session_pro_features;
enum session_pro_features_ {
    session_pro_features_nil = 0,
    session_pro_features_10k_character_limit = 1 << 0,
    session_pro_features_pro_badge = 1 << 1,
    session_pro_features_animated_avatar = 1 << 2,
    session_pro_features_all = session_pro_features_10k_character_limit |
                               session_pro_features_pro_badge |
                               session_pro_features_animated_avatar,
};

#ifdef __cplusplus
}
#endif
