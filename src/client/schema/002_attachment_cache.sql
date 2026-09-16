CREATE TABLE attachment_cache (
    name TEXT PRIMARY KEY NOT NULL,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL
) STRICT;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);
