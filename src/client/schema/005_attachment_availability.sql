-- Discards the cache rather than migrating it: it gains a surrogate key, which cannot be added in
-- place, and its files were named without the key that names them now.  The files left behind are
-- orphans the next sweep deletes, and everything in it can be fetched again.
DROP TABLE attachment_cache;

CREATE TABLE attachment_cache (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL
) STRICT;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);

ALTER TABLE message_attachments ADD COLUMN unavailable INTEGER;

ALTER TABLE message_attachments DROP COLUMN caption;

ALTER TABLE message_attachments
    ADD COLUMN cached INTEGER REFERENCES attachment_cache(id) ON DELETE SET NULL;

CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;

CREATE INDEX message_attachments_cached ON message_attachments(cached) WHERE cached IS NOT NULL;
