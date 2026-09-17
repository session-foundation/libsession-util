-- Link an attachment to its cached copy, instead of recomputing which file that is.
--
-- The cached file's name is a keyed hash of its url, so until now "is this file here" was answered
-- by hashing the url and looking the result up.  That made the hash load-bearing for every existing
-- entry rather than only for the ones being written: when the naming changed, the only migration
-- available was to throw the whole cache away, which is exactly what 005 did.  A stored link is
-- read rather than recomputed, so a future change to the naming costs nothing already downloaded.
--
-- It also answers the question the hash cannot.  Eviction holds a file's name and needs the
-- messages showing it, and a keyed hash does not run backwards: finding them meant hashing every
-- url in the table.  So eviction could not report itself, and a conversation went on drawing
-- pictures whose files had been deleted underneath it.  Now the rows come off an index, and the
-- foreign key un-marks them on the way out whether or not anyone remembered to.
--
-- Dropped and recreated rather than migrated: the cache is disposable by construction, the files
-- left behind become orphans that the reconcile sweep removes, and a surrogate key cannot be added
-- to an existing table without rebuilding it anyway.
DROP TABLE attachment_cache;

CREATE TABLE attachment_cache (
    -- Surrogate, so that what an attachment row stores is an integer rather than a second copy of
    -- the name -- and so that the name is free to change shape later without the references to it
    -- meaning anything different.
    id INTEGER PRIMARY KEY,
    -- The file on disk, and deliberately not the url: someone reading the cache directory should
    -- not be able to tell which files this account has fetched.
    name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL      -- ms since epoch
) STRICT;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);

-- NULL means no local copy, which is also what eviction leaves behind: ON DELETE SET NULL is what
-- makes "this row says cached" and "that file exists" impossible to disagree in the direction that
-- matters, since the only way to be marked is to reference a living row.
--
-- The other direction is still possible -- a row naming a file something outside us deleted -- and
-- is what the reconcile sweep is for.
ALTER TABLE message_attachments
    ADD COLUMN cached INTEGER REFERENCES attachment_cache(id) ON DELETE SET NULL;

-- Which messages show a file that is being evicted.  Partial for the same reason the url index is:
-- most rows are not cached at any given moment, and those are never the subject of this question.
CREATE INDEX message_attachments_cached ON message_attachments(cached) WHERE cached IS NOT NULL;
