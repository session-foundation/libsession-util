CREATE TABLE swarm_nodes (
    id INTEGER PRIMARY KEY,
    pubkey BLOB NOT NULL UNIQUE CHECK(length(pubkey) = 32)
) STRICT;

CREATE TABLE swarm_hashes (
    id INTEGER PRIMARY KEY,
    namespace INTEGER NOT NULL,
    node INTEGER NOT NULL REFERENCES swarm_nodes(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    expiry INTEGER,
    UNIQUE(namespace, node, hash)
) STRICT;

CREATE INDEX swarm_hashes_cursor ON swarm_hashes(namespace, node, id DESC);

-- The cursors this replaces cannot be carried across: an entry is only usable if we know when the
-- server will drop it, and the old table never recorded that.  Inventing an expiry to preserve them
-- would put a guess into the one column whose whole meaning is a fact the server told us.  Losing
-- them costs one full retrieve per namespace per node, once, and everything in it dedupes.
DROP TABLE namespace_sync;
