CREATE TABLE namespace_sync (
    namespace INTEGER PRIMARY KEY NOT NULL,
    last_hash TEXT NOT NULL
) STRICT;
