CREATE TABLE namespace_sync (
    namespace INTEGER NOT NULL,
    sn_pubkey BLOB NOT NULL CHECK(length(sn_pubkey) = 32),
    last_hash TEXT NOT NULL,
    PRIMARY KEY (namespace, sn_pubkey)
) STRICT;
