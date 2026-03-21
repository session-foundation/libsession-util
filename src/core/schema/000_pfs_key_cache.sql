-- Cache of remote account public keys (X25519 + ML-KEM-768) used for PFS+PQ message encryption.
-- Keys are considered fresh for PFS_KEY_FRESH_DURATION (24h) and expire after
-- PFS_KEY_EXPIRY_DURATION (48h); stale entries (24-48h old) are still usable as a fallback.
CREATE TABLE pfs_key_cache (
    session_id BLOB NOT NULL PRIMARY KEY CHECK(length(session_id) = 33),
    fetched_at INTEGER NOT NULL,  -- unix timestamp (seconds) of last successful fetch
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) = 32),
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) = 1184)
) STRICT;
