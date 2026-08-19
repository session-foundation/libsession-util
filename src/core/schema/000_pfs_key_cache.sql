-- Cache of remote account public keys (X25519 + ML-KEM-768) used for PFS+PQ message encryption.
-- Keys are considered fresh for PFS_KEY_FRESH_DURATION (24h) and expire after
-- PFS_KEY_EXPIRY_DURATION (48h); stale entries (24-48h old) are still usable as a fallback.
--
-- nak_at is set whenever a successful fetch returns no valid keys, and is never cleared.  It
-- suppresses re-fetching for PFS_KEY_NAK_DURATION (1h) when no valid keys exist.  When valid
-- keys are present nak_at may coexist with them (the keys are still usable as a fallback).
-- In SQLite, CHECK constraints with a NULL argument evaluate to NULL (not FALSE), so the length
-- checks do not reject NULL pubkeys.
CREATE TABLE pfs_key_cache (
    session_id BLOB NOT NULL PRIMARY KEY CHECK(length(session_id) = 33),
    fetched_at INTEGER,           -- unix timestamp (seconds) of last fetch with valid keys; NULL if none
    nak_at INTEGER,               -- unix timestamp of last fetch returning no keys; NULL if none
    pubkey_x25519 BLOB CHECK(length(pubkey_x25519) = 32),
    pubkey_mlkem768 BLOB CHECK(length(pubkey_mlkem768) = 1184)
) STRICT;
