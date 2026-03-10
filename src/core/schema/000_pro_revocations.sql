CREATE TABLE pro_revocations (
    gen_index_hash BLOB PRIMARY KEY NOT NULL,
    expiry_unix_ts_ms INTEGER NOT NULL
) STRICT
