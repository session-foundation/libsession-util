CREATE TABLE pro_revocations (
    revocation_tag BLOB PRIMARY KEY NOT NULL,
    expiry_unix_ts_ms INTEGER NOT NULL
) STRICT
