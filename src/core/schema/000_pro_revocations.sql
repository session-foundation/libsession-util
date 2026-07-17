CREATE TABLE pro_revocations (
    revocation_tag BLOB PRIMARY KEY NOT NULL,
    effective_ts INTEGER NOT NULL,  -- unix seconds; a matching proof is revoked once the clock reaches this
    seen_at INTEGER NOT NULL        -- unix seconds when last seen in a fetched list (for retain_for aging)
) STRICT
