-- Base migration for the prefix-ordering check; see 001_ordering+002.sql.
CREATE TABLE ext_ordering (
    id INTEGER PRIMARY KEY NOT NULL
) STRICT;
