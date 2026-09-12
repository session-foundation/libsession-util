-- The schema produced by every migration in this directory, used to build a fresh database in one
-- step.  ext_ordering is the interesting one: the chain reaches it as a CREATE plus a later ALTER,
-- so the stored DDL text differs from this even though the schema does not -- which is what the
-- drift test in test_core_schema.cpp compares structurally rather than textually.
CREATE TABLE ext_thing (
    id INTEGER PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE ext_globals (
    id INTEGER PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE ext_ordering (
    id INTEGER PRIMARY KEY NOT NULL,
    added_later INTEGER
) STRICT;
