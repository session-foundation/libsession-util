-- Addendum to 001_ordering.sql, exercising the branch workflow: iterate with `+NNN` files, then
-- squash them into the base before merging.
--
-- The name is deliberately one where '+' (0x2B) sorts below '.' (0x2E), so sorting by *filename*
-- would run this before the table it alters exists and the migration would fail outright.  That
-- makes this file the regression test for ordering by migration name instead.
ALTER TABLE ext_ordering ADD COLUMN added_later INTEGER;
