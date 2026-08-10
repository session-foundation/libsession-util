-- Conversation priority, mirroring the value the Contacts and UserGroups configs sync: 0 is
-- unpinned, a positive value is pinned with higher values sorting first, and a negative value is
-- hidden.  Kept numerically identical to the config so that reconciling one into the other is a
-- copy rather than a translation.
ALTER TABLE conversations ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- The conversation list orders by priority before recency, so it leads the index for the same
-- reason last_activity did on its own.
DROP INDEX conversations_activity;
CREATE INDEX conversations_order ON conversations(priority DESC, last_activity DESC);
