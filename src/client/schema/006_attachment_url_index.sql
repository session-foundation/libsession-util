-- Which messages show a given file.  Every question the attachment cache asks of this table is
-- that one -- reporting a transfer starting, finishing or being evicted -- and more than one
-- message routinely quotes the same file, because an attachment url is a hash of the encrypted
-- body: the same file sent twice by the same account lands at the same url.  Without this, each of
-- those answers scans the whole table to touch a handful of rows.
--
-- Partial because a row with no url has nothing to fetch and is never the subject of any of them:
-- an outgoing attachment before its upload finishes, which on a sending-heavy account is a large
-- share of the table.
CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;
