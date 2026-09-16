ALTER TABLE message_attachments ADD COLUMN unavailable INTEGER NOT NULL DEFAULT 0;
CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;
