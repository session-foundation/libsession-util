CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;
