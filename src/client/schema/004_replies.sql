ALTER TABLE messages ADD COLUMN reply_author INTEGER REFERENCES accounts(id);
ALTER TABLE messages ADD COLUMN reply_timestamp INTEGER;
ALTER TABLE messages ADD COLUMN reply_msgid INTEGER;

CREATE INDEX messages_reply_target ON messages(conversation, reply_author, reply_timestamp)
    WHERE reply_timestamp IS NOT NULL;
