-- A one-to-one message is stored on both participants' swarms, so an outgoing message is two
-- independent sends: one to the recipient, and one to our own swarm so that our other devices see
-- it.  They succeed, fail and are retried separately, so one column cannot describe both.
--
-- send_state keeps its meaning -- the copy going to the recipient -- and NULL continues to mean
-- "there is no such send": on an incoming message, and on the sync copy of a note to self, where
-- the recipient's swarm *is* our own and a second store would be the same store twice.
ALTER TABLE messages ADD COLUMN sync_send_state INTEGER;
