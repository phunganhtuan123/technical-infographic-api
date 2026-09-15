-- Administration: who may manage accounts, and which accounts are suspended.
--
-- Both columns live on users rather than in a side table. A role is a property
-- of the account, not a relationship, and every sign-in has to read the
-- suspension flag anyway — a join on the hot path to answer "may this person
-- still use the service" would be the wrong trade.

ALTER TABLE users
    ADD COLUMN role        text NOT NULL DEFAULT 'user',
    ADD COLUMN disabled_at timestamptz;

-- A typo in a role string is an authorisation bug that shows up as a silent
-- loss of access, so the database refuses one rather than storing it.
ALTER TABLE users
    ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));

-- Partial: the admin list is short and read on every boot to check that at
-- least one survives. Indexing the whole column would be pages of 'user'.
CREATE INDEX users_admin_idx ON users (id) WHERE role = 'admin' AND deleted_at IS NULL;
CREATE INDEX users_disabled_at_idx ON users (disabled_at) WHERE disabled_at IS NOT NULL;
