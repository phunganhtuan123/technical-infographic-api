DROP INDEX IF EXISTS users_disabled_at_idx;
DROP INDEX IF EXISTS users_admin_idx;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users
    DROP COLUMN IF EXISTS disabled_at,
    DROP COLUMN IF EXISTS role;
