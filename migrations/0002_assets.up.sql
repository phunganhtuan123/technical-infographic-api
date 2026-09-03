-- Files a diagram points at, kept out of the document.
--
-- The editor inlines background images as base64. Autosave then writes that
-- payload into projects.document and a row of project_versions every few
-- seconds, which is how a handful of photos turns into gigabytes of history.

CREATE TABLE assets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id  uuid REFERENCES projects(id) ON DELETE CASCADE,
    storage_key text NOT NULL UNIQUE,
    mime        text NOT NULL,
    bytes       bigint NOT NULL,
    checksum    bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX assets_owner_idx ON assets (owner_id);
CREATE INDEX assets_project_idx ON assets (project_id);
-- Same bytes uploaded twice can be spotted later and de-duplicated.
CREATE INDEX assets_checksum_idx ON assets (checksum);
