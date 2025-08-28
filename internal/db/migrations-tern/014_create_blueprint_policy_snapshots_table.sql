CREATE TABLE IF NOT EXISTS blueprint_policy_snapshots
(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    blueprint_version_id uuid NOT NULL UNIQUE REFERENCES blueprint_versions(id) ON DELETE CASCADE,
    policy_id text NOT NULL,
    policy_blueprint_toml text NOT NULL,
    created_at timestamp NOT NULL DEFAULT current_timestamp,
    updated_at timestamp NOT NULL DEFAULT current_timestamp
);

CREATE INDEX IF NOT EXISTS idx_blueprint_policy_snapshots_blueprint_version_id
ON blueprint_policy_snapshots(blueprint_version_id);

CREATE INDEX IF NOT EXISTS idx_blueprint_policy_snapshots_policy_id
ON blueprint_policy_snapshots(policy_id);
