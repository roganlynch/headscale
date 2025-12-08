-- This file is the representation of the SQLite schema of Headscale.
-- It is the "source of truth" and is used to validate any migrations
-- that are run against the database to ensure it ends in the expected state.

CREATE TABLE migrations(id text,PRIMARY KEY(id));

CREATE TABLE users(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  display_name text,
  email text,
  provider_identifier text,
  provider text,
  profile_pic_url text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);


-- The following three UNIQUE indexes work together to enforce the user identity model:
--
-- 1. Users can be either local (provider_identifier is NULL) or from external providers (provider_identifier set)
-- 2. Each external provider identifier must be unique across the system
-- 3. Local usernames must be unique among local users
-- 4. The same username can exist across different providers with different identifiers
--
-- Examples:
-- - Can create local user "alice" (provider_identifier=NULL)
-- - Can create external user "alice" with GitHub (name="alice", provider_identifier="alice_github")
-- - Can create external user "alice" with Google (name="alice", provider_identifier="alice_google")
-- - Cannot create another local user "alice" (blocked by idx_name_no_provider_identifier)
-- - Cannot create another user with provider_identifier="alice_github" (blocked by idx_provider_identifier)
-- - Cannot create user "bob" with provider_identifier="alice_github" (blocked by idx_name_provider_identifier)
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;

CREATE TABLE pre_auth_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  key text,
  prefix text,
  hash blob,
  user_id integer,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  tags text,
  expiration datetime,

  created_at datetime,

  CONSTRAINT fk_pre_auth_keys_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != '';

CREATE TABLE api_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  expiration datetime,
  last_seen datetime,

  created_at datetime
);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);

CREATE TABLE nodes(
  id integer PRIMARY KEY AUTOINCREMENT,
  machine_key text,
  node_key text,
  disco_key text,

  endpoints text,
  host_info text,
  ipv4 text,
  ipv6 text,
  hostname text,
  given_name varchar(63),
  user_id integer,
  register_method text,
  tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime,

  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
);

CREATE TABLE policies(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime
);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);

-- Logtail tables for log collection and management
CREATE TABLE node_logs(
  id integer PRIMARY KEY AUTOINCREMENT,
  collection text NOT NULL,
  private_id text NOT NULL,
  public_id text NOT NULL,
  timestamp datetime NOT NULL,
  log_data text NOT NULL,
  size_bytes integer NOT NULL,
  persisted numeric DEFAULT false,
  log_tier text NOT NULL DEFAULT 'grace_period',

  created_at datetime DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_logs_collection_private ON node_logs(collection, private_id);
CREATE INDEX idx_logs_public ON node_logs(public_id);
CREATE INDEX idx_logs_timestamp ON node_logs(timestamp);
CREATE INDEX idx_logs_persisted ON node_logs(persisted);
CREATE INDEX idx_logs_tier ON node_logs(log_tier);
CREATE INDEX idx_logs_tier_timestamp ON node_logs(log_tier, timestamp);

CREATE TABLE log_instances(
  id integer PRIMARY KEY AUTOINCREMENT,
  collection text NOT NULL,
  private_id text UNIQUE NOT NULL,
  public_id text UNIQUE NOT NULL,
  persisted numeric DEFAULT false,
  persisted_at datetime,
  first_seen datetime NOT NULL,
  last_seen datetime NOT NULL,
  total_logs integer DEFAULT 0,
  total_size_bytes integer DEFAULT 0,
  retention_days integer,
  log_tier text NOT NULL DEFAULT 'grace_period',
  tier_transitioned_at datetime,

  UNIQUE(collection, private_id)
);
CREATE INDEX idx_instances_collection ON log_instances(collection);
CREATE INDEX idx_instances_persisted ON log_instances(persisted);
CREATE INDEX idx_instances_tier ON log_instances(log_tier);

CREATE TABLE logtail_private_id_associations(
  private_id text PRIMARY KEY,
  node_id integer NOT NULL,
  collection text NOT NULL,
  associated_at datetime NOT NULL,
  current_ip text NOT NULL,
  last_ip_change datetime,

  CONSTRAINT fk_logtail_assoc_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX idx_logtail_assoc_node ON logtail_private_id_associations(node_id);
CREATE INDEX idx_logtail_assoc_collection ON logtail_private_id_associations(collection);

CREATE TABLE logtail_ip_observations(
  id integer PRIMARY KEY AUTOINCREMENT,
  private_id text NOT NULL,
  ip_address text NOT NULL,
  first_seen datetime NOT NULL,
  last_seen datetime NOT NULL,
  observation_count integer DEFAULT 1,

  created_at datetime DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_logtail_ip_obs_private FOREIGN KEY(private_id) REFERENCES logtail_private_id_associations(private_id) ON DELETE CASCADE
);
CREATE INDEX idx_logtail_ip_obs_private ON logtail_ip_observations(private_id);
CREATE INDEX idx_logtail_ip_obs_time ON logtail_ip_observations(private_id, last_seen);
CREATE INDEX idx_logtail_ip_obs_ip ON logtail_ip_observations(private_id, ip_address);
CREATE INDEX idx_logtail_ip_obs_window ON logtail_ip_observations(private_id, last_seen DESC);

CREATE TABLE logtail_first_seen(
  private_id text PRIMARY KEY,
  collection text NOT NULL,
  first_seen_at datetime NOT NULL,
  first_seen_ip text NOT NULL,
  request_count integer DEFAULT 0
);
CREATE INDEX idx_logtail_first_seen_time ON logtail_first_seen(first_seen_at);

CREATE TABLE logtail_rate_limits(
  private_id text PRIMARY KEY,
  request_count integer DEFAULT 0,
  window_start datetime NOT NULL,
  last_request datetime NOT NULL
);
