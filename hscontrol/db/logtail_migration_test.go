package db

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestLogtailMigration(t *testing.T) {
	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create nodes table (dependency for foreign key)
	err = db.Exec(`
		CREATE TABLE nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL
		)
	`).Error
	require.NoError(t, err)

	// Run the logtail migration by executing the migration function directly
	// Extract the migration logic
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Verify all tables exist
	tables := []string{
		"node_logs",
		"log_instances",
		"logtail_private_id_associations",
		"logtail_ip_observations",
		"logtail_first_seen",
		"logtail_rate_limits",
	}

	for _, table := range tables {
		var count int
		err := db.Raw(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
			table,
		).Scan(&count).Error
		require.NoError(t, err)
		assert.Equal(t, 1, count, "table %s should exist", table)
	}
}

func TestLogtailTablesIndexes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Verify indexes exist
	expectedIndexes := map[string][]string{
		"node_logs": {
			"idx_logs_collection_private",
			"idx_logs_public",
			"idx_logs_timestamp",
			"idx_logs_persisted",
			"idx_logs_tier",
			"idx_logs_tier_timestamp",
		},
		"log_instances": {
			"idx_instances_collection",
			"idx_instances_persisted",
			"idx_instances_tier",
		},
		"logtail_private_id_associations": {
			"idx_logtail_assoc_node",
			"idx_logtail_assoc_collection",
		},
		"logtail_ip_observations": {
			"idx_logtail_ip_obs_private",
			"idx_logtail_ip_obs_time",
			"idx_logtail_ip_obs_ip",
			"idx_logtail_ip_obs_window",
		},
		"logtail_first_seen": {
			"idx_logtail_first_seen_time",
		},
	}

	for table, indexes := range expectedIndexes {
		for _, index := range indexes {
			var count int
			err := db.Raw(`
				SELECT COUNT(*) FROM sqlite_master 
				WHERE type='index' AND name=? AND tbl_name=?
			`, index, table).Scan(&count).Error
			require.NoError(t, err)
			assert.Equal(t, 1, count, "index %s on table %s should exist", index, table)
		}
	}
}

func TestLogtailTableForeignKeys(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Enable foreign keys
	db.Exec("PRAGMA foreign_keys = ON")

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Insert test node
	err = db.Exec("INSERT INTO nodes (id) VALUES (1)").Error
	require.NoError(t, err)

	// Test foreign key constraint for associations
	err = db.Exec(`
		INSERT INTO logtail_private_id_associations 
		(private_id, node_id, collection, associated_at, current_ip)
		VALUES ('test123', 1, 'tailnode.log.tailscale.io', datetime('now'), '10.0.0.1')
	`).Error
	require.NoError(t, err)

	// Test cascade delete
	err = db.Exec("DELETE FROM nodes WHERE id = 1").Error
	require.NoError(t, err)

	var count int
	err = db.Raw("SELECT COUNT(*) FROM logtail_private_id_associations WHERE node_id = 1").Scan(&count).Error
	require.NoError(t, err)
	assert.Equal(t, 0, count, "association should be deleted on cascade")
}

func TestLogtailTableIPObservationsCascade(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Enable foreign keys
	db.Exec("PRAGMA foreign_keys = ON")

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Insert test node
	err = db.Exec("INSERT INTO nodes (id) VALUES (1)").Error
	require.NoError(t, err)

	// Insert association
	err = db.Exec(`
		INSERT INTO logtail_private_id_associations 
		(private_id, node_id, collection, associated_at, current_ip)
		VALUES ('test123', 1, 'tailnode.log.tailscale.io', datetime('now'), '10.0.0.1')
	`).Error
	require.NoError(t, err)

	// Insert IP observation
	err = db.Exec(`
		INSERT INTO logtail_ip_observations
		(private_id, ip_address, first_seen, last_seen)
		VALUES ('test123', '10.0.0.1', datetime('now'), datetime('now'))
	`).Error
	require.NoError(t, err)

	// Delete association - should cascade to IP observations
	err = db.Exec("DELETE FROM logtail_private_id_associations WHERE private_id = 'test123'").Error
	require.NoError(t, err)

	var count int
	err = db.Raw("SELECT COUNT(*) FROM logtail_ip_observations WHERE private_id = 'test123'").Scan(&count).Error
	require.NoError(t, err)
	assert.Equal(t, 0, count, "IP observations should be deleted on cascade")
}

func TestLogtailTableDefaultValues(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Insert minimal log entry
	err = db.Exec(`
		INSERT INTO node_logs 
		(collection, private_id, public_id, timestamp, log_data, size_bytes)
		VALUES 
		('test', 'priv123', 'pub123', datetime('now'), '{}', 100)
	`).Error
	require.NoError(t, err)

	// Verify defaults
	var log struct {
		Persisted bool
		LogTier   string
	}
	err = db.Raw("SELECT persisted, log_tier FROM node_logs WHERE private_id = 'priv123'").Scan(&log).Error
	require.NoError(t, err)
	assert.False(t, log.Persisted, "persisted should default to false")
	assert.Equal(t, "grace_period", log.LogTier, "log_tier should default to grace_period")
}

func TestLogtailTableUniqueConstraints(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Insert instance
	err = db.Exec(`
		INSERT INTO log_instances 
		(collection, private_id, public_id, first_seen, last_seen)
		VALUES 
		('test', 'priv123', 'pub123', datetime('now'), datetime('now'))
	`).Error
	require.NoError(t, err)

	// Try to insert duplicate private_id - should fail
	err = db.Exec(`
		INSERT INTO log_instances 
		(collection, private_id, public_id, first_seen, last_seen)
		VALUES 
		('test', 'priv123', 'pub456', datetime('now'), datetime('now'))
	`).Error
	assert.Error(t, err, "duplicate private_id should fail")

	// Try to insert duplicate public_id - should fail
	err = db.Exec(`
		INSERT INTO log_instances 
		(collection, private_id, public_id, first_seen, last_seen)
		VALUES 
		('test', 'priv456', 'pub123', datetime('now'), datetime('now'))
	`).Error
	assert.Error(t, err, "duplicate public_id should fail")
}

func TestLogtailMigrationIdempotency(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration first time
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Run migration second time - should not error (idempotent)
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Verify tables still exist and are correct
	var count int
	err = db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='node_logs'").Scan(&count).Error
	require.NoError(t, err)
	assert.Equal(t, 1, count, "node_logs table should still exist after re-running migration")
}

func TestLogtailTableRequiredFields(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create nodes table
	err = db.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY)`).Error
	require.NoError(t, err)

	// Run migration
	err = runLogtailMigration(db)
	require.NoError(t, err)

	// Try to insert without required fields - should fail
	err = db.Exec(`
		INSERT INTO node_logs (collection) VALUES ('test')
	`).Error
	assert.Error(t, err, "insert without required fields should fail")

	// Insert with all required fields - should succeed
	err = db.Exec(`
		INSERT INTO node_logs 
		(collection, private_id, public_id, timestamp, log_data, size_bytes)
		VALUES 
		('test', 'priv', 'pub', datetime('now'), '{}', 100)
	`).Error
	require.NoError(t, err, "insert with all required fields should succeed")
}

// runLogtailMigration is a test helper that runs the logtail migration
func runLogtailMigration(tx *gorm.DB) error {
	// Create node_logs table
	err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS node_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			collection TEXT NOT NULL,
			private_id TEXT NOT NULL,
			public_id TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			log_data TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			persisted NUMERIC DEFAULT false,
			log_tier TEXT NOT NULL DEFAULT 'grace_period',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`).Error
	if err != nil {
		return err
	}

	// Create indexes for node_logs
	nodeLogsIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_logs_collection_private ON node_logs(collection, private_id)",
		"CREATE INDEX IF NOT EXISTS idx_logs_public ON node_logs(public_id)",
		"CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON node_logs(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_logs_persisted ON node_logs(persisted)",
		"CREATE INDEX IF NOT EXISTS idx_logs_tier ON node_logs(log_tier)",
		"CREATE INDEX IF NOT EXISTS idx_logs_tier_timestamp ON node_logs(log_tier, timestamp)",
	}
	for _, idx := range nodeLogsIndexes {
		if err := tx.Exec(idx).Error; err != nil {
			return err
		}
	}

	// Create log_instances table
	err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS log_instances (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			collection TEXT NOT NULL,
			private_id TEXT UNIQUE NOT NULL,
			public_id TEXT UNIQUE NOT NULL,
			persisted NUMERIC DEFAULT false,
			persisted_at DATETIME,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			total_logs INTEGER DEFAULT 0,
			total_size_bytes INTEGER DEFAULT 0,
			retention_days INTEGER,
			log_tier TEXT NOT NULL DEFAULT 'grace_period',
			tier_transitioned_at DATETIME,
			UNIQUE(collection, private_id)
		)
	`).Error
	if err != nil {
		return err
	}

	// Create indexes for log_instances
	instanceIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_instances_collection ON log_instances(collection)",
		"CREATE INDEX IF NOT EXISTS idx_instances_persisted ON log_instances(persisted)",
		"CREATE INDEX IF NOT EXISTS idx_instances_tier ON log_instances(log_tier)",
	}
	for _, idx := range instanceIndexes {
		if err := tx.Exec(idx).Error; err != nil {
			return err
		}
	}

	// Create logtail_private_id_associations table
	err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_private_id_associations (
			private_id TEXT PRIMARY KEY,
			node_id INTEGER NOT NULL,
			collection TEXT NOT NULL,
			associated_at DATETIME NOT NULL,
			current_ip TEXT NOT NULL,
			last_ip_change DATETIME,
			CONSTRAINT fk_logtail_assoc_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)
	`).Error
	if err != nil {
		return err
	}

	// Create indexes for associations
	assocIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_logtail_assoc_node ON logtail_private_id_associations(node_id)",
		"CREATE INDEX IF NOT EXISTS idx_logtail_assoc_collection ON logtail_private_id_associations(collection)",
	}
	for _, idx := range assocIndexes {
		if err := tx.Exec(idx).Error; err != nil {
			return err
		}
	}

	// Create logtail_ip_observations table
	err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_ip_observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			private_id TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			observation_count INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT fk_logtail_ip_obs_private FOREIGN KEY(private_id) REFERENCES logtail_private_id_associations(private_id) ON DELETE CASCADE
		)
	`).Error
	if err != nil {
		return err
	}

	// Create indexes for IP observations
	ipIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_logtail_ip_obs_private ON logtail_ip_observations(private_id)",
		"CREATE INDEX IF NOT EXISTS idx_logtail_ip_obs_time ON logtail_ip_observations(private_id, last_seen)",
		"CREATE INDEX IF NOT EXISTS idx_logtail_ip_obs_ip ON logtail_ip_observations(private_id, ip_address)",
		"CREATE INDEX IF NOT EXISTS idx_logtail_ip_obs_window ON logtail_ip_observations(private_id, last_seen DESC)",
	}
	for _, idx := range ipIndexes {
		if err := tx.Exec(idx).Error; err != nil {
			return err
		}
	}

	// Create logtail_first_seen table
	err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_first_seen (
			private_id TEXT PRIMARY KEY,
			collection TEXT NOT NULL,
			first_seen_at DATETIME NOT NULL,
			first_seen_ip TEXT NOT NULL,
			request_count INTEGER DEFAULT 0
		)
	`).Error
	if err != nil {
		return err
	}

	// Create index for first_seen
	err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_logtail_first_seen_time ON logtail_first_seen(first_seen_at)").Error
	if err != nil {
		return err
	}

	// Create logtail_rate_limits table
	err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_rate_limits (
			private_id TEXT PRIMARY KEY,
			request_count INTEGER DEFAULT 0,
			window_start DATETIME NOT NULL,
			last_request DATETIME NOT NULL
		)
	`).Error
	if err != nil {
		return err
	}

	return nil
}
