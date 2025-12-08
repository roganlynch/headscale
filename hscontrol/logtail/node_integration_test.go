package logtail

import (
	"context"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func TestDeriveLogPrivateIDFromNode(t *testing.T) {
	// Create test node with machine key
	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	privateID := DeriveLogPrivateIDFromNode(node)

	assert.NotEmpty(t, privateID)
	assert.Contains(t, privateID, "logtail-")
	assert.Len(t, privateID, 40) // "logtail-" + 32 hex chars

	// Verify deterministic - same node produces same ID
	privateID2 := DeriveLogPrivateIDFromNode(node)
	assert.Equal(t, privateID, privateID2)
}

func TestDeriveLogPrivateIDFromNode_DifferentNodes(t *testing.T) {
	node1 := &types.Node{
		ID:         1,
		MachineKey: key.NewMachine().Public(),
	}

	node2 := &types.Node{
		ID:         2,
		MachineKey: key.NewMachine().Public(),
	}

	privateID1 := DeriveLogPrivateIDFromNode(node1)
	privateID2 := DeriveLogPrivateIDFromNode(node2)

	assert.NotEqual(t, privateID1, privateID2, "different nodes should have different private IDs")
}

func TestDeriveLogPrivateIDFromNode_NilNode(t *testing.T) {
	privateID := DeriveLogPrivateIDFromNode(nil)
	assert.Empty(t, privateID)
}

func TestDeriveLogPrivateIDFromNode_EmptyMachineKey(t *testing.T) {
	node := &types.Node{
		ID:       1,
		Hostname: "test-node",
		// MachineKey is zero value
	}

	privateID := DeriveLogPrivateIDFromNode(node)
	// Note: Zero value MachineKey still produces a valid string representation
	// so it creates a private ID. Only nil node or truly empty string returns empty.
	assert.NotEmpty(t, privateID)
}

func TestAssociateNodeWithLogtail_NewNode(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	clientIP := "10.0.0.1"

	err := service.AssociateNodeWithLogtail(node, clientIP)
	require.NoError(t, err)

	// Verify association created
	privateID := DeriveLogPrivateIDFromNode(node)
	association, err := service.storage.GetPrivateIDAssociation(ctx, privateID)
	require.NoError(t, err)
	assert.NotNil(t, association)
	assert.Equal(t, uint64(node.ID), association.NodeID)
	assert.Equal(t, clientIP, association.CurrentIP)
	assert.Contains(t, association.RecentIPs, clientIP)
}

func TestAssociateNodeWithLogtail_WithGracePeriodLogs(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	privateID := DeriveLogPrivateIDFromNode(node)

	// Create some grace period logs
	graceLogs := []LogEntry{
		{
			Collection: DefaultCollection,
			PrivateID:  privateID,
			PublicID:   "pub1",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"text":"startup log"}`),
			SizeBytes:  100,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := service.storage.StoreLogs(ctx, graceLogs)
	require.NoError(t, err)

	// Associate node
	err = service.AssociateNodeWithLogtail(node, "10.0.0.1")
	require.NoError(t, err)

	// Verify logs migrated to ephemeral tier
	logs, err := service.storage.QueryLogs(ctx, LogQuery{
		Collection: DefaultCollection,
		PrivateIDs: []string{privateID},
	})
	require.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, LogTierEphemeral, logs[0].LogTier)
}

func TestAssociateNodeWithLogtail_ReAuthentication_AlreadyPersisted(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	privateID := DeriveLogPrivateIDFromNode(node)

	// Create persisted logs (simulating previous session)
	persistedLogs := []LogEntry{
		{
			Collection: DefaultCollection,
			PrivateID:  privateID,
			PublicID:   "pub1",
			Timestamp:  time.Now().Add(-1 * time.Hour),
			LogData:    []byte(`{"text":"old log"}`),
			SizeBytes:  100,
			LogTier:    LogTierPersisted,
		},
	}
	err := service.storage.StoreLogs(ctx, persistedLogs)
	require.NoError(t, err)

	// Mark instance as persisted
	err = service.storage.UpdateInstancePersistence(ctx, privateID, DefaultCollection, true, 30)
	require.NoError(t, err)

	// Create new grace period logs (re-authentication startup)
	graceLogs := []LogEntry{
		{
			Collection: DefaultCollection,
			PrivateID:  privateID,
			PublicID:   "pub1",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"text":"restart log"}`),
			SizeBytes:  100,
			LogTier:    LogTierGracePeriod,
		},
	}
	err = service.storage.StoreLogs(ctx, graceLogs)
	require.NoError(t, err)

	// Re-associate node (simulating re-authentication)
	err = service.AssociateNodeWithLogtail(node, "10.0.0.1")
	require.NoError(t, err)

	// Verify new logs migrated to PERSISTED tier (not ephemeral)
	logs, err := service.storage.QueryLogs(ctx, LogQuery{
		Collection: DefaultCollection,
		PrivateIDs: []string{privateID},
	})
	require.NoError(t, err)

	// Should have 2 logs, both persisted
	assert.Len(t, logs, 2)
	for _, log := range logs {
		assert.Equal(t, LogTierPersisted, log.LogTier, "all logs should be persisted after re-auth")
	}
}

func TestDisassociateNodeFromLogtail(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	// Create association
	err := service.AssociateNodeWithLogtail(node, "10.0.0.1")
	require.NoError(t, err)

	privateID := DeriveLogPrivateIDFromNode(node)

	// Verify association exists
	association, err := service.storage.GetPrivateIDAssociation(ctx, privateID)
	require.NoError(t, err)
	assert.NotNil(t, association)

	// Disassociate
	err = service.DisassociateNodeFromLogtail(node)
	require.NoError(t, err)

	// Verify association deleted
	association, err = service.storage.GetPrivateIDAssociation(ctx, privateID)
	require.NoError(t, err)
	assert.Nil(t, association)
}

func TestGetNodeAssociations(t *testing.T) {
	service := setupTestServiceWithStorage(t)

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	// Create association
	err := service.AssociateNodeWithLogtail(node, "10.0.0.1")
	require.NoError(t, err)

	// Get associations for node
	associations, err := service.GetNodeAssociations(uint64(node.ID))
	require.NoError(t, err)
	assert.Len(t, associations, 1)
	assert.Equal(t, uint64(node.ID), associations[0].NodeID)
}

func TestMigrateGracePeriodLogsForNode_NoLogs(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	privateID := "test-private-id"

	// Should not error if no logs exist
	err := service.MigrateGracePeriodLogsForNode(ctx, privateID, DefaultCollection)
	assert.NoError(t, err)
}

func TestMigrateGracePeriodLogsForNode_ToEphemeral(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	privateID := "test-private-id"

	// Create grace period logs
	graceLogs := []LogEntry{
		{
			Collection: DefaultCollection,
			PrivateID:  privateID,
			PublicID:   "pub1",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"text":"test log"}`),
			SizeBytes:  100,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := service.storage.StoreLogs(ctx, graceLogs)
	require.NoError(t, err)

	// Migrate
	err = service.MigrateGracePeriodLogsForNode(ctx, privateID, DefaultCollection)
	require.NoError(t, err)

	// Verify logs migrated to ephemeral
	logs, err := service.storage.QueryLogs(ctx, LogQuery{
		Collection: DefaultCollection,
		PrivateIDs: []string{privateID},
	})
	require.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, LogTierEphemeral, logs[0].LogTier)
}

func TestMigrateGracePeriodLogsForNode_ToPersisted(t *testing.T) {
	service := setupTestServiceWithStorage(t)
	ctx := context.Background()

	privateID := "test-private-id"

	// Create initial persisted logs
	persistedLogs := []LogEntry{
		{
			Collection: DefaultCollection,
			PrivateID:  privateID,
			PublicID:   "pub1",
			Timestamp:  time.Now().Add(-1 * time.Hour),
			LogData:    []byte(`{"text":"old log"}`),
			SizeBytes:  100,
			LogTier:    LogTierPersisted,
		},
	}
	err := service.storage.StoreLogs(ctx, persistedLogs)
	require.NoError(t, err)

	// Mark instance as persisted
	err = service.storage.UpdateInstancePersistence(ctx, privateID, DefaultCollection, true, 30)
	require.NoError(t, err)

	// Create new grace period logs
	graceLogs := []LogEntry{
		{
			Collection: DefaultCollection,
			PrivateID:  privateID,
			PublicID:   "pub1",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"text":"new log"}`),
			SizeBytes:  100,
			LogTier:    LogTierGracePeriod,
		},
	}
	err = service.storage.StoreLogs(ctx, graceLogs)
	require.NoError(t, err)

	// Migrate
	err = service.MigrateGracePeriodLogsForNode(ctx, privateID, DefaultCollection)
	require.NoError(t, err)

	// Verify all logs are persisted
	logs, err := service.storage.QueryLogs(ctx, LogQuery{
		Collection: DefaultCollection,
		PrivateIDs: []string{privateID},
	})
	require.NoError(t, err)
	assert.Len(t, logs, 2)
	for _, log := range logs {
		assert.Equal(t, LogTierPersisted, log.LogTier)
	}
}

func TestAssociateNodeWithLogtail_DisabledService(t *testing.T) {
	// Create service with disabled config
	service := &LogtailService{
		config: types.LogTailServerConfig{
			Enabled: false,
		},
	}

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	// Should return nil without error
	err := service.AssociateNodeWithLogtail(node, "10.0.0.1")
	assert.NoError(t, err)
}

func TestDisassociateNodeFromLogtail_DisabledService(t *testing.T) {
	// Create service with disabled config
	service := &LogtailService{
		config: types.LogTailServerConfig{
			Enabled: false,
		},
	}

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	// Should return nil without error
	err := service.DisassociateNodeFromLogtail(node)
	assert.NoError(t, err)
}

func TestGetNodeAssociations_DisabledService(t *testing.T) {
	// Create service with disabled config
	service := &LogtailService{
		config: types.LogTailServerConfig{
			Enabled: false,
		},
	}

	// Should return nil without error
	associations, err := service.GetNodeAssociations(1)
	assert.NoError(t, err)
	assert.Nil(t, associations)
}

func TestInvalidateAllCachesForNode(t *testing.T) {
	service := setupTestServiceWithStorage(t)

	privateID := "test-private-id"

	// Populate caches
	service.cache.authCache.Store(privateID, &CachedAuthResult{
		Result:    AuthResult{Allowed: true},
		ExpiresAt: time.Now().Add(1 * time.Minute),
	})
	service.cache.firstSeen.Store(privateID, &FirstSeenRecord{
		PrivateID:   privateID,
		FirstSeenAt: time.Now(),
	})
	service.cache.recentIPs.Store(privateID, []string{"10.0.0.1"})
	service.cache.instanceTiers.Store(privateID+":"+DefaultCollection, LogTierEphemeral)

	// Invalidate all caches
	service.invalidateAllCachesForNode(privateID)

	// Verify caches cleared
	_, authExists := service.cache.authCache.Load(privateID)
	assert.False(t, authExists, "auth cache should be cleared")

	_, firstSeenExists := service.cache.firstSeen.Load(privateID)
	assert.False(t, firstSeenExists, "first seen cache should be cleared")

	_, recentIPsExists := service.cache.recentIPs.Load(privateID)
	assert.False(t, recentIPsExists, "recent IPs cache should be cleared")

	_, tierExists := service.cache.instanceTiers.Load(privateID + ":" + DefaultCollection)
	assert.False(t, tierExists, "instance tier cache should be cleared")
}

func TestCacheInvalidation_AfterAssociation(t *testing.T) {
	service := setupTestServiceWithStorage(t)

	machineKey := key.NewMachine().Public()
	node := &types.Node{
		ID:         1,
		Hostname:   "test-node",
		MachineKey: machineKey,
	}

	privateID := DeriveLogPrivateIDFromNode(node)

	// Populate caches before association
	service.cache.authCache.Store(privateID, &CachedAuthResult{
		Result:    AuthResult{Allowed: true, IsGracePeriod: true},
		ExpiresAt: time.Now().Add(1 * time.Minute),
	})

	// Associate node
	err := service.AssociateNodeWithLogtail(node, "10.0.0.1")
	require.NoError(t, err)

	// Verify auth cache cleared (grace period state no longer valid)
	_, authExists := service.cache.authCache.Load(privateID)
	assert.False(t, authExists, "auth cache should be cleared after association")
}

// Helper function to set up test service with storage
func setupTestServiceWithStorage(t *testing.T) *LogtailService {
	t.Helper()

	// Create in-memory storage for testing
	db := setupTestDB(t)

	// Create all necessary logtail tables
	err := db.Exec(`
		CREATE TABLE IF NOT EXISTS node_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			collection TEXT NOT NULL,
			private_id TEXT NOT NULL,
			public_id TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			log_data JSON NOT NULL,
			size_bytes INTEGER NOT NULL,
			log_tier TEXT NOT NULL DEFAULT 'ephemeral',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS log_instances (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			collection TEXT NOT NULL,
			private_id TEXT UNIQUE NOT NULL,
			public_id TEXT UNIQUE NOT NULL,
			persisted BOOLEAN DEFAULT FALSE,
			persisted_at DATETIME,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			total_logs INTEGER DEFAULT 0,
			total_size_bytes INTEGER DEFAULT 0,
			retention_days INTEGER,
			log_tier TEXT NOT NULL DEFAULT 'ephemeral',
			tier_transitioned_at DATETIME,
			UNIQUE(collection, private_id)
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_private_id_associations (
			private_id TEXT PRIMARY KEY,
			node_id INTEGER NOT NULL,
			collection TEXT NOT NULL,
			associated_at DATETIME NOT NULL,
			current_ip TEXT NOT NULL,
			last_ip_change DATETIME
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_ip_observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			private_id TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			observation_count INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(private_id, ip_address)
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS logtail_first_seen (
			private_id TEXT PRIMARY KEY,
			collection TEXT NOT NULL,
			first_seen_at DATETIME NOT NULL,
			first_seen_ip TEXT NOT NULL,
			request_count INTEGER DEFAULT 0
		)
	`).Error
	require.NoError(t, err)

	storage := NewDBStorage(db)

	config := types.LogTailServerConfig{
		Enabled: true,
		Retention: types.LogTailRetentionConfig{
			EphemeralMinutes:     720,
			PersistedDefaultDays: 30,
			CleanupIntervalHours: 1,
		},
		RateLimit: types.LogTailRateLimitConfig{
			RequestsPerMinute: 10,
		},
	}

	service := &LogtailService{
		storage: storage,
		cache:   NewLogtailCache(),
		config:  config,
	}

	return service
}
