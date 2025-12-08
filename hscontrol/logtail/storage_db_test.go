package logtail

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupStorageTestDB creates an in-memory SQLite database with all tables
func setupStorageTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create all tables
	err = db.Exec(`
		CREATE TABLE node_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			collection TEXT NOT NULL,
			private_id TEXT NOT NULL,
			public_id TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			log_data BLOB NOT NULL,
			size_bytes INTEGER NOT NULL,
			log_tier TEXT NOT NULL,
			created_at DATETIME NOT NULL
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE log_instances (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			collection TEXT NOT NULL,
			private_id TEXT NOT NULL,
			public_id TEXT NOT NULL,
			persisted BOOLEAN DEFAULT FALSE,
			persisted_at DATETIME,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			total_logs INTEGER DEFAULT 0,
			total_size_bytes INTEGER DEFAULT 0,
			retention_days INTEGER,
			log_tier TEXT NOT NULL,
			tier_transitioned_at DATETIME,
			UNIQUE(private_id, collection)
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE logtail_private_id_associations (
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
		CREATE TABLE logtail_first_seen (
			private_id TEXT PRIMARY KEY,
			collection TEXT NOT NULL,
			first_seen_at DATETIME NOT NULL,
			first_seen_ip TEXT NOT NULL,
			request_count INTEGER DEFAULT 0
		)
	`).Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE logtail_ip_observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			private_id TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			observation_count INTEGER DEFAULT 0,
			created_at DATETIME NOT NULL,
			UNIQUE(private_id, ip_address)
		)
	`).Error
	require.NoError(t, err)

	return db
}

func TestStoreLogs(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"test log 1"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now().Add(1 * time.Second),
			LogData:    []byte(`{"msg":"test log 2"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := storage.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Verify logs were stored
	var count int64
	err = db.Raw("SELECT COUNT(*) FROM node_logs").Scan(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Verify instance was created
	instance, err := storage.GetLogInstance(ctx, "test-private-id", "test-collection")
	require.NoError(t, err)
	require.NotNil(t, instance)
	assert.Equal(t, "test-private-id", instance.PrivateID)
	assert.Equal(t, 2, instance.TotalLogs)
	assert.Equal(t, int64(40), instance.TotalSizeBytes)
	assert.Equal(t, LogTierGracePeriod, instance.LogTier)
}

func TestStoreLogs_UpdatesExistingInstance(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Store first batch
	logs1 := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"log 1"}`),
			SizeBytes:  15,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := storage.StoreLogs(ctx, logs1)
	require.NoError(t, err)

	// Store second batch
	logs2 := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now().Add(1 * time.Second),
			LogData:    []byte(`{"msg":"log 2"}`),
			SizeBytes:  15,
			LogTier:    LogTierGracePeriod,
		},
	}
	err = storage.StoreLogs(ctx, logs2)
	require.NoError(t, err)

	// Verify instance was updated, not duplicated
	instance, err := storage.GetLogInstance(ctx, "test-private-id", "test-collection")
	require.NoError(t, err)
	require.NotNil(t, instance)
	assert.Equal(t, 2, instance.TotalLogs)
	assert.Equal(t, int64(30), instance.TotalSizeBytes)
}

func TestQueryLogs(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Store test logs
	now := time.Now()
	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "private-1",
			PublicID:   "public-1",
			Timestamp:  now,
			LogData:    []byte(`{"msg":"log 1"}`),
			SizeBytes:  15,
			LogTier:    LogTierGracePeriod,
		},
		{
			Collection: "test-collection",
			PrivateID:  "private-2",
			PublicID:   "public-2",
			Timestamp:  now.Add(1 * time.Second),
			LogData:    []byte(`{"msg":"log 2"}`),
			SizeBytes:  15,
			LogTier:    LogTierEphemeral,
		},
	}
	err := storage.StoreLogs(ctx, logs)
	require.NoError(t, err)

	t.Run("query all logs in collection", func(t *testing.T) {
		results, err := storage.QueryLogs(ctx, LogQuery{
			Collection: "test-collection",
		})
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("query by private ID", func(t *testing.T) {
		results, err := storage.QueryLogs(ctx, LogQuery{
			Collection: "test-collection",
			PrivateIDs: []string{"private-1"},
		})
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "private-1", results[0].PrivateID)
	})

	t.Run("query by tier", func(t *testing.T) {
		tier := LogTierGracePeriod
		results, err := storage.QueryLogs(ctx, LogQuery{
			Collection: "test-collection",
			Tier:       &tier,
		})
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, LogTierGracePeriod, results[0].LogTier)
	})

	t.Run("query with max count", func(t *testing.T) {
		results, err := storage.QueryLogs(ctx, LogQuery{
			Collection: "test-collection",
			MaxCount:   1,
		})
		require.NoError(t, err)
		assert.Len(t, results, 1)
	})
}

func TestMigrateLogTier(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Store logs in grace period tier
	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"log 1"}`),
			SizeBytes:  15,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := storage.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Migrate to ephemeral
	err = storage.MigrateLogTier(ctx, "test-private-id", "test-collection", LogTierGracePeriod, LogTierEphemeral)
	require.NoError(t, err)

	// Verify logs were migrated
	tier := LogTierEphemeral
	results, err := storage.QueryLogs(ctx, LogQuery{
		Collection: "test-collection",
		Tier:       &tier,
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, LogTierEphemeral, results[0].LogTier)

	// Verify instance tier was updated
	instance, err := storage.GetLogInstance(ctx, "test-private-id", "test-collection")
	require.NoError(t, err)
	assert.Equal(t, LogTierEphemeral, instance.LogTier)
	assert.NotNil(t, instance.TierTransitionedAt)
}

func TestUpdateInstancePersistence(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Create instance
	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"log 1"}`),
			SizeBytes:  15,
			LogTier:    LogTierEphemeral,
		},
	}
	err := storage.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Mark as persisted
	err = storage.UpdateInstancePersistence(ctx, "test-private-id", "test-collection", true, 90)
	require.NoError(t, err)

	// Verify persistence
	instance, err := storage.GetLogInstance(ctx, "test-private-id", "test-collection")
	require.NoError(t, err)
	assert.True(t, instance.Persisted)
	assert.Equal(t, 90, instance.RetentionDays)
	assert.Equal(t, LogTierPersisted, instance.LogTier)
	assert.NotEqual(t, time.Time{}, instance.PersistedAt)
}

func TestPrivateIDAssociation(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	assoc := &PrivateIDAssociation{
		PrivateID:  "test-private-id",
		NodeID:     12345,
		Collection: "test-collection",
		CurrentIP:  "10.0.0.1",
		RecentIPs:  []string{"10.0.0.1"},
	}

	t.Run("store association", func(t *testing.T) {
		err := storage.StorePrivateIDAssociation(ctx, assoc)
		require.NoError(t, err)
	})

	t.Run("get association", func(t *testing.T) {
		retrieved, err := storage.GetPrivateIDAssociation(ctx, "test-private-id")
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, uint64(12345), retrieved.NodeID)
		assert.Equal(t, "10.0.0.1", retrieved.CurrentIP)
		assert.Equal(t, "test-collection", retrieved.Collection)
	})

	t.Run("update recent IPs", func(t *testing.T) {
		err := storage.UpdateRecentIPs(ctx, "test-private-id", "10.0.0.2")
		require.NoError(t, err)

		retrieved, err := storage.GetPrivateIDAssociation(ctx, "test-private-id")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.2", retrieved.CurrentIP)
	})

	t.Run("get associations by node ID", func(t *testing.T) {
		associations, err := storage.GetAssociationsByNodeID(ctx, 12345)
		require.NoError(t, err)
		assert.Len(t, associations, 1)
		assert.Equal(t, "test-private-id", associations[0].PrivateID)
	})

	t.Run("delete association", func(t *testing.T) {
		err := storage.DeletePrivateIDAssociation(ctx, "test-private-id")
		require.NoError(t, err)

		retrieved, err := storage.GetPrivateIDAssociation(ctx, "test-private-id")
		require.NoError(t, err)
		assert.Nil(t, retrieved)
	})
}

func TestFirstSeenTracking(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	record := &FirstSeenRecord{
		PrivateID:   "test-private-id",
		Collection:  "test-collection",
		FirstSeenAt: time.Now(),
		FirstSeenIP: "10.0.0.1",
	}

	t.Run("record first seen", func(t *testing.T) {
		err := storage.RecordFirstSeen(ctx, record)
		require.NoError(t, err)
	})

	t.Run("get first seen", func(t *testing.T) {
		retrieved, err := storage.GetFirstSeen(ctx, "test-private-id")
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, "test-private-id", retrieved.PrivateID)
		assert.Equal(t, "10.0.0.1", retrieved.FirstSeenIP)
	})

	t.Run("increment request count", func(t *testing.T) {
		err := storage.IncrementFirstSeenCount(ctx, "test-private-id")
		require.NoError(t, err)

		retrieved, err := storage.GetFirstSeen(ctx, "test-private-id")
		require.NoError(t, err)
		assert.Equal(t, 2, retrieved.RequestCount) // RecordFirstSeen sets count to 1, incremented to 2
	})

	t.Run("delete first seen", func(t *testing.T) {
		err := storage.DeleteFirstSeen(ctx, "test-private-id")
		require.NoError(t, err)

		retrieved, err := storage.GetFirstSeen(ctx, "test-private-id")
		require.NoError(t, err)
		assert.Nil(t, retrieved)
	})
}

func TestIPObservations(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	t.Run("record IP observations", func(t *testing.T) {
		err := storage.RecordIPObservation(ctx, "test-private-id", "10.0.0.1")
		require.NoError(t, err)

		err = storage.RecordIPObservation(ctx, "test-private-id", "10.0.0.2")
		require.NoError(t, err)

		// Record same IP again (should increment count)
		err = storage.RecordIPObservation(ctx, "test-private-id", "10.0.0.1")
		require.NoError(t, err)
	})

	t.Run("get recent IP observations", func(t *testing.T) {
		observations, err := storage.GetRecentIPObservations(ctx, "test-private-id", 24)
		require.NoError(t, err)
		assert.Len(t, observations, 2)
	})

	t.Run("cleanup old IP observations", func(t *testing.T) {
		// This won't delete anything since we just created them
		err := storage.CleanupOldIPObservations(ctx, 30)
		require.NoError(t, err)
	})
}

func TestListCollections(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Create instances in different collections
	logs1 := []LogEntry{
		{
			Collection: "collection-1",
			PrivateID:  "private-1",
			PublicID:   "public-1",
			Timestamp:  time.Now(),
			LogData:    []byte(`{}`),
			SizeBytes:  2,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := storage.StoreLogs(ctx, logs1)
	require.NoError(t, err)

	logs2 := []LogEntry{
		{
			Collection: "collection-2",
			PrivateID:  "private-2",
			PublicID:   "public-2",
			Timestamp:  time.Now(),
			LogData:    []byte(`{}`),
			SizeBytes:  2,
			LogTier:    LogTierGracePeriod,
		},
	}
	err = storage.StoreLogs(ctx, logs2)
	require.NoError(t, err)

	collections, err := storage.ListCollections(ctx)
	require.NoError(t, err)
	assert.Len(t, collections, 2)
	assert.Contains(t, collections, "collection-1")
	assert.Contains(t, collections, "collection-2")
}

func TestListInstancesInCollection(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Create multiple instances in same collection
	logs1 := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "private-1",
			PublicID:   "public-1",
			Timestamp:  time.Now(),
			LogData:    []byte(`{}`),
			SizeBytes:  2,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := storage.StoreLogs(ctx, logs1)
	require.NoError(t, err)

	logs2 := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "private-2",
			PublicID:   "public-2",
			Timestamp:  time.Now(),
			LogData:    []byte(`{}`),
			SizeBytes:  2,
			LogTier:    LogTierGracePeriod,
		},
	}
	err = storage.StoreLogs(ctx, logs2)
	require.NoError(t, err)

	instances, err := storage.ListInstancesInCollection(ctx, "test-collection")
	require.NoError(t, err)
	assert.Len(t, instances, 2)
}

func TestDeleteLogsByTier(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Store logs in different tiers
	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"grace period log"}`),
			SizeBytes:  30,
			LogTier:    LogTierGracePeriod,
		},
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now().Add(1 * time.Second),
			LogData:    []byte(`{"msg":"ephemeral log"}`),
			SizeBytes:  25,
			LogTier:    LogTierEphemeral,
		},
	}
	err := storage.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Delete grace period logs
	count, bytes, err := storage.DeleteLogsByTier(ctx, "test-private-id", "test-collection", LogTierGracePeriod)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, int64(30), bytes)

	// Verify only ephemeral log remains
	results, err := storage.QueryLogs(ctx, LogQuery{
		Collection: "test-collection",
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, LogTierEphemeral, results[0].LogTier)
}

func TestFindExpiredGracePeriodInstances(t *testing.T) {
	db := setupStorageTestDB(t)
	storage := NewDBStorage(db)
	ctx := context.Background()

	// Create instance with old first_seen
	oldTime := time.Now().Add(-10 * time.Minute)
	err := db.Exec(`
		INSERT INTO log_instances 
		(collection, private_id, public_id, first_seen, last_seen, total_logs, total_size_bytes, log_tier)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-collection", "old-private-id", "old-public-id", oldTime, time.Now(), 0, 0, string(LogTierGracePeriod)).Error
	require.NoError(t, err)

	// Find expired instances (cutoff 5 minutes ago)
	cutoff := time.Now().Add(-5 * time.Minute)
	instances, err := storage.FindExpiredGracePeriodInstances(ctx, cutoff)
	require.NoError(t, err)
	assert.Len(t, instances, 1)
	assert.Equal(t, "old-private-id", instances[0].PrivateID)
}
