package logtail

import (
	"context"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupServiceTestDB creates an in-memory SQLite database for service tests
func setupServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create all required tables
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

	err = db.Exec(`
		CREATE TABLE logtail_rate_limits (
			private_id TEXT PRIMARY KEY,
			request_count INTEGER DEFAULT 0,
			window_start DATETIME NOT NULL,
			last_request DATETIME NOT NULL
		)
	`).Error
	require.NoError(t, err)

	return db
}

// getDefaultTestConfig returns a default test configuration
func getDefaultTestConfig() types.LogTailServerConfig {
	return types.LogTailServerConfig{
		Enabled:     true,
		EnableCache: true,
		Retention: types.LogTailRetentionConfig{
			EphemeralMinutes:     720,
			PersistedDefaultDays: 30,
			CleanupIntervalHours: 1,
		},
		RateLimit: types.LogTailRateLimitConfig{
			RequestsPerMinute: 10,
		},
		Auth: types.LogTailAuthConfig{
			WriteAuth: types.WriteAuthConfig{
				RequireNodeRegistration:   true,
				PreAuthGracePeriodSeconds: 300,
				IPValidation: types.IPValidationConfig{
					Enabled:               true,
					Mode:                  "relaxed",
					AllowIPChanges:        true,
					ValidationWindowHours: 48,
					CleanupHistoryDays:    30,
					LogIPMismatches:       true,
				},
			},
		},
	}
}

func TestAuthenticateWithCache_CacheHit(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Pre-populate cache with auth result
	cachedResult := &CachedAuthResult{
		Result: AuthResult{
			Allowed:       true,
			Reason:        "cached result",
			IsGracePeriod: false,
		},
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}
	service.cache.authCache.Store("test-private-id", cachedResult)

	// Call authentication - should hit cache
	result := service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.1", "test-collection")

	assert.True(t, result.Allowed)
	assert.Equal(t, "cached result", result.Reason)
	assert.False(t, result.IsGracePeriod)
}

func TestAuthenticateWithCache_CacheMiss_NoAssociation_GracePeriod(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()
	config.Auth.WriteAuth.RequireNodeRegistration = true
	config.Auth.WriteAuth.PreAuthGracePeriodSeconds = 300

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// First authentication - no association, no first-seen
	result := service.AuthenticateWithCache(ctx, "new-private-id", "10.0.0.1", "test-collection")

	assert.True(t, result.Allowed)
	assert.True(t, result.IsGracePeriod)
	assert.Contains(t, result.Reason, "grace period")

	// Verify first-seen was recorded in DB
	firstSeen, err := storage.GetFirstSeen(ctx, "new-private-id")
	require.NoError(t, err)
	require.NotNil(t, firstSeen)
	assert.Equal(t, "10.0.0.1", firstSeen.FirstSeenIP)

	// Verify first-seen was cached
	cached, ok := service.cache.firstSeen.Load("new-private-id")
	assert.True(t, ok)
	assert.NotNil(t, cached)
}

func TestAuthenticateWithCache_WithAssociation_IPValidation(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "strict"
	config.Auth.WriteAuth.IPValidation.AllowIPChanges = false

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Create association
	assoc := &PrivateIDAssociation{
		PrivateID:  "test-private-id",
		NodeID:     12345,
		Collection: "test-collection",
		CurrentIP:  "10.0.0.1",
		RecentIPs:  []string{"10.0.0.1"},
	}
	err := storage.StorePrivateIDAssociation(ctx, assoc)
	require.NoError(t, err)

	// Authenticate with matching IP
	result := service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.1", "test-collection")
	assert.True(t, result.Allowed)
	assert.False(t, result.IsGracePeriod)

	// Clear auth cache
	service.cache.EvictAuth("test-private-id")

	// Authenticate with different IP (should fail in strict mode)
	result = service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.2", "test-collection")
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "IP validation failed")
}

func TestAuthenticateWithCache_RecentIPsCaching(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Create association with initial IP
	assoc := &PrivateIDAssociation{
		PrivateID:  "test-private-id",
		NodeID:     12345,
		Collection: "test-collection",
		CurrentIP:  "10.0.0.1",
		RecentIPs:  []string{"10.0.0.1"},
	}
	err := storage.StorePrivateIDAssociation(ctx, assoc)
	require.NoError(t, err)

	// First authentication - should cache recent IPs from DB
	result := service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.1", "test-collection")
	assert.True(t, result.Allowed)

	// Verify recent IPs were cached from DB
	cachedIPs, ok := service.cache.recentIPs.Load("test-private-id")
	assert.True(t, ok)
	ips := cachedIPs.([]string)
	assert.Len(t, ips, 1)
	assert.Contains(t, ips, "10.0.0.1")

	// Test that subsequent authentications use cached IPs (no DB query)
	result = service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.1", "test-collection")
	assert.True(t, result.Allowed)
}

func TestAuthenticateWithCache_ExpiredCache(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Pre-populate cache with expired auth result
	expiredResult := &CachedAuthResult{
		Result: AuthResult{
			Allowed:       true,
			Reason:        "expired result",
			IsGracePeriod: false,
		},
		ExpiresAt: time.Now().Add(-1 * time.Minute), // Expired
	}
	service.cache.authCache.Store("test-private-id", expiredResult)

	// Call authentication - should not use expired cache
	result := service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.1", "test-collection")

	// Should get fresh result (grace period since no association)
	assert.True(t, result.Allowed)
	assert.True(t, result.IsGracePeriod)
	assert.NotEqual(t, "expired result", result.Reason)
}

func TestUpdateRecentIPsCached(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Create association
	assoc := &PrivateIDAssociation{
		PrivateID:  "test-private-id",
		NodeID:     12345,
		Collection: "test-collection",
		CurrentIP:  "10.0.0.1",
		RecentIPs:  []string{"10.0.0.1"},
	}
	err := storage.StorePrivateIDAssociation(ctx, assoc)
	require.NoError(t, err)

	// Pre-cache the IPs
	service.cache.recentIPs.Store("test-private-id", []string{"10.0.0.1"})

	// Update with new IP
	err = service.updateRecentIPsCached(ctx, "test-private-id", "10.0.0.2")
	require.NoError(t, err)

	// Verify cache was updated
	cachedIPs, ok := service.cache.recentIPs.Load("test-private-id")
	require.True(t, ok)
	ips := cachedIPs.([]string)
	assert.Len(t, ips, 2)
	assert.Equal(t, "10.0.0.2", ips[0]) // New IP should be first

	// Verify DB was updated
	retrieved, err := storage.GetPrivateIDAssociation(ctx, "test-private-id")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", retrieved.CurrentIP)
}

func TestUpdateRecentIPsCached_MaxTenIPs(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Create association
	assoc := &PrivateIDAssociation{
		PrivateID:  "test-private-id",
		NodeID:     12345,
		Collection: "test-collection",
		CurrentIP:  "10.0.0.1",
		RecentIPs:  []string{"10.0.0.1"},
	}
	err := storage.StorePrivateIDAssociation(ctx, assoc)
	require.NoError(t, err)

	// Pre-cache with 10 IPs
	tenIPs := []string{
		"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
		"10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10",
	}
	service.cache.recentIPs.Store("test-private-id", tenIPs)

	// Add 11th IP
	err = service.updateRecentIPsCached(ctx, "test-private-id", "10.0.0.11")
	require.NoError(t, err)

	// Verify only 10 IPs remain
	cachedIPs, ok := service.cache.recentIPs.Load("test-private-id")
	require.True(t, ok)
	ips := cachedIPs.([]string)
	assert.Len(t, ips, 10)
	assert.Equal(t, "10.0.0.11", ips[0])    // New IP should be first
	assert.NotContains(t, ips, "10.0.0.10") // Oldest IP should be removed
}

func TestAssociatePrivateIDCached(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Record first-seen (simulating grace period)
	firstSeen := &FirstSeenRecord{
		PrivateID:   "test-private-id",
		Collection:  "test-collection",
		FirstSeenAt: time.Now(),
		FirstSeenIP: "10.0.0.1",
	}
	err := storage.RecordFirstSeen(ctx, firstSeen)
	require.NoError(t, err)

	// Cache first-seen and auth result
	service.cache.firstSeen.Store("test-private-id", firstSeen)
	service.cache.authCache.Store("test-private-id", &CachedAuthResult{
		Result:    AuthResult{Allowed: true, IsGracePeriod: true},
		ExpiresAt: time.Now().Add(1 * time.Minute),
	})

	// Associate private ID with node
	err = service.AssociatePrivateIDCached(ctx, "test-private-id", 12345, "test-collection", "10.0.0.1")
	require.NoError(t, err)

	// Verify association was created in DB
	assoc, err := storage.GetPrivateIDAssociation(ctx, "test-private-id")
	require.NoError(t, err)
	require.NotNil(t, assoc)
	assert.Equal(t, uint64(12345), assoc.NodeID)

	// Verify caches were invalidated
	_, ok := service.cache.firstSeen.Load("test-private-id")
	assert.False(t, ok, "first-seen cache should be evicted")

	_, ok = service.cache.authCache.Load("test-private-id")
	assert.False(t, ok, "auth cache should be evicted")

	// Verify recent IPs were initialized
	cachedIPs, ok := service.cache.recentIPs.Load("test-private-id")
	assert.True(t, ok)
	ips := cachedIPs.([]string)
	assert.Equal(t, []string{"10.0.0.1"}, ips)
}

func TestStoreLogs_ServiceLayer(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"test"}`),
			SizeBytes:  16,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := service.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Verify logs were stored
	instance, err := service.GetLogInstance(ctx, "test-private-id", "test-collection")
	require.NoError(t, err)
	require.NotNil(t, instance)
	assert.Equal(t, 1, instance.TotalLogs)
}

func TestQueryLogs_ServiceLayer(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Store test logs
	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"test"}`),
			SizeBytes:  16,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := service.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Query logs
	results, err := service.QueryLogs(ctx, LogQuery{
		Collection: "test-collection",
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "test-private-id", results[0].PrivateID)
}

func TestMigrateLogTier_ServiceLayer(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Store logs
	logs := []LogEntry{
		{
			Collection: "test-collection",
			PrivateID:  "test-private-id",
			PublicID:   "test-public-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"msg":"test"}`),
			SizeBytes:  16,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := service.StoreLogs(ctx, logs)
	require.NoError(t, err)

	// Migrate tier
	err = service.MigrateLogTier(ctx, "test-private-id", "test-collection", LogTierGracePeriod, LogTierEphemeral)
	require.NoError(t, err)

	// Verify tier cache was updated
	tierKey := "test-private-id:test-collection"
	cachedTier, ok := service.cache.instanceTiers.Load(tierKey)
	assert.True(t, ok)
	assert.Equal(t, LogTierEphemeral, cachedTier.(LogTier))

	// Verify instance tier was updated
	instance, err := service.GetLogInstance(ctx, "test-private-id", "test-collection")
	require.NoError(t, err)
	assert.Equal(t, LogTierEphemeral, instance.LogTier)
}

func TestAuthenticateWithCache_WriteThroughFirstSeen(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()
	config.Auth.WriteAuth.RequireNodeRegistration = true

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// First authentication - should record first-seen
	result := service.AuthenticateWithCache(ctx, "new-private-id", "10.0.0.1", "test-collection")
	assert.True(t, result.Allowed)
	assert.True(t, result.IsGracePeriod)

	// Verify write-through: both cache and DB should have it
	cached, ok := service.cache.firstSeen.Load("new-private-id")
	assert.True(t, ok)
	assert.NotNil(t, cached)

	dbRecord, err := storage.GetFirstSeen(ctx, "new-private-id")
	require.NoError(t, err)
	require.NotNil(t, dbRecord)
	assert.Equal(t, "10.0.0.1", dbRecord.FirstSeenIP)
}

func TestAuthenticateWithCache_IPChangeDetection(t *testing.T) {
	db := setupServiceTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 10)
	config := getDefaultTestConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	config.Auth.WriteAuth.IPValidation.AllowIPChanges = true

	service := NewLogtailService(storage, rateLimiter, config)
	ctx := context.Background()

	// Create association with one IP
	assoc := &PrivateIDAssociation{
		PrivateID:  "test-private-id",
		NodeID:     12345,
		Collection: "test-collection",
		CurrentIP:  "10.0.0.1",
		RecentIPs:  []string{"10.0.0.1"},
	}
	err := storage.StorePrivateIDAssociation(ctx, assoc)
	require.NoError(t, err)

	// Authenticate with new IP in same subnet
	result := service.AuthenticateWithCache(ctx, "test-private-id", "10.0.0.2", "test-collection")
	assert.True(t, result.Allowed)

	// Recent IPs should be updated in DB
	time.Sleep(100 * time.Millisecond) // Give time for async update
	retrieved, err := storage.GetPrivateIDAssociation(ctx, "test-private-id")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", retrieved.CurrentIP)
}
