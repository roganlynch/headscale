package logtail

import (
	"context"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupWorkerTestService creates a test service for worker tests
func setupWorkerTestService(t *testing.T) (*LogtailService, *WorkerManager) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create tables
	err = db.AutoMigrate(
		&LogEntry{},
		&LogInstance{},
		&PrivateIDAssociation{},
		&IPObservation{},
		&FirstSeenRecord{},
		&RateLimitWindow{},
	)
	if err != nil {
		t.Fatalf("Failed to migrate tables: %v", err)
	}

	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 100)
	config := types.LogTailServerConfig{
		Enabled:     true,
		EnableCache: true,
		Retention: types.LogTailRetentionConfig{
			EphemeralMinutes:     60, // 1 hour
			PersistedDefaultDays: 30, // 30 days
			CleanupIntervalHours: 1,  // 1 hour
		},
		RateLimit: types.LogTailRateLimitConfig{
			RequestsPerMinute: 100,
		},
		Auth: types.LogTailAuthConfig{
			WriteAuth: types.WriteAuthConfig{
				RequireNodeRegistration:   true,
				PreAuthGracePeriodSeconds: 300, // 5 minutes
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

	service := NewLogtailService(storage, rateLimiter, config)
	workerManager := NewWorkerManager(service)

	return service, workerManager
}

func TestNewWorkerManager(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)

	if workerManager == nil {
		t.Fatal("WorkerManager should not be nil")
	}

	if workerManager.service != service {
		t.Error("WorkerManager should reference the service")
	}

	if workerManager.stopChan == nil {
		t.Error("stopChan should be initialized")
	}

	if workerManager.doneChan == nil {
		t.Error("doneChan should be initialized")
	}
}

func TestWorkerManager_StartStop(t *testing.T) {
	_, workerManager := setupWorkerTestService(t)

	// Start workers
	workerManager.Start()

	// Verify tickers are created
	if workerManager.cleanupTicker == nil {
		t.Error("cleanupTicker should be initialized after Start")
	}

	if workerManager.migrateTicker == nil {
		t.Error("migrateTicker should be initialized after Start")
	}

	// Stop workers
	workerManager.Stop()

	// Verify cleanup
	// Note: We can't directly check if tickers are stopped, but we can verify
	// that Stop() completes without hanging
}

func TestCleanupExpiredLogs_Ephemeral(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create logs: some old (expired), some recent
	oldTime := time.Now().Add(-2 * time.Hour)
	recentTime := time.Now()

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "test-id-1",
			Timestamp:  oldTime,
			LogData:    []byte(`{"message":"old log"}`),
			SizeBytes:  20,
			LogTier:    LogTierEphemeral,
		},
		{
			Collection: "test.collection",
			PrivateID:  "test-id-2",
			Timestamp:  recentTime,
			LogData:    []byte(`{"message":"recent log"}`),
			SizeBytes:  20,
			LogTier:    LogTierEphemeral,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Run cleanup
	stats, err := workerManager.ForceCleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify old logs were deleted (1 hour retention for ephemeral)
	if stats.EphemeralLogsDeleted == 0 {
		t.Error("Expected some ephemeral logs to be deleted")
	}

	if stats.BytesFreed == 0 {
		t.Error("Expected some bytes to be freed")
	}
}

func TestCleanupExpiredLogs_Persisted(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create persisted logs: very old (expired)
	oldTime := time.Now().Add(-31 * 24 * time.Hour) // 31 days old

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "test-id",
			Timestamp:  oldTime,
			LogData:    []byte(`{"message":"old persisted log"}`),
			SizeBytes:  25,
			LogTier:    LogTierPersisted,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Run cleanup
	stats, err := workerManager.ForceCleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify old persisted logs were deleted (30 day retention)
	if stats.PersistedLogsDeleted == 0 {
		t.Error("Expected persisted logs to be deleted")
	}
}

func TestHandleGracePeriodExpirations_NoAssociation(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create grace period logs from 10 minutes ago (expired with 5 min grace period)
	expiredTime := time.Now().Add(-10 * time.Minute)

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "unassociated-id",
			Timestamp:  expiredTime,
			LogData:    []byte(`{"message":"grace period log"}`),
			SizeBytes:  25,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Run migration (should delete grace period logs without association)
	count, err := workerManager.ForceMigration(ctx)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Should have deleted the instance
	if count == 0 {
		t.Error("Expected at least one expired instance to be deleted")
	}
}

func TestHandleGracePeriodExpirations_WithAssociation(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create grace period logs from 10 minutes ago
	expiredTime := time.Now().Add(-10 * time.Minute)

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "associated-id",
			Timestamp:  expiredTime,
			LogData:    []byte(`{"message":"grace period log"}`),
			SizeBytes:  25,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Create association (authenticated)
	assoc := &PrivateIDAssociation{
		PrivateID:    "associated-id",
		NodeID:       123,
		Collection:   "test.collection",
		CurrentIP:    "192.168.1.100",
		RecentIPs:    []string{"192.168.1.100"},
		AssociatedAt: time.Now(),
	}
	err = service.storage.StorePrivateIDAssociation(ctx, assoc)
	if err != nil {
		t.Fatalf("Failed to store association: %v", err)
	}

	// Run migration (should NOT delete logs with association)
	count, err := workerManager.ForceMigration(ctx)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Should not have deleted the instance (has association)
	if count != 0 {
		t.Error("Expected no instances to be deleted (has association)")
	}
}

func TestWorkerManager_MigrateLogTier(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create ephemeral logs
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "migrate-test-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"log to migrate"}`),
			SizeBytes:  25,
			LogTier:    LogTierEphemeral,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Migrate from ephemeral to persisted
	err = workerManager.MigrateLogTier(ctx, "test.collection", "migrate-test-id", LogTierEphemeral, LogTierPersisted)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify log tier was updated
	instance, err := service.storage.GetLogInstance(ctx, "migrate-test-id", "test.collection")
	if err != nil {
		t.Fatalf("Failed to get instance: %v", err)
	}

	if instance.LogTier != LogTierPersisted {
		t.Errorf("Expected tier %s, got %s", LogTierPersisted, instance.LogTier)
	}
}

func TestSetInstancePersistence_Enable(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create ephemeral logs
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "persist-test-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"log to persist"}`),
			SizeBytes:  25,
			LogTier:    LogTierEphemeral,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Enable persistence (30 day retention)
	err = workerManager.SetInstancePersistence(ctx, "test.collection", "persist-test-id", true, 30)
	if err != nil {
		t.Fatalf("SetInstancePersistence failed: %v", err)
	}

	// Verify instance is persisted
	instance, err := service.storage.GetLogInstance(ctx, "persist-test-id", "test.collection")
	if err != nil {
		t.Fatalf("Failed to get instance: %v", err)
	}

	if !instance.Persisted {
		t.Error("Expected instance to be persisted")
	}

	if instance.LogTier != LogTierPersisted {
		t.Errorf("Expected tier %s, got %s", LogTierPersisted, instance.LogTier)
	}

	if instance.RetentionDays != 30 {
		t.Errorf("Expected retention 30 days, got %d", instance.RetentionDays)
	}
}

func TestSetInstancePersistence_Disable(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create persisted logs
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "unpersist-test-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"persisted log"}`),
			SizeBytes:  25,
			LogTier:    LogTierPersisted,
			Persisted:  true,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Disable persistence
	err = workerManager.SetInstancePersistence(ctx, "test.collection", "unpersist-test-id", false, 0)
	if err != nil {
		t.Fatalf("SetInstance Persistence failed: %v", err)
	}

	// Verify instance is no longer persisted
	instance, err := service.storage.GetLogInstance(ctx, "unpersist-test-id", "test.collection")
	if err != nil {
		t.Fatalf("Failed to get instance: %v", err)
	}

	if instance.Persisted {
		t.Error("Expected instance to not be persisted")
	}

	if instance.LogTier != LogTierEphemeral {
		t.Errorf("Expected tier %s, got %s", LogTierEphemeral, instance.LogTier)
	}
}

func TestForceCleanup(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create some test logs
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "cleanup-test-id",
			Timestamp:  time.Now().Add(-2 * time.Hour),
			LogData:    []byte(`{"message":"test"}`),
			SizeBytes:  15,
			LogTier:    LogTierEphemeral,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Force cleanup
	stats, err := workerManager.ForceCleanup(ctx)
	if err != nil {
		t.Fatalf("ForceCleanup failed: %v", err)
	}

	// Verify stats are returned
	if stats == nil {
		t.Fatal("Expected stats to be returned")
	}
}

func TestForceMigration(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create grace period logs from 10 minutes ago (expired)
	expiredTime := time.Now().Add(-10 * time.Minute)

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "migration-test-id",
			Timestamp:  expiredTime,
			LogData:    []byte(`{"message":"grace period log"}`),
			SizeBytes:  25,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Force migration
	count, err := workerManager.ForceMigration(ctx)
	if err != nil {
		t.Fatalf("ForceMigration failed: %v", err)
	}

	// Should have processed at least one instance
	if count == 0 {
		t.Error("Expected at least one instance to be processed")
	}
}

func TestCleanupStats_AllTiers(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create logs in all tiers (all expired)
	oldTime := time.Now().Add(-31 * 24 * time.Hour)

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "stats-test-1",
			Timestamp:  oldTime,
			LogData:    []byte(`{"message":"grace"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
		{
			Collection: "test.collection",
			PrivateID:  "stats-test-2",
			Timestamp:  oldTime,
			LogData:    []byte(`{"message":"ephemeral"}`),
			SizeBytes:  25,
			LogTier:    LogTierEphemeral,
		},
		{
			Collection: "test.collection",
			PrivateID:  "stats-test-3",
			Timestamp:  oldTime,
			LogData:    []byte(`{"message":"persisted"}`),
			SizeBytes:  25,
			LogTier:    LogTierPersisted,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Run cleanup
	stats, err := workerManager.ForceCleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify stats capture deletions across all tiers
	totalDeleted := stats.EphemeralLogsDeleted + stats.PersistedLogsDeleted + stats.GracePeriodLogsDeleted
	if totalDeleted == 0 {
		t.Error("Expected some logs to be deleted from various tiers")
	}
}

func TestWorkerManager_NoLogsToCleanup(t *testing.T) {
	_, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Run cleanup with no logs
	stats, err := workerManager.ForceCleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Should complete without error
	if stats.EphemeralLogsDeleted != 0 || stats.PersistedLogsDeleted != 0 {
		t.Error("Expected no logs to be deleted when none exist")
	}

	if stats.BytesFreed != 0 {
		t.Error("Expected no bytes to be freed when no logs exist")
	}
}

func TestWorkerManager_NoExpiredInstances(t *testing.T) {
	service, workerManager := setupWorkerTestService(t)
	ctx := context.Background()

	// Create recent grace period logs (not expired)
	recentTime := time.Now()

	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "recent-id",
			Timestamp:  recentTime,
			LogData:    []byte(`{"message":"recent grace period log"}`),
			SizeBytes:  25,
			LogTier:    LogTierGracePeriod,
		},
	}

	err := service.storage.StoreLogs(ctx, logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	// Run migration
	count, err := workerManager.ForceMigration(ctx)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Should not delete recent grace period instances
	if count != 0 {
		t.Error("Expected no instances to be deleted (not expired)")
	}
}
