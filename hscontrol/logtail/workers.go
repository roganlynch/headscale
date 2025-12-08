package logtail

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

// WorkerManager manages background workers for log cleanup and tier migration
type WorkerManager struct {
	service       *LogtailService
	cleanupTicker *time.Ticker
	migrateTicker *time.Ticker
	stopChan      chan struct{}
	doneChan      chan struct{}
}

// NewWorkerManager creates a new worker manager with the given service
func NewWorkerManager(service *LogtailService) *WorkerManager {
	return &WorkerManager{
		service:  service,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
}

// Start starts all background workers
func (wm *WorkerManager) Start() {
	cleanupInterval := time.Duration(wm.service.config.Retention.CleanupIntervalHours) * time.Hour
	wm.cleanupTicker = time.NewTicker(cleanupInterval)

	// Migrate logs every hour (check for grace period expirations and tier transitions)
	wm.migrateTicker = time.NewTicker(1 * time.Hour)

	go wm.runWorkers()

	log.Info().
		Dur("cleanup_interval", cleanupInterval).
		Msg("Logtail background workers started")
}

// Stop stops all background workers
func (wm *WorkerManager) Stop() {
	close(wm.stopChan)
	<-wm.doneChan

	if wm.cleanupTicker != nil {
		wm.cleanupTicker.Stop()
	}
	if wm.migrateTicker != nil {
		wm.migrateTicker.Stop()
	}

	log.Info().Msg("Logtail background workers stopped")
}

// runWorkers is the main worker loop
func (wm *WorkerManager) runWorkers() {
	defer close(wm.doneChan)

	// Run initial cleanup and migration
	wm.runCleanup()
	wm.runMigration()

	for {
		select {
		case <-wm.stopChan:
			return
		case <-wm.cleanupTicker.C:
			wm.runCleanup()
		case <-wm.migrateTicker.C:
			wm.runMigration()
		}
	}
}

// runCleanup performs log cleanup based on retention policies
func (wm *WorkerManager) runCleanup() {
	ctx := context.Background()
	start := time.Now()

	log.Info().Msg("Starting log cleanup worker")

	stats, err := wm.cleanupExpiredLogs(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Log cleanup failed")
		return
	}

	log.Info().
		Int("ephemeral_deleted", stats.EphemeralLogsDeleted).
		Int("persisted_deleted", stats.PersistedLogsDeleted).
		Int("grace_period_deleted", stats.GracePeriodLogsDeleted).
		Int64("bytes_freed", stats.BytesFreed).
		Dur("duration", time.Since(start)).
		Msg("Log cleanup completed")
}

// runMigration performs tier migration and grace period expiration
func (wm *WorkerManager) runMigration() {
	ctx := context.Background()
	start := time.Now()

	log.Info().Msg("Starting log migration worker")

	// Handle grace period expirations
	expiredCount, err := wm.handleGracePeriodExpirations(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Grace period expiration handling failed")
	} else if expiredCount > 0 {
		log.Info().
			Int("expired_instances", expiredCount).
			Msg("Expired grace period instances deleted")
	}

	log.Info().
		Dur("duration", time.Since(start)).
		Msg("Log migration completed")
}

// cleanupExpiredLogs removes expired logs based on retention policies
func (wm *WorkerManager) cleanupExpiredLogs(ctx context.Context) (*CleanupStats, error) {
	stats := &CleanupStats{}

	// Calculate cutoff times
	ephemeralCutoff := time.Now().Add(-time.Duration(wm.service.config.Retention.EphemeralMinutes) * time.Minute)
	persistedCutoff := time.Now().Add(-time.Duration(wm.service.config.Retention.PersistedDefaultDays) * 24 * time.Hour)

	// Delete expired ephemeral logs
	if count, bytes, err := wm.service.storage.DeleteOldLogsByTier(ctx, LogTierEphemeral, ephemeralCutoff); err != nil {
		return nil, err
	} else {
		stats.EphemeralLogsDeleted = count
		stats.BytesFreed += bytes
	}

	// Delete expired persisted logs
	if count, bytes, err := wm.service.storage.DeleteOldLogsByTier(ctx, LogTierPersisted, persistedCutoff); err != nil {
		return nil, err
	} else {
		stats.PersistedLogsDeleted = count
		stats.BytesFreed += bytes
	}

	// Clean up IP observation history
	ipCleanupDays := wm.service.config.Auth.WriteAuth.IPValidation.CleanupHistoryDays
	if ipCleanupDays > 0 {
		if err := wm.service.storage.CleanupOldIPObservations(ctx, ipCleanupDays); err != nil {
			log.Warn().Err(err).Msg("Failed to cleanup old IP observations")
		}
	}

	return stats, nil
}

// handleGracePeriodExpirations deletes logs from instances where grace period has expired
// and no association was created
func (wm *WorkerManager) handleGracePeriodExpirations(ctx context.Context) (int, error) {
	gracePeriodMinutes := wm.service.config.Auth.WriteAuth.PreAuthGracePeriodSeconds / 60
	cutoff := time.Now().Add(-time.Duration(gracePeriodMinutes) * time.Minute)

	// Find instances with expired grace periods
	expiredInstances, err := wm.service.storage.FindExpiredGracePeriodInstances(ctx, cutoff)
	if err != nil {
		return 0, err
	}

	if len(expiredInstances) == 0 {
		return 0, nil
	}

	log.Info().
		Int("count", len(expiredInstances)).
		Msg("Found instances with expired grace periods")

	deletedCount := 0
	for _, instance := range expiredInstances {
		// Check if association exists for this private ID
		assoc, err := wm.service.storage.GetPrivateIDAssociation(ctx, instance.PrivateID)
		if err != nil {
			log.Warn().
				Err(err).
				Str("collection", instance.Collection).
				Str("private_id", instance.PrivateID).
				Msg("Failed to check association for expired instance")
			continue
		}

		// If no association was created, delete the logs
		if assoc == nil {
			// Delete all grace period logs for this instance
			count, bytes, err := wm.service.storage.DeleteLogsByTier(ctx, instance.PrivateID, instance.Collection, LogTierGracePeriod)
			if err != nil {
				log.Error().
					Err(err).
					Str("collection", instance.Collection).
					Str("private_id", instance.PrivateID).
					Msg("Failed to delete logs for expired grace period instance")
				continue
			}

			log.Debug().
				Str("collection", instance.Collection).
				Str("private_id", instance.PrivateID).
				Int("logs_deleted", count).
				Int64("bytes_freed", bytes).
				Msg("Deleted logs for expired grace period instance")

			deletedCount++
		}
	}

	return deletedCount, nil
}

// MigrateLogTier manually migrates logs from one tier to another
// This can be used by administrators to promote logs from ephemeral to persisted
func (wm *WorkerManager) MigrateLogTier(ctx context.Context, collection, privateID string, fromTier, toTier LogTier) error {
	log.Info().
		Str("collection", collection).
		Str("private_id", privateID).
		Str("from_tier", fromTier.String()).
		Str("to_tier", toTier.String()).
		Msg("Manually migrating log tier")

	err := wm.service.storage.MigrateLogTier(ctx, privateID, collection, fromTier, toTier)
	if err != nil {
		return err
	}

	// Update instance tier
	if err := wm.service.storage.UpdateInstanceTier(ctx, privateID, collection, toTier); err != nil {
		log.Warn().Err(err).Msg("Failed to update instance tier")
	}

	log.Info().
		Msg("Log tier migration completed")

	return nil
}

// SetInstancePersistence sets whether logs for an instance should be persisted
// If persist=true, logs are migrated to LogTierPersisted
// If persist=false, logs remain or are migrated to LogTierEphemeral
func (wm *WorkerManager) SetInstancePersistence(ctx context.Context, collection, privateID string, persist bool, retentionDays int) error {
	log.Info().
		Str("collection", collection).
		Str("private_id", privateID).
		Bool("persist", persist).
		Int("retention_days", retentionDays).
		Msg("Setting instance persistence")

	// Update the instance persistence flag
	if err := wm.service.storage.UpdateInstancePersistence(ctx, privateID, collection, persist, retentionDays); err != nil {
		return err
	}

	// Migrate logs to appropriate tier
	fromTier := LogTierEphemeral
	toTier := LogTierPersisted
	if !persist {
		fromTier = LogTierPersisted
		toTier = LogTierEphemeral
	}

	return wm.MigrateLogTier(ctx, collection, privateID, fromTier, toTier)
}

// ForceCleanup runs cleanup immediately (useful for testing or admin operations)
func (wm *WorkerManager) ForceCleanup(ctx context.Context) (*CleanupStats, error) {
	log.Info().Msg("Forcing immediate cleanup")
	return wm.cleanupExpiredLogs(ctx)
}

// ForceMigration runs migration immediately (useful for testing or admin operations)
func (wm *WorkerManager) ForceMigration(ctx context.Context) (int, error) {
	log.Info().Msg("Forcing immediate migration")
	return wm.handleGracePeriodExpirations(ctx)
}
