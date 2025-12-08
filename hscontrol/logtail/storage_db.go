package logtail

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// DBStorage implements Storage interface using database operations.
type DBStorage struct {
	db *gorm.DB
}

// NewDBStorage creates a new database storage instance.
func NewDBStorage(db *gorm.DB) *DBStorage {
	return &DBStorage{db: db}
}

// StoreLogs stores multiple log entries atomically and updates instance metadata.
func (s *DBStorage) StoreLogs(ctx context.Context, logs []LogEntry) error {
	if len(logs) == 0 {
		return nil
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Insert all logs
		for _, logEntry := range logs {
			err := tx.Exec(`
				INSERT INTO node_logs 
				(collection, private_id, public_id, timestamp, log_data, size_bytes, log_tier, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`,
				logEntry.Collection,
				logEntry.PrivateID,
				logEntry.PublicID,
				logEntry.Timestamp,
				logEntry.LogData,
				logEntry.SizeBytes,
				string(logEntry.LogTier),
				time.Now(),
			).Error

			if err != nil {
				return fmt.Errorf("failed to insert log: %w", err)
			}
		}

		// Update or create instance metadata
		firstLog := logs[0]

		var instance struct {
			ID uint64
		}
		err := tx.Raw(`
			SELECT id FROM log_instances WHERE private_id = ? AND collection = ?
		`, firstLog.PrivateID, firstLog.Collection).Scan(&instance).Error

		if err == gorm.ErrRecordNotFound || instance.ID == 0 {
			// Create new instance
			err = tx.Exec(`
				INSERT INTO log_instances 
				(collection, private_id, public_id, first_seen, last_seen, total_logs, total_size_bytes, log_tier)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`,
				firstLog.Collection,
				firstLog.PrivateID,
				firstLog.PublicID,
				time.Now(),
				time.Now(),
				len(logs),
				sumLogSizes(logs),
				string(firstLog.LogTier),
			).Error

			if err != nil {
				return fmt.Errorf("failed to create instance: %w", err)
			}
		} else {
			// Update existing instance
			err = tx.Exec(`
				UPDATE log_instances
				SET last_seen = ?, total_logs = total_logs + ?, total_size_bytes = total_size_bytes + ?
				WHERE private_id = ? AND collection = ?
			`,
				time.Now(),
				len(logs),
				sumLogSizes(logs),
				firstLog.PrivateID,
				firstLog.Collection,
			).Error

			if err != nil {
				return fmt.Errorf("failed to update instance: %w", err)
			}
		}

		return nil
	})
}

// QueryLogs retrieves logs matching the query parameters.
func (s *DBStorage) QueryLogs(ctx context.Context, query LogQuery) ([]LogEntry, error) {
	sql := `SELECT * FROM node_logs WHERE collection = ?`
	args := []interface{}{query.Collection}

	if len(query.PrivateIDs) > 0 {
		sql += ` AND private_id IN (?)`
		args = append(args, query.PrivateIDs)
	}

	if len(query.PublicIDs) > 0 {
		sql += ` AND public_id IN (?)`
		args = append(args, query.PublicIDs)
	}

	if query.TimeStart != nil {
		sql += ` AND timestamp >= ?`
		args = append(args, *query.TimeStart)
	}

	if query.TimeEnd != nil {
		sql += ` AND timestamp <= ?`
		args = append(args, *query.TimeEnd)
	}

	if query.Tier != nil {
		sql += ` AND log_tier = ?`
		args = append(args, string(*query.Tier))
	}

	sql += ` ORDER BY timestamp DESC`

	if query.MaxCount > 0 {
		sql += ` LIMIT ?`
		args = append(args, query.MaxCount)
	}

	var rows []struct {
		ID         uint64
		Collection string
		PrivateID  string `gorm:"column:private_id"`
		PublicID   string `gorm:"column:public_id"`
		Timestamp  time.Time
		LogData    []byte    `gorm:"column:log_data"`
		SizeBytes  int       `gorm:"column:size_bytes"`
		LogTier    string    `gorm:"column:log_tier"`
		CreatedAt  time.Time `gorm:"column:created_at"`
	}

	err := s.db.WithContext(ctx).Raw(sql, args...).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query logs: %w", err)
	}

	logs := make([]LogEntry, len(rows))
	for i, row := range rows {
		logs[i] = LogEntry{
			ID:         row.ID,
			Collection: row.Collection,
			PrivateID:  row.PrivateID,
			PublicID:   row.PublicID,
			Timestamp:  row.Timestamp,
			LogData:    row.LogData,
			SizeBytes:  row.SizeBytes,
			LogTier:    LogTier(row.LogTier),
			CreatedAt:  row.CreatedAt,
		}
	}

	return logs, nil
}

// DeleteLogsByTier deletes all logs for a specific instance and tier.
func (s *DBStorage) DeleteLogsByTier(ctx context.Context, privateID, collection string, tier LogTier) (int, int64, error) {
	// First, get the size of logs to be deleted
	var totalSize struct {
		SizeBytes int64 `gorm:"column:size_bytes"`
	}
	err := s.db.WithContext(ctx).Raw(`
		SELECT COALESCE(SUM(size_bytes), 0) as size_bytes
		FROM node_logs
		WHERE private_id = ? AND collection = ? AND log_tier = ?
	`, privateID, collection, string(tier)).Scan(&totalSize).Error

	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate total size: %w", err)
	}

	// Delete the logs
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM node_logs
		WHERE private_id = ? AND collection = ? AND log_tier = ?
	`, privateID, collection, string(tier))

	if result.Error != nil {
		return 0, 0, fmt.Errorf("failed to delete logs: %w", result.Error)
	}

	// Update instance statistics
	if result.RowsAffected > 0 {
		err = s.db.WithContext(ctx).Exec(`
			UPDATE log_instances
			SET total_logs = total_logs - ?, total_size_bytes = total_size_bytes - ?
			WHERE private_id = ? AND collection = ?
		`, result.RowsAffected, totalSize.SizeBytes, privateID, collection).Error

		if err != nil {
			log.Warn().Err(err).Msg("Failed to update instance statistics after deletion")
		}
	}

	return int(result.RowsAffected), totalSize.SizeBytes, nil
}

// DeleteOldLogsByTier deletes logs older than cutoff time for a specific tier.
func (s *DBStorage) DeleteOldLogsByTier(ctx context.Context, tier LogTier, cutoff time.Time) (int, int64, error) {
	// Get total size to be deleted
	var totalSize struct {
		SizeBytes int64 `gorm:"column:size_bytes"`
	}
	err := s.db.WithContext(ctx).Raw(`
		SELECT COALESCE(SUM(size_bytes), 0) as size_bytes
		FROM node_logs
		WHERE log_tier = ? AND timestamp < ?
	`, string(tier), cutoff).Scan(&totalSize).Error

	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate total size: %w", err)
	}

	// Delete old logs
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM node_logs
		WHERE log_tier = ? AND timestamp < ?
	`, string(tier), cutoff)

	if result.Error != nil {
		return 0, 0, fmt.Errorf("failed to delete old logs: %w", result.Error)
	}

	log.Info().
		Str("tier", string(tier)).
		Time("cutoff", cutoff).
		Int64("rows_deleted", result.RowsAffected).
		Int64("bytes_deleted", totalSize.SizeBytes).
		Msg("Deleted old logs by tier")

	return int(result.RowsAffected), totalSize.SizeBytes, nil
}

// DeleteOldLogsForInstance deletes logs older than cutoff for a specific instance and tier.
func (s *DBStorage) DeleteOldLogsForInstance(ctx context.Context, privateID, collection string, tier LogTier, cutoff time.Time) (int, int64, error) {
	// Get total size to be deleted
	var totalSize struct {
		SizeBytes int64 `gorm:"column:size_bytes"`
	}
	err := s.db.WithContext(ctx).Raw(`
		SELECT COALESCE(SUM(size_bytes), 0) as size_bytes
		FROM node_logs
		WHERE private_id = ? AND collection = ? AND log_tier = ? AND timestamp < ?
	`, privateID, collection, string(tier), cutoff).Scan(&totalSize).Error

	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate total size: %w", err)
	}

	// Delete the logs
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM node_logs
		WHERE private_id = ? AND collection = ? AND log_tier = ? AND timestamp < ?
	`, privateID, collection, string(tier), cutoff)

	if result.Error != nil {
		return 0, 0, fmt.Errorf("failed to delete logs: %w", result.Error)
	}

	// Update instance statistics
	if result.RowsAffected > 0 {
		err = s.db.WithContext(ctx).Exec(`
			UPDATE log_instances
			SET total_logs = total_logs - ?, total_size_bytes = total_size_bytes - ?
			WHERE private_id = ? AND collection = ?
		`, result.RowsAffected, totalSize.SizeBytes, privateID, collection).Error

		if err != nil {
			log.Warn().Err(err).Msg("Failed to update instance statistics after deletion")
		}
	}

	return int(result.RowsAffected), totalSize.SizeBytes, nil
}

// Helper function to sum log sizes.
func sumLogSizes(logs []LogEntry) int64 {
	var total int64
	for _, logEntry := range logs {
		total += int64(logEntry.SizeBytes)
	}
	return total
}

// GetLogInstance retrieves instance metadata for a private ID and collection.
func (s *DBStorage) GetLogInstance(ctx context.Context, privateID, collection string) (*LogInstance, error) {
	var row struct {
		ID                 uint64
		Collection         string
		PrivateID          string `gorm:"column:private_id"`
		PublicID           string `gorm:"column:public_id"`
		Persisted          bool
		PersistedAt        *time.Time `gorm:"column:persisted_at"`
		FirstSeen          time.Time  `gorm:"column:first_seen"`
		LastSeen           time.Time  `gorm:"column:last_seen"`
		TotalLogs          int        `gorm:"column:total_logs"`
		TotalSizeBytes     int64      `gorm:"column:total_size_bytes"`
		RetentionDays      *int       `gorm:"column:retention_days"`
		LogTier            string     `gorm:"column:log_tier"`
		TierTransitionedAt *time.Time `gorm:"column:tier_transitioned_at"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM log_instances WHERE private_id = ? AND collection = ?
	`, privateID, collection).Scan(&row).Error

	if err == gorm.ErrRecordNotFound || row.ID == 0 {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get instance: %w", err)
	}

	instance := &LogInstance{
		ID:             row.ID,
		Collection:     row.Collection,
		PrivateID:      row.PrivateID,
		PublicID:       row.PublicID,
		Persisted:      row.Persisted,
		FirstSeen:      row.FirstSeen,
		LastSeen:       row.LastSeen,
		TotalLogs:      row.TotalLogs,
		TotalSizeBytes: row.TotalSizeBytes,
		LogTier:        LogTier(row.LogTier),
	}

	// Handle nullable fields
	if row.PersistedAt != nil {
		instance.PersistedAt = *row.PersistedAt
	}
	if row.RetentionDays != nil {
		instance.RetentionDays = *row.RetentionDays
	}
	if row.TierTransitionedAt != nil {
		instance.TierTransitionedAt = *row.TierTransitionedAt
	}

	return instance, nil
}

// UpdateInstancePersistence marks an instance as persisted with retention policy.
func (s *DBStorage) UpdateInstancePersistence(ctx context.Context, privateID, collection string, persisted bool, retentionDays int) error {
	now := time.Now()

	var err error
	if persisted {
		err = s.db.WithContext(ctx).Exec(`
			UPDATE log_instances
			SET persisted = ?, persisted_at = ?, retention_days = ?, log_tier = ?, tier_transitioned_at = ?
			WHERE private_id = ? AND collection = ?
		`, persisted, now, retentionDays, string(LogTierPersisted), now, privateID, collection).Error
	} else {
		err = s.db.WithContext(ctx).Exec(`
			UPDATE log_instances
			SET persisted = ?, persisted_at = NULL, retention_days = NULL
			WHERE private_id = ? AND collection = ?
		`, persisted, privateID, collection).Error
	}

	if err != nil {
		return fmt.Errorf("failed to update instance persistence: %w", err)
	}

	return nil
}

// UpdateInstanceTier updates the tier for an instance.
func (s *DBStorage) UpdateInstanceTier(ctx context.Context, privateID, collection string, tier LogTier) error {
	now := time.Now()

	err := s.db.WithContext(ctx).Exec(`
		UPDATE log_instances
		SET log_tier = ?, tier_transitioned_at = ?
		WHERE private_id = ? AND collection = ?
	`, string(tier), now, privateID, collection).Error

	if err != nil {
		return fmt.Errorf("failed to update instance tier: %w", err)
	}

	return nil
}

// MigrateLogTier migrates logs from one tier to another for an instance.
func (s *DBStorage) MigrateLogTier(ctx context.Context, privateID, collection string, fromTier, toTier LogTier) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Update logs tier
		result := tx.Exec(`
			UPDATE node_logs
			SET log_tier = ?
			WHERE private_id = ? AND collection = ? AND log_tier = ?
		`, string(toTier), privateID, collection, string(fromTier))

		if result.Error != nil {
			return fmt.Errorf("failed to migrate logs: %w", result.Error)
		}

		log.Info().
			Str("private_id", privateID).
			Str("collection", collection).
			Str("from_tier", string(fromTier)).
			Str("to_tier", string(toTier)).
			Int64("rows_affected", result.RowsAffected).
			Msg("Migrated log tier")

		// Update instance tier
		now := time.Now()
		err := tx.Exec(`
			UPDATE log_instances
			SET log_tier = ?, tier_transitioned_at = ?
			WHERE private_id = ? AND collection = ?
		`, string(toTier), now, privateID, collection).Error

		if err != nil {
			return fmt.Errorf("failed to update instance tier: %w", err)
		}

		return nil
	})
}

// GetPersistedInstances retrieves all instances marked as persisted.
func (s *DBStorage) GetPersistedInstances(ctx context.Context) ([]LogInstance, error) {
	var rows []struct {
		ID                 uint64
		Collection         string
		PrivateID          string `gorm:"column:private_id"`
		PublicID           string `gorm:"column:public_id"`
		Persisted          bool
		PersistedAt        *time.Time `gorm:"column:persisted_at"`
		FirstSeen          time.Time  `gorm:"column:first_seen"`
		LastSeen           time.Time  `gorm:"column:last_seen"`
		TotalLogs          int        `gorm:"column:total_logs"`
		TotalSizeBytes     int64      `gorm:"column:total_size_bytes"`
		RetentionDays      *int       `gorm:"column:retention_days"`
		LogTier            string     `gorm:"column:log_tier"`
		TierTransitionedAt *time.Time `gorm:"column:tier_transitioned_at"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM log_instances WHERE persisted = true ORDER BY persisted_at DESC
	`).Scan(&rows).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get persisted instances: %w", err)
	}

	instances := make([]LogInstance, len(rows))
	for i, row := range rows {
		instance := LogInstance{
			ID:             row.ID,
			Collection:     row.Collection,
			PrivateID:      row.PrivateID,
			PublicID:       row.PublicID,
			Persisted:      row.Persisted,
			FirstSeen:      row.FirstSeen,
			LastSeen:       row.LastSeen,
			TotalLogs:      row.TotalLogs,
			TotalSizeBytes: row.TotalSizeBytes,
			LogTier:        LogTier(row.LogTier),
		}

		// Handle nullable fields
		if row.PersistedAt != nil {
			instance.PersistedAt = *row.PersistedAt
		}
		if row.RetentionDays != nil {
			instance.RetentionDays = *row.RetentionDays
		}
		if row.TierTransitionedAt != nil {
			instance.TierTransitionedAt = *row.TierTransitionedAt
		}

		instances[i] = instance
	}

	return instances, nil
}

// FindExpiredGracePeriodInstances finds instances that have been in grace period longer than cutoff.
func (s *DBStorage) FindExpiredGracePeriodInstances(ctx context.Context, cutoff time.Time) ([]LogInstance, error) {
	var rows []struct {
		ID                 uint64
		Collection         string
		PrivateID          string `gorm:"column:private_id"`
		PublicID           string `gorm:"column:public_id"`
		Persisted          bool
		PersistedAt        *time.Time `gorm:"column:persisted_at"`
		FirstSeen          time.Time  `gorm:"column:first_seen"`
		LastSeen           time.Time  `gorm:"column:last_seen"`
		TotalLogs          int        `gorm:"column:total_logs"`
		TotalSizeBytes     int64      `gorm:"column:total_size_bytes"`
		RetentionDays      *int       `gorm:"column:retention_days"`
		LogTier            string     `gorm:"column:log_tier"`
		TierTransitionedAt *time.Time `gorm:"column:tier_transitioned_at"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM log_instances 
		WHERE log_tier = ? AND first_seen < ?
		ORDER BY first_seen ASC
	`, string(LogTierGracePeriod), cutoff).Scan(&rows).Error

	if err != nil {
		return nil, fmt.Errorf("failed to find expired grace period instances: %w", err)
	}

	instances := make([]LogInstance, len(rows))
	for i, row := range rows {
		instance := LogInstance{
			ID:             row.ID,
			Collection:     row.Collection,
			PrivateID:      row.PrivateID,
			PublicID:       row.PublicID,
			Persisted:      row.Persisted,
			FirstSeen:      row.FirstSeen,
			LastSeen:       row.LastSeen,
			TotalLogs:      row.TotalLogs,
			TotalSizeBytes: row.TotalSizeBytes,
			LogTier:        LogTier(row.LogTier),
		}

		// Handle nullable fields
		if row.PersistedAt != nil {
			instance.PersistedAt = *row.PersistedAt
		}
		if row.RetentionDays != nil {
			instance.RetentionDays = *row.RetentionDays
		}
		if row.TierTransitionedAt != nil {
			instance.TierTransitionedAt = *row.TierTransitionedAt
		}

		instances[i] = instance
	}

	return instances, nil
}

// DeleteEmptyInstances removes instances with no logs.
func (s *DBStorage) DeleteEmptyInstances(ctx context.Context) (int, error) {
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM log_instances WHERE total_logs = 0
	`)

	if result.Error != nil {
		return 0, fmt.Errorf("failed to delete empty instances: %w", result.Error)
	}

	return int(result.RowsAffected), nil
}

// GetPrivateIDAssociation retrieves association for a private ID.
func (s *DBStorage) GetPrivateIDAssociation(ctx context.Context, privateID string) (*PrivateIDAssociation, error) {
	var row struct {
		PrivateID    string `gorm:"column:private_id"`
		NodeID       uint64 `gorm:"column:node_id"`
		Collection   string
		AssociatedAt time.Time  `gorm:"column:associated_at"`
		CurrentIP    string     `gorm:"column:current_ip"`
		LastIPChange *time.Time `gorm:"column:last_ip_change"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM logtail_private_id_associations WHERE private_id = ?
	`, privateID).Scan(&row).Error

	if err == gorm.ErrRecordNotFound || row.PrivateID == "" {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get association: %w", err)
	}

	// Get recent IPs from observations (last 48 hours)
	recentIPs, err := s.getRecentIPsForPrivateID(ctx, privateID, 48)
	if err != nil {
		log.Warn().Err(err).Str("private_id", privateID).Msg("Failed to get recent IPs")
		recentIPs = []string{row.CurrentIP}
	}

	lastChange := time.Time{}
	if row.LastIPChange != nil {
		lastChange = *row.LastIPChange
	}

	return &PrivateIDAssociation{
		PrivateID:    row.PrivateID,
		NodeID:       row.NodeID,
		Collection:   row.Collection,
		AssociatedAt: row.AssociatedAt,
		CurrentIP:    row.CurrentIP,
		RecentIPs:    recentIPs,
		LastIPChange: lastChange,
	}, nil
}

// StorePrivateIDAssociation creates or updates an association.
func (s *DBStorage) StorePrivateIDAssociation(ctx context.Context, assoc *PrivateIDAssociation) error {
	now := time.Now()

	// Upsert association
	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO logtail_private_id_associations 
		(private_id, node_id, collection, associated_at, current_ip, last_ip_change)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(private_id) DO UPDATE SET
			node_id = excluded.node_id,
			collection = excluded.collection,
			current_ip = excluded.current_ip,
			last_ip_change = excluded.last_ip_change
	`, assoc.PrivateID, assoc.NodeID, assoc.Collection, now, assoc.CurrentIP, now).Error

	if err != nil {
		return fmt.Errorf("failed to store association: %w", err)
	}

	// Record IP observation
	err = s.RecordIPObservation(ctx, assoc.PrivateID, assoc.CurrentIP)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to record IP observation")
	}

	return nil
}

// UpdateRecentIPs adds a new IP to the recent IPs list.
func (s *DBStorage) UpdateRecentIPs(ctx context.Context, privateID, newIP string) error {
	now := time.Now()

	// Update current IP and timestamp
	err := s.db.WithContext(ctx).Exec(`
		UPDATE logtail_private_id_associations
		SET current_ip = ?, last_ip_change = ?
		WHERE private_id = ?
	`, newIP, now, privateID).Error

	if err != nil {
		return fmt.Errorf("failed to update recent IPs: %w", err)
	}

	// Record IP observation
	err = s.RecordIPObservation(ctx, privateID, newIP)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to record IP observation")
	}

	return nil
}

// DeletePrivateIDAssociation deletes an association.
func (s *DBStorage) DeletePrivateIDAssociation(ctx context.Context, privateID string) error {
	err := s.db.WithContext(ctx).Exec(`
		DELETE FROM logtail_private_id_associations WHERE private_id = ?
	`, privateID).Error

	if err != nil {
		return fmt.Errorf("failed to delete association: %w", err)
	}

	return nil
}

// GetAssociationsByNodeID retrieves all associations for a node.
func (s *DBStorage) GetAssociationsByNodeID(ctx context.Context, nodeID uint64) ([]PrivateIDAssociation, error) {
	var rows []struct {
		PrivateID    string `gorm:"column:private_id"`
		NodeID       uint64 `gorm:"column:node_id"`
		Collection   string
		AssociatedAt time.Time  `gorm:"column:associated_at"`
		CurrentIP    string     `gorm:"column:current_ip"`
		LastIPChange *time.Time `gorm:"column:last_ip_change"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM logtail_private_id_associations WHERE node_id = ?
	`, nodeID).Scan(&rows).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get associations by node ID: %w", err)
	}

	associations := make([]PrivateIDAssociation, len(rows))
	for i, row := range rows {
		lastChange := time.Time{}
		if row.LastIPChange != nil {
			lastChange = *row.LastIPChange
		}

		associations[i] = PrivateIDAssociation{
			PrivateID:    row.PrivateID,
			NodeID:       row.NodeID,
			Collection:   row.Collection,
			AssociatedAt: row.AssociatedAt,
			CurrentIP:    row.CurrentIP,
			RecentIPs:    []string{row.CurrentIP},
			LastIPChange: lastChange,
		}
	}

	return associations, nil
}

// getRecentIPsForPrivateID is a helper to get recent IPs from observations.
func (s *DBStorage) getRecentIPsForPrivateID(ctx context.Context, privateID string, windowHours int) ([]string, error) {
	cutoff := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	var ips []string
	err := s.db.WithContext(ctx).Raw(`
		SELECT DISTINCT ip_address 
		FROM logtail_ip_observations 
		WHERE private_id = ? AND last_seen >= ?
		ORDER BY last_seen DESC
		LIMIT 10
	`, privateID, cutoff).Scan(&ips).Error

	if err != nil {
		return nil, err
	}

	return ips, nil
}

// GetFirstSeen retrieves first seen record.
func (s *DBStorage) GetFirstSeen(ctx context.Context, privateID string) (*FirstSeenRecord, error) {
	var row struct {
		PrivateID    string `gorm:"column:private_id"`
		Collection   string
		FirstSeenAt  time.Time `gorm:"column:first_seen_at"`
		FirstSeenIP  string    `gorm:"column:first_seen_ip"`
		RequestCount int       `gorm:"column:request_count"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM logtail_first_seen WHERE private_id = ?
	`, privateID).Scan(&row).Error

	if err == gorm.ErrRecordNotFound || row.PrivateID == "" {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get first seen: %w", err)
	}

	return &FirstSeenRecord{
		PrivateID:    row.PrivateID,
		Collection:   row.Collection,
		FirstSeenAt:  row.FirstSeenAt,
		FirstSeenIP:  row.FirstSeenIP,
		RequestCount: row.RequestCount,
	}, nil
}

// RecordFirstSeen creates a first seen record.
func (s *DBStorage) RecordFirstSeen(ctx context.Context, record *FirstSeenRecord) error {
	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO logtail_first_seen 
		(private_id, collection, first_seen_at, first_seen_ip, request_count)
		VALUES (?, ?, ?, ?, 1)
	`, record.PrivateID, record.Collection, time.Now(), record.FirstSeenIP).Error

	if err != nil {
		return fmt.Errorf("failed to record first seen: %w", err)
	}

	return nil
}

// DeleteFirstSeen deletes a first seen record.
func (s *DBStorage) DeleteFirstSeen(ctx context.Context, privateID string) error {
	err := s.db.WithContext(ctx).Exec(`
		DELETE FROM logtail_first_seen WHERE private_id = ?
	`, privateID).Error

	if err != nil {
		return fmt.Errorf("failed to delete first seen: %w", err)
	}

	return nil
}

// IncrementFirstSeenCount increments the request count for a first seen record.
func (s *DBStorage) IncrementFirstSeenCount(ctx context.Context, privateID string) error {
	err := s.db.WithContext(ctx).Exec(`
		UPDATE logtail_first_seen
		SET request_count = request_count + 1
		WHERE private_id = ?
	`, privateID).Error

	if err != nil {
		return fmt.Errorf("failed to increment first seen count: %w", err)
	}

	return nil
}

// RecordIPObservation records an IP address observation.
func (s *DBStorage) RecordIPObservation(ctx context.Context, privateID, ipAddress string) error {
	now := time.Now()

	// Upsert IP observation
	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO logtail_ip_observations 
		(private_id, ip_address, first_seen, last_seen, observation_count, created_at)
		VALUES (?, ?, ?, ?, 1, ?)
		ON CONFLICT(private_id, ip_address) DO UPDATE SET
			last_seen = excluded.last_seen,
			observation_count = logtail_ip_observations.observation_count + 1
	`, privateID, ipAddress, now, now, now).Error

	if err != nil {
		return fmt.Errorf("failed to record IP observation: %w", err)
	}

	return nil
}

// GetRecentIPObservations retrieves recent IP observations for a private ID.
func (s *DBStorage) GetRecentIPObservations(ctx context.Context, privateID string, windowHours int) ([]IPObservation, error) {
	cutoff := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	var rows []struct {
		ID               uint64 `gorm:"column:id"`
		PrivateID        string `gorm:"column:private_id"`
		IPAddress        string `gorm:"column:ip_address"`
		FirstSeen        time.Time
		LastSeen         time.Time
		ObservationCount int `gorm:"column:observation_count"`
		CreatedAt        time.Time
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM logtail_ip_observations 
		WHERE private_id = ? AND last_seen >= ?
		ORDER BY last_seen DESC
	`, privateID, cutoff).Scan(&rows).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get recent IP observations: %w", err)
	}

	observations := make([]IPObservation, len(rows))
	for i, row := range rows {
		observations[i] = IPObservation{
			ID:               row.ID,
			PrivateID:        row.PrivateID,
			IPAddress:        row.IPAddress,
			FirstSeen:        row.FirstSeen,
			LastSeen:         row.LastSeen,
			ObservationCount: row.ObservationCount,
			CreatedAt:        row.CreatedAt,
		}
	}

	return observations, nil
}

// CleanupOldIPObservations removes IP observations older than cutoff days.
func (s *DBStorage) CleanupOldIPObservations(ctx context.Context, cutoffDays int) error {
	cutoff := time.Now().AddDate(0, 0, -cutoffDays)

	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM logtail_ip_observations WHERE last_seen < ?
	`, cutoff)

	if result.Error != nil {
		return fmt.Errorf("failed to cleanup old IP observations: %w", result.Error)
	}

	log.Info().
		Int("cutoff_days", cutoffDays).
		Int64("rows_deleted", result.RowsAffected).
		Msg("Cleaned up old IP observations")

	return nil
}

// ListCollections retrieves all unique collections.
func (s *DBStorage) ListCollections(ctx context.Context) ([]string, error) {
	var collections []string

	err := s.db.WithContext(ctx).Raw(`
		SELECT DISTINCT collection FROM log_instances ORDER BY collection
	`).Scan(&collections).Error

	if err != nil {
		return nil, fmt.Errorf("failed to list collections: %w", err)
	}

	return collections, nil
}

// ListInstancesInCollection retrieves all instances in a collection.
func (s *DBStorage) ListInstancesInCollection(ctx context.Context, collection string) ([]LogInstance, error) {
	var rows []struct {
		ID                 uint64
		Collection         string
		PrivateID          string `gorm:"column:private_id"`
		PublicID           string `gorm:"column:public_id"`
		Persisted          bool
		PersistedAt        *time.Time `gorm:"column:persisted_at"`
		FirstSeen          time.Time  `gorm:"column:first_seen"`
		LastSeen           time.Time  `gorm:"column:last_seen"`
		TotalLogs          int        `gorm:"column:total_logs"`
		TotalSizeBytes     int64      `gorm:"column:total_size_bytes"`
		RetentionDays      *int       `gorm:"column:retention_days"`
		LogTier            string     `gorm:"column:log_tier"`
		TierTransitionedAt *time.Time `gorm:"column:tier_transitioned_at"`
	}

	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM log_instances 
		WHERE collection = ?
		ORDER BY last_seen DESC
	`, collection).Scan(&rows).Error

	if err != nil {
		return nil, fmt.Errorf("failed to list instances in collection: %w", err)
	}

	instances := make([]LogInstance, len(rows))
	for i, row := range rows {
		instance := LogInstance{
			ID:             row.ID,
			Collection:     row.Collection,
			PrivateID:      row.PrivateID,
			PublicID:       row.PublicID,
			Persisted:      row.Persisted,
			FirstSeen:      row.FirstSeen,
			LastSeen:       row.LastSeen,
			TotalLogs:      row.TotalLogs,
			TotalSizeBytes: row.TotalSizeBytes,
			LogTier:        LogTier(row.LogTier),
		}

		// Handle nullable fields
		if row.PersistedAt != nil {
			instance.PersistedAt = *row.PersistedAt
		}
		if row.RetentionDays != nil {
			instance.RetentionDays = *row.RetentionDays
		}
		if row.TierTransitionedAt != nil {
			instance.TierTransitionedAt = *row.TierTransitionedAt
		}

		instances[i] = instance
	}

	return instances, nil
}
