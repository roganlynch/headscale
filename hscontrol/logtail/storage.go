package logtail

import (
	"context"
	"time"
)

// Storage defines the interface for logtail log storage operations.
// This interface abstracts database operations for testing and flexibility.
type Storage interface {
	// Log storage operations
	StoreLogs(ctx context.Context, logs []LogEntry) error
	QueryLogs(ctx context.Context, query LogQuery) ([]LogEntry, error)
	DeleteLogsByTier(ctx context.Context, privateID, collection string, tier LogTier) (int, int64, error)
	DeleteOldLogsByTier(ctx context.Context, tier LogTier, cutoff time.Time) (int, int64, error)
	DeleteOldLogsForInstance(ctx context.Context, privateID, collection string, tier LogTier, cutoff time.Time) (int, int64, error)

	// Instance management operations
	GetLogInstance(ctx context.Context, privateID, collection string) (*LogInstance, error)
	UpdateInstancePersistence(ctx context.Context, privateID, collection string, persisted bool, retentionDays int) error
	UpdateInstanceTier(ctx context.Context, privateID, collection string, tier LogTier) error
	GetPersistedInstances(ctx context.Context) ([]LogInstance, error)
	FindExpiredGracePeriodInstances(ctx context.Context, cutoff time.Time) ([]LogInstance, error)
	DeleteEmptyInstances(ctx context.Context) (int, error)

	// Tier migration operations
	MigrateLogTier(ctx context.Context, privateID, collection string, fromTier, toTier LogTier) error

	// Association management operations
	GetPrivateIDAssociation(ctx context.Context, privateID string) (*PrivateIDAssociation, error)
	StorePrivateIDAssociation(ctx context.Context, assoc *PrivateIDAssociation) error
	UpdateRecentIPs(ctx context.Context, privateID, newIP string) error
	DeletePrivateIDAssociation(ctx context.Context, privateID string) error
	GetAssociationsByNodeID(ctx context.Context, nodeID uint64) ([]PrivateIDAssociation, error)

	// First seen tracking operations
	GetFirstSeen(ctx context.Context, privateID string) (*FirstSeenRecord, error)
	RecordFirstSeen(ctx context.Context, record *FirstSeenRecord) error
	DeleteFirstSeen(ctx context.Context, privateID string) error
	IncrementFirstSeenCount(ctx context.Context, privateID string) error

	// IP observation operations
	RecordIPObservation(ctx context.Context, privateID, ipAddress string) error
	GetRecentIPObservations(ctx context.Context, privateID string, windowHours int) ([]IPObservation, error)
	CleanupOldIPObservations(ctx context.Context, cutoffDays int) error

	// Collection operations
	ListCollections(ctx context.Context) ([]string, error)
	ListInstancesInCollection(ctx context.Context, collection string) ([]LogInstance, error)
}

// LogQuery defines parameters for querying logs.
type LogQuery struct {
	Collection string
	PrivateIDs []string
	PublicIDs  []string
	TimeStart  *time.Time
	TimeEnd    *time.Time
	MaxCount   int
	Tier       *LogTier
}
