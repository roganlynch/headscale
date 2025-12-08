package logtail

import (
	"sync"
	"time"
)

// LogTier represents the three-tier log classification system
type LogTier string

const (
	// LogTierGracePeriod represents logs from unauthenticated clients during grace period
	LogTierGracePeriod LogTier = "grace_period"

	// LogTierEphemeral represents logs from authenticated clients (passed IP validation)
	// that have not been explicitly persisted by an administrator
	LogTierEphemeral LogTier = "ephemeral"

	// LogTierPersisted represents logs that have been explicitly persisted by an administrator
	// and will be retained according to custom retention policies
	LogTierPersisted LogTier = "persisted"
)

// String returns the string representation of the LogTier
func (lt LogTier) String() string {
	return string(lt)
}

// LogEntry represents a single log entry from a Tailscale client
type LogEntry struct {
	ID         uint64    `json:"id"`
	Collection string    `json:"collection"`
	PrivateID  string    `json:"private_id"`
	PublicID   string    `json:"public_id"`
	Timestamp  time.Time `json:"timestamp"`
	LogData    []byte    `json:"log_data"` // JSON-encoded log data
	SizeBytes  int       `json:"size_bytes"`
	Persisted  bool      `json:"persisted"`
	LogTier    LogTier   `json:"log_tier"`
	CreatedAt  time.Time `json:"created_at"`
}

// LogInstance represents metadata for a logging instance (private ID)
type LogInstance struct {
	ID                 uint64    `json:"id"`
	Collection         string    `json:"collection"`
	PrivateID          string    `json:"private_id"`
	PublicID           string    `json:"public_id"`
	Persisted          bool      `json:"persisted"`
	PersistedAt        time.Time `json:"persisted_at,omitempty"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	TotalLogs          int       `json:"total_logs"`
	TotalSizeBytes     int64     `json:"total_size_bytes"`
	RetentionDays      int       `json:"retention_days,omitempty"`
	LogTier            LogTier   `json:"log_tier"`
	TierTransitionedAt time.Time `json:"tier_transitioned_at,omitempty"`
}

// PrivateIDAssociation represents the association between a private ID and a registered node
type PrivateIDAssociation struct {
	PrivateID    string    `json:"private_id"`
	NodeID       uint64    `json:"node_id"`
	Collection   string    `json:"collection"`
	AssociatedAt time.Time `json:"associated_at"`
	CurrentIP    string    `json:"current_ip"`
	RecentIPs    []string  `json:"recent_ips"`
	LastIPChange time.Time `json:"last_ip_change,omitempty"`
}

// IPObservation represents an IP address observation for a private ID
type IPObservation struct {
	ID               uint64    `json:"id"`
	PrivateID        string    `json:"private_id"`
	IPAddress        string    `json:"ip_address"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ObservationCount int       `json:"observation_count"`
	CreatedAt        time.Time `json:"created_at"`
}

// FirstSeenRecord tracks the first time a private ID is seen (for grace period)
type FirstSeenRecord struct {
	PrivateID    string    `json:"private_id"`
	Collection   string    `json:"collection"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	FirstSeenIP  string    `json:"first_seen_ip"`
	RequestCount int       `json:"request_count"`
}

// RateLimitWindow represents rate limiting state for a private ID
type RateLimitWindow struct {
	PrivateID    string    `json:"private_id"`
	RequestCount int       `json:"request_count"`
	WindowStart  time.Time `json:"window_start"`
	LastRequest  time.Time `json:"last_request"`
}

// AuthResult represents the result of write authentication check
type AuthResult struct {
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
	IsGracePeriod bool   `json:"is_grace_period"`
}

// IPValidationResult represents the result of IP address validation
type IPValidationResult struct {
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
	IsExactMatch  bool   `json:"is_exact_match"`
	IsSubnetMatch bool   `json:"is_subnet_match"`
}

// LogtailCache holds in-memory caches for hot-path data
// This cache layer eliminates ~70% of DB operations for active clients
type LogtailCache struct {
	// Rate limiting (1-minute TTL) - eliminates 2 DB ops per request
	rateLimits sync.Map // key: privateID -> *RateLimitWindow

	// First-seen during grace period (5-minute TTL) - eliminates 1 DB read during grace period
	firstSeen sync.Map // key: privateID -> *FirstSeenRecord

	// Recent IPs for validation (TTL = validation_window_hours) - eliminates complex time-windowed query
	recentIPs sync.Map // key: privateID -> []string

	// Authentication results (1-minute TTL) - eliminates all DB reads for same client within window
	authCache sync.Map // key: privateID -> *CachedAuthResult

	// Instance tier state (updated on migrations) - quick tier checks
	instanceTiers sync.Map // key: privateID+collection -> LogTier
}

// CachedAuthResult stores authentication results with expiration
type CachedAuthResult struct {
	Result    AuthResult
	ExpiresAt time.Time
}

// CleanupStats represents statistics from a cleanup operation
type CleanupStats struct {
	GracePeriodLogsDeleted int
	EphemeralLogsDeleted   int
	PersistedLogsDeleted   int
	InstancesDeleted       int
	BytesFreed             int64
	Duration               time.Duration
}

// QueryOptions represents options for querying logs
type QueryOptions struct {
	Collection    string
	PrivateID     string
	PublicID      string
	TimeStart     time.Time
	TimeEnd       time.Time
	MaxCount      int
	Tier          LogTier
	PersistedOnly bool
}

// CollectionInfo represents information about a log collection
type CollectionInfo struct {
	Collection     string `json:"collection"`
	InstanceCount  int    `json:"instance_count"`
	TotalLogs      int    `json:"total_logs"`
	TotalSizeBytes int64  `json:"total_size_bytes"`
}
