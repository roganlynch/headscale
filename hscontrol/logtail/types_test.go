package logtail

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogTier_String(t *testing.T) {
	tests := []struct {
		name string
		tier LogTier
		want string
	}{
		{"grace period", LogTierGracePeriod, "grace_period"},
		{"ephemeral", LogTierEphemeral, "ephemeral"},
		{"persisted", LogTierPersisted, "persisted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.tier.String())
		})
	}
}

func TestLogTierConstants(t *testing.T) {
	// Verify the tier constants have correct values
	assert.Equal(t, LogTier("grace_period"), LogTierGracePeriod)
	assert.Equal(t, LogTier("ephemeral"), LogTierEphemeral)
	assert.Equal(t, LogTier("persisted"), LogTierPersisted)

	// Verify they are different from each other
	assert.NotEqual(t, LogTierGracePeriod, LogTierEphemeral)
	assert.NotEqual(t, LogTierEphemeral, LogTierPersisted)
	assert.NotEqual(t, LogTierGracePeriod, LogTierPersisted)
}

func TestLogEntry_Structure(t *testing.T) {
	now := time.Now()
	entry := LogEntry{
		ID:         123,
		Collection: "tailnode.log.tailscale.io",
		PrivateID:  "priv123",
		PublicID:   "pub123",
		Timestamp:  now,
		LogData:    []byte(`{"text":"test log"}`),
		SizeBytes:  100,
		Persisted:  false,
		LogTier:    LogTierEphemeral,
		CreatedAt:  now,
	}

	assert.Equal(t, uint64(123), entry.ID)
	assert.Equal(t, "tailnode.log.tailscale.io", entry.Collection)
	assert.Equal(t, "priv123", entry.PrivateID)
	assert.Equal(t, "pub123", entry.PublicID)
	assert.Equal(t, now, entry.Timestamp)
	assert.Equal(t, []byte(`{"text":"test log"}`), entry.LogData)
	assert.Equal(t, 100, entry.SizeBytes)
	assert.False(t, entry.Persisted)
	assert.Equal(t, LogTierEphemeral, entry.LogTier)
	assert.Equal(t, now, entry.CreatedAt)
}

func TestLogInstance_Structure(t *testing.T) {
	now := time.Now()
	instance := LogInstance{
		ID:                 1,
		Collection:         "tailnode.log.tailscale.io",
		PrivateID:          "priv123",
		PublicID:           "pub123",
		Persisted:          true,
		PersistedAt:        now,
		FirstSeen:          now.Add(-24 * time.Hour),
		LastSeen:           now,
		TotalLogs:          1000,
		TotalSizeBytes:     1024000,
		RetentionDays:      30,
		LogTier:            LogTierPersisted,
		TierTransitionedAt: now.Add(-1 * time.Hour),
	}

	assert.Equal(t, uint64(1), instance.ID)
	assert.Equal(t, "tailnode.log.tailscale.io", instance.Collection)
	assert.True(t, instance.Persisted)
	assert.Equal(t, 1000, instance.TotalLogs)
	assert.Equal(t, int64(1024000), instance.TotalSizeBytes)
	assert.Equal(t, 30, instance.RetentionDays)
	assert.Equal(t, LogTierPersisted, instance.LogTier)
}

func TestPrivateIDAssociation_Structure(t *testing.T) {
	now := time.Now()
	assoc := PrivateIDAssociation{
		PrivateID:    "priv123",
		NodeID:       456,
		Collection:   "tailnode.log.tailscale.io",
		AssociatedAt: now,
		CurrentIP:    "10.0.0.1",
		RecentIPs:    []string{"10.0.0.1", "10.0.0.2"},
		LastIPChange: now.Add(-1 * time.Hour),
	}

	assert.Equal(t, "priv123", assoc.PrivateID)
	assert.Equal(t, uint64(456), assoc.NodeID)
	assert.Equal(t, "10.0.0.1", assoc.CurrentIP)
	assert.Len(t, assoc.RecentIPs, 2)
	assert.Contains(t, assoc.RecentIPs, "10.0.0.1")
	assert.Contains(t, assoc.RecentIPs, "10.0.0.2")
}

func TestIPObservation_Structure(t *testing.T) {
	now := time.Now()
	obs := IPObservation{
		ID:               1,
		PrivateID:        "priv123",
		IPAddress:        "10.0.0.1",
		FirstSeen:        now.Add(-24 * time.Hour),
		LastSeen:         now,
		ObservationCount: 10,
		CreatedAt:        now.Add(-24 * time.Hour),
	}

	assert.Equal(t, uint64(1), obs.ID)
	assert.Equal(t, "priv123", obs.PrivateID)
	assert.Equal(t, "10.0.0.1", obs.IPAddress)
	assert.Equal(t, 10, obs.ObservationCount)
}

func TestFirstSeenRecord_Structure(t *testing.T) {
	now := time.Now()
	record := FirstSeenRecord{
		PrivateID:    "priv123",
		Collection:   "tailnode.log.tailscale.io",
		FirstSeenAt:  now,
		FirstSeenIP:  "10.0.0.1",
		RequestCount: 5,
	}

	assert.Equal(t, "priv123", record.PrivateID)
	assert.Equal(t, "tailnode.log.tailscale.io", record.Collection)
	assert.Equal(t, "10.0.0.1", record.FirstSeenIP)
	assert.Equal(t, 5, record.RequestCount)
}

func TestRateLimitWindow_Structure(t *testing.T) {
	now := time.Now()
	window := RateLimitWindow{
		PrivateID:    "priv123",
		RequestCount: 10,
		WindowStart:  now,
		LastRequest:  now.Add(30 * time.Second),
	}

	assert.Equal(t, "priv123", window.PrivateID)
	assert.Equal(t, 10, window.RequestCount)
	assert.Equal(t, now, window.WindowStart)
}

func TestAuthResult_Structure(t *testing.T) {
	tests := []struct {
		name                string
		result              AuthResult
		expectedAllowed     bool
		expectedReason      string
		expectedGracePeriod bool
	}{
		{
			name: "allowed with grace period",
			result: AuthResult{
				Allowed:       true,
				Reason:        "within grace period",
				IsGracePeriod: true,
			},
			expectedAllowed:     true,
			expectedReason:      "within grace period",
			expectedGracePeriod: true,
		},
		{
			name: "allowed authenticated",
			result: AuthResult{
				Allowed:       true,
				Reason:        "IP validated",
				IsGracePeriod: false,
			},
			expectedAllowed:     true,
			expectedReason:      "IP validated",
			expectedGracePeriod: false,
		},
		{
			name: "rejected IP mismatch",
			result: AuthResult{
				Allowed:       false,
				Reason:        "IP address mismatch",
				IsGracePeriod: false,
			},
			expectedAllowed:     false,
			expectedReason:      "IP address mismatch",
			expectedGracePeriod: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedAllowed, tt.result.Allowed)
			assert.Equal(t, tt.expectedReason, tt.result.Reason)
			assert.Equal(t, tt.expectedGracePeriod, tt.result.IsGracePeriod)
		})
	}
}

func TestIPValidationResult_Structure(t *testing.T) {
	tests := []struct {
		name        string
		result      IPValidationResult
		wantAllowed bool
		wantExact   bool
		wantSubnet  bool
	}{
		{
			name: "exact match",
			result: IPValidationResult{
				Allowed:       true,
				Reason:        "exact IP match",
				IsExactMatch:  true,
				IsSubnetMatch: false,
			},
			wantAllowed: true,
			wantExact:   true,
			wantSubnet:  false,
		},
		{
			name: "subnet match",
			result: IPValidationResult{
				Allowed:       true,
				Reason:        "subnet match within /24",
				IsExactMatch:  false,
				IsSubnetMatch: true,
			},
			wantAllowed: true,
			wantExact:   false,
			wantSubnet:  true,
		},
		{
			name: "no match",
			result: IPValidationResult{
				Allowed:       false,
				Reason:        "no IP match found",
				IsExactMatch:  false,
				IsSubnetMatch: false,
			},
			wantAllowed: false,
			wantExact:   false,
			wantSubnet:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantAllowed, tt.result.Allowed)
			assert.Equal(t, tt.wantExact, tt.result.IsExactMatch)
			assert.Equal(t, tt.wantSubnet, tt.result.IsSubnetMatch)
		})
	}
}

func TestCachedAuthResult_Structure(t *testing.T) {
	now := time.Now()
	expiry := now.Add(1 * time.Minute)

	cached := CachedAuthResult{
		Result: AuthResult{
			Allowed:       true,
			Reason:        "cached result",
			IsGracePeriod: false,
		},
		ExpiresAt: expiry,
	}

	assert.True(t, cached.Result.Allowed)
	assert.Equal(t, "cached result", cached.Result.Reason)
	assert.Equal(t, expiry, cached.ExpiresAt)

	// Test expiration check
	assert.True(t, now.Before(cached.ExpiresAt), "should not be expired yet")
	assert.False(t, now.Add(2*time.Minute).Before(cached.ExpiresAt), "should be expired")
}

func TestCleanupStats_Structure(t *testing.T) {
	stats := CleanupStats{
		GracePeriodLogsDeleted: 100,
		EphemeralLogsDeleted:   200,
		PersistedLogsDeleted:   50,
		InstancesDeleted:       5,
		BytesFreed:             1024000,
		Duration:               30 * time.Second,
	}

	assert.Equal(t, 100, stats.GracePeriodLogsDeleted)
	assert.Equal(t, 200, stats.EphemeralLogsDeleted)
	assert.Equal(t, 50, stats.PersistedLogsDeleted)
	assert.Equal(t, 5, stats.InstancesDeleted)
	assert.Equal(t, int64(1024000), stats.BytesFreed)
	assert.Equal(t, 30*time.Second, stats.Duration)

	// Calculate total logs deleted
	totalDeleted := stats.GracePeriodLogsDeleted + stats.EphemeralLogsDeleted + stats.PersistedLogsDeleted
	assert.Equal(t, 350, totalDeleted)
}

func TestQueryOptions_Structure(t *testing.T) {
	now := time.Now()
	opts := QueryOptions{
		Collection:    "tailnode.log.tailscale.io",
		PrivateID:     "priv123",
		PublicID:      "pub123",
		TimeStart:     now.Add(-24 * time.Hour),
		TimeEnd:       now,
		MaxCount:      100,
		Tier:          LogTierEphemeral,
		PersistedOnly: false,
	}

	assert.Equal(t, "tailnode.log.tailscale.io", opts.Collection)
	assert.Equal(t, "priv123", opts.PrivateID)
	assert.Equal(t, "pub123", opts.PublicID)
	assert.Equal(t, 100, opts.MaxCount)
	assert.Equal(t, LogTierEphemeral, opts.Tier)
	assert.False(t, opts.PersistedOnly)
}

func TestCollectionInfo_Structure(t *testing.T) {
	info := CollectionInfo{
		Collection:     "tailnode.log.tailscale.io",
		InstanceCount:  10,
		TotalLogs:      1000,
		TotalSizeBytes: 1024000,
	}

	assert.Equal(t, "tailnode.log.tailscale.io", info.Collection)
	assert.Equal(t, 10, info.InstanceCount)
	assert.Equal(t, 1000, info.TotalLogs)
	assert.Equal(t, int64(1024000), info.TotalSizeBytes)
}

func TestLogtailCache_Concurrency(t *testing.T) {
	// Test that LogtailCache uses sync.Map which is safe for concurrent access
	cache := &LogtailCache{}

	// Test concurrent writes to rateLimits
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			cache.rateLimits.Store("test", &RateLimitWindow{
				PrivateID:    "test",
				RequestCount: id,
			})
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should be able to load without panic
	val, ok := cache.rateLimits.Load("test")
	assert.True(t, ok)
	assert.NotNil(t, val)
}

func TestLogtailCache_AllFields(t *testing.T) {
	cache := &LogtailCache{}

	// Test all cache fields can store and retrieve values
	now := time.Now()

	// Rate limits
	cache.rateLimits.Store("test1", &RateLimitWindow{PrivateID: "test1"})
	val, ok := cache.rateLimits.Load("test1")
	assert.True(t, ok)
	assert.Equal(t, "test1", val.(*RateLimitWindow).PrivateID)

	// First seen
	cache.firstSeen.Store("test2", &FirstSeenRecord{PrivateID: "test2"})
	val, ok = cache.firstSeen.Load("test2")
	assert.True(t, ok)
	assert.Equal(t, "test2", val.(*FirstSeenRecord).PrivateID)

	// Recent IPs
	cache.recentIPs.Store("test3", []string{"10.0.0.1"})
	val, ok = cache.recentIPs.Load("test3")
	assert.True(t, ok)
	assert.Equal(t, []string{"10.0.0.1"}, val.([]string))

	// Auth cache
	cache.authCache.Store("test4", &CachedAuthResult{
		Result:    AuthResult{Allowed: true},
		ExpiresAt: now.Add(1 * time.Minute),
	})
	val, ok = cache.authCache.Load("test4")
	assert.True(t, ok)
	assert.True(t, val.(*CachedAuthResult).Result.Allowed)

	// Instance tiers
	cache.instanceTiers.Store("test5", LogTierPersisted)
	val, ok = cache.instanceTiers.Load("test5")
	assert.True(t, ok)
	assert.Equal(t, LogTierPersisted, val.(LogTier))
}
