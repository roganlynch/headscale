package logtail

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDefaultConfig creates a default configuration for testing
func testDefaultConfig() types.LogTailServerConfig {
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

func TestNewAuthenticator(t *testing.T) {
	config := testDefaultConfig()
	auth := NewAuthenticator(config)

	assert.NotNil(t, auth)
	assert.Equal(t, config, auth.config)
}

func TestAuthenticateLogWrite_NoAssociation_NoRegistrationRequired(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.RequireNodeRegistration = false
	auth := NewAuthenticator(config)

	result := auth.AuthenticateLogWrite(nil, nil, "10.0.0.1")

	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "not required")
	assert.False(t, result.IsGracePeriod)
}

func TestAuthenticateLogWrite_NoAssociation_FirstSeen_GracePeriod(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.RequireNodeRegistration = true
	config.Auth.WriteAuth.PreAuthGracePeriodSeconds = 300
	auth := NewAuthenticator(config)

	// No first seen record - should start grace period
	result := auth.AuthenticateLogWrite(nil, nil, "10.0.0.1")

	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "grace period started")
	assert.True(t, result.IsGracePeriod)
}

func TestAuthenticateLogWrite_NoAssociation_WithinGracePeriod(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.RequireNodeRegistration = true
	config.Auth.WriteAuth.PreAuthGracePeriodSeconds = 300
	auth := NewAuthenticator(config)

	firstSeen := &FirstSeenRecord{
		PrivateID:   "test-id",
		FirstSeenAt: time.Now().Add(-2 * time.Minute), // 2 minutes ago
	}

	result := auth.AuthenticateLogWrite(nil, firstSeen, "10.0.0.1")

	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "within grace period")
	assert.True(t, result.IsGracePeriod)
}

func TestAuthenticateLogWrite_NoAssociation_GracePeriodExpired(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.RequireNodeRegistration = true
	config.Auth.WriteAuth.PreAuthGracePeriodSeconds = 300
	auth := NewAuthenticator(config)

	firstSeen := &FirstSeenRecord{
		PrivateID:   "test-id",
		FirstSeenAt: time.Now().Add(-10 * time.Minute), // 10 minutes ago
	}

	result := auth.AuthenticateLogWrite(nil, firstSeen, "10.0.0.1")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "grace period expired")
	assert.False(t, result.IsGracePeriod)
}

func TestAuthenticateLogWrite_Associated_IPValidationDisabled(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Enabled = false
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		NodeID:    1,
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.AuthenticateLogWrite(association, nil, "10.0.0.2")

	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "IP validation disabled")
}

func TestAuthenticateLogWrite_Associated_ExactIPMatch(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Enabled = true
	config.Auth.WriteAuth.IPValidation.Mode = "strict"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		NodeID:    1,
		RecentIPs: []string{"10.0.0.1", "10.0.0.2"},
	}

	result := auth.AuthenticateLogWrite(association, nil, "10.0.0.1")

	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "exact IP match")
}

func TestAuthenticateLogWrite_Associated_StrictMode_NoMatch(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Enabled = true
	config.Auth.WriteAuth.IPValidation.Mode = "strict"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		NodeID:    1,
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.AuthenticateLogWrite(association, nil, "10.0.0.2")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "strict mode")
}

func TestValidateIP_ModeNone(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "none"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "192.168.1.1")

	assert.True(t, result.Allowed)
	assert.Contains(t, result.Reason, "disabled")
}

func TestValidateIP_StrictMode_ExactMatch(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "strict"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1", "10.0.0.2"},
	}

	result := auth.ValidateIP(association, "10.0.0.2")

	assert.True(t, result.Allowed)
	assert.True(t, result.IsExactMatch)
	assert.False(t, result.IsSubnetMatch)
}

func TestValidateIP_StrictMode_NoMatch(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "strict"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "10.0.0.2")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "strict mode")
}

func TestValidateIP_RelaxedMode_ExactMatch(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "10.0.0.1")

	assert.True(t, result.Allowed)
	assert.True(t, result.IsExactMatch)
}

func TestValidateIP_RelaxedMode_SubnetMatch(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	config.Auth.WriteAuth.IPValidation.AllowIPChanges = true
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "10.0.0.50")

	assert.True(t, result.Allowed)
	assert.False(t, result.IsExactMatch)
	assert.True(t, result.IsSubnetMatch)
	assert.Contains(t, result.Reason, "/24")
}

func TestValidateIP_RelaxedMode_SubnetMatch_ChangesNotAllowed(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	config.Auth.WriteAuth.IPValidation.AllowIPChanges = false
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "10.0.0.50")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "IP changes not allowed")
}

func TestValidateIP_RelaxedMode_DifferentSubnet(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	config.Auth.WriteAuth.IPValidation.AllowIPChanges = true
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "10.0.1.1")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "not in same /24 subnet")
}

func TestValidateIP_UnknownMode(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "unknown"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "10.0.0.1")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "unknown IP validation mode")
}

func TestValidateIP_InvalidClientIP(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	result := auth.ValidateIP(association, "invalid-ip")

	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "invalid client IP format")
}

func TestIsSameSubnet24(t *testing.T) {
	tests := []struct {
		name     string
		ip1      string
		ip2      string
		expected bool
	}{
		{"exact match", "10.0.0.1", "10.0.0.1", true},
		{"same subnet", "10.0.0.1", "10.0.0.255", true},
		{"same subnet different IPs", "192.168.1.10", "192.168.1.200", true},
		{"different subnet", "10.0.0.1", "10.0.1.1", false},
		{"completely different", "10.0.0.1", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr1, err := netip.ParseAddr(tt.ip1)
			require.NoError(t, err)

			addr2, err := netip.ParseAddr(tt.ip2)
			require.NoError(t, err)

			result := isSameSubnet24(addr1, addr2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldUpdateRecentIPs(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Enabled = true
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	tests := []struct {
		name     string
		clientIP string
		ipResult IPValidationResult
		want     bool
	}{
		{
			name:     "validation failed",
			clientIP: "10.0.1.1",
			ipResult: IPValidationResult{Allowed: false},
			want:     false,
		},
		{
			name:     "exact match",
			clientIP: "10.0.0.1",
			ipResult: IPValidationResult{Allowed: true, IsExactMatch: true},
			want:     false,
		},
		{
			name:     "subnet match",
			clientIP: "10.0.0.50",
			ipResult: IPValidationResult{Allowed: true, IsSubnetMatch: true},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.ShouldUpdateRecentIPs(association, tt.clientIP, tt.ipResult)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestShouldUpdateRecentIPs_ValidationDisabled(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Enabled = false
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		RecentIPs: []string{"10.0.0.1"},
	}

	// New IP when validation disabled
	result := auth.ShouldUpdateRecentIPs(
		association,
		"10.0.0.2",
		IPValidationResult{Allowed: true},
	)
	assert.True(t, result, "should update for new IP when validation disabled")

	// Existing IP when validation disabled
	result = auth.ShouldUpdateRecentIPs(
		association,
		"10.0.0.1",
		IPValidationResult{Allowed: true},
	)
	assert.False(t, result, "should not update for existing IP")
}

func TestAuthenticateLogWrite_MultipleRecentIPs(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Enabled = true
	config.Auth.WriteAuth.IPValidation.Mode = "strict"
	auth := NewAuthenticator(config)

	association := &PrivateIDAssociation{
		PrivateID: "test-id",
		NodeID:    1,
		RecentIPs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
	}

	// Test with each IP in the list
	for _, ip := range association.RecentIPs {
		result := auth.AuthenticateLogWrite(association, nil, ip)
		assert.True(t, result.Allowed, "IP %s should be allowed", ip)
		assert.Contains(t, result.Reason, "exact IP match")
	}

	// Test with an IP not in the list
	result := auth.AuthenticateLogWrite(association, nil, "10.0.0.4")
	assert.False(t, result.Allowed)
}

func TestCheckGracePeriod_EdgeCases(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.PreAuthGracePeriodSeconds = 300 // 5 minutes
	auth := NewAuthenticator(config)

	t.Run("exactly at grace period boundary", func(t *testing.T) {
		firstSeen := &FirstSeenRecord{
			PrivateID:   "test-id",
			FirstSeenAt: time.Now().Add(-5 * time.Minute),
		}

		result := auth.checkGracePeriod(firstSeen)
		// Should be expired (grace period is exclusive, not inclusive)
		assert.False(t, result.Allowed)
	})

	t.Run("just before grace period expires", func(t *testing.T) {
		firstSeen := &FirstSeenRecord{
			PrivateID:   "test-id",
			FirstSeenAt: time.Now().Add(-4*time.Minute - 59*time.Second),
		}

		result := auth.checkGracePeriod(firstSeen)
		assert.True(t, result.Allowed)
		assert.True(t, result.IsGracePeriod)
	})
}

func TestValidateIPRelaxed_EdgeCases(t *testing.T) {
	config := testDefaultConfig()
	config.Auth.WriteAuth.IPValidation.Mode = "relaxed"
	config.Auth.WriteAuth.IPValidation.AllowIPChanges = true
	auth := NewAuthenticator(config)

	t.Run("multiple recent IPs, one matches subnet", func(t *testing.T) {
		association := &PrivateIDAssociation{
			PrivateID: "test-id",
			RecentIPs: []string{"10.0.0.1", "192.168.1.1", "10.0.0.50"},
		}

		result := auth.ValidateIP(association, "10.0.0.100")

		assert.True(t, result.Allowed)
		assert.True(t, result.IsSubnetMatch)
	})

	t.Run("invalid IP in recent IPs list", func(t *testing.T) {
		association := &PrivateIDAssociation{
			PrivateID: "test-id",
			RecentIPs: []string{"invalid-ip", "10.0.0.1"},
		}

		// Should skip invalid IP and check valid ones
		result := auth.ValidateIP(association, "10.0.0.50")

		assert.True(t, result.Allowed)
		assert.True(t, result.IsSubnetMatch)
	})

	t.Run("empty recent IPs list", func(t *testing.T) {
		association := &PrivateIDAssociation{
			PrivateID: "test-id",
			RecentIPs: []string{},
		}

		result := auth.ValidateIP(association, "10.0.0.1")

		assert.False(t, result.Allowed)
	})
}
