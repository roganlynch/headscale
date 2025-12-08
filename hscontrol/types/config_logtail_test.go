package types

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLogtailConfigDefaults(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Set defaults (simulating LoadConfig)
	viper.SetDefault("logtail.enabled", false)
	viper.SetDefault("logtail.server.enabled", false)
	viper.SetDefault("logtail.server.enable_cache", true)
	viper.SetDefault("logtail.server.retention.ephemeral_minutes", 720)
	viper.SetDefault("logtail.server.retention.persisted_default_days", 30)
	viper.SetDefault("logtail.server.retention.cleanup_interval_hours", 1)
	viper.SetDefault("logtail.server.rate_limit.requests_per_minute", 10)
	viper.SetDefault("logtail.server.auth.write_auth.require_node_registration", true)
	viper.SetDefault("logtail.server.auth.write_auth.pre_auth_grace_period_seconds", 300)
	viper.SetDefault("logtail.server.auth.write_auth.ip_validation.enabled", true)
	viper.SetDefault("logtail.server.auth.write_auth.ip_validation.mode", "relaxed")
	viper.SetDefault("logtail.server.auth.write_auth.ip_validation.allow_ip_changes", true)
	viper.SetDefault("logtail.server.auth.write_auth.ip_validation.validation_window_hours", 48)
	viper.SetDefault("logtail.server.auth.write_auth.ip_validation.cleanup_history_days", 30)
	viper.SetDefault("logtail.server.auth.write_auth.ip_validation.log_ip_mismatches", true)

	config := logtailConfig()

	// Test client-side (deprecated) defaults
	assert.False(t, config.Enabled, "logtail.enabled should default to false")

	// Test server defaults
	assert.False(t, config.Server.Enabled, "logtail.server.enabled should default to false")
	assert.True(t, config.Server.EnableCache, "logtail.server.enable_cache should default to true")

	// Test retention defaults
	assert.Equal(t, 720, config.Server.Retention.EphemeralMinutes)
	assert.Equal(t, 30, config.Server.Retention.PersistedDefaultDays)
	assert.Equal(t, 1, config.Server.Retention.CleanupIntervalHours)

	// Test rate limit defaults
	assert.Equal(t, 10, config.Server.RateLimit.RequestsPerMinute)

	// Test auth defaults
	assert.True(t, config.Server.Auth.WriteAuth.RequireNodeRegistration)
	assert.Equal(t, 300, config.Server.Auth.WriteAuth.PreAuthGracePeriodSeconds)

	// Test IP validation defaults
	assert.True(t, config.Server.Auth.WriteAuth.IPValidation.Enabled)
	assert.Equal(t, "relaxed", config.Server.Auth.WriteAuth.IPValidation.Mode)
	assert.True(t, config.Server.Auth.WriteAuth.IPValidation.AllowIPChanges)
	assert.Equal(t, 48, config.Server.Auth.WriteAuth.IPValidation.ValidationWindowHours)
	assert.Equal(t, 30, config.Server.Auth.WriteAuth.IPValidation.CleanupHistoryDays)
	assert.True(t, config.Server.Auth.WriteAuth.IPValidation.LogIPMismatches)
}

func TestLogtailConfigCustomValues(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Set custom values
	viper.Set("logtail.enabled", true)
	viper.Set("logtail.server.enabled", true)
	viper.Set("logtail.server.enable_cache", false)
	viper.Set("logtail.server.retention.ephemeral_minutes", 360)
	viper.Set("logtail.server.retention.persisted_default_days", 90)
	viper.Set("logtail.server.retention.cleanup_interval_hours", 2)
	viper.Set("logtail.server.rate_limit.requests_per_minute", 5)
	viper.Set("logtail.server.auth.write_auth.require_node_registration", false)
	viper.Set("logtail.server.auth.write_auth.pre_auth_grace_period_seconds", 60)
	viper.Set("logtail.server.auth.write_auth.ip_validation.enabled", false)
	viper.Set("logtail.server.auth.write_auth.ip_validation.mode", "strict")
	viper.Set("logtail.server.auth.write_auth.ip_validation.allow_ip_changes", false)
	viper.Set("logtail.server.auth.write_auth.ip_validation.validation_window_hours", 24)
	viper.Set("logtail.server.auth.write_auth.ip_validation.cleanup_history_days", 7)
	viper.Set("logtail.server.auth.write_auth.ip_validation.log_ip_mismatches", false)

	config := logtailConfig()

	// Test custom values are loaded correctly
	assert.True(t, config.Enabled)
	assert.True(t, config.Server.Enabled)
	assert.False(t, config.Server.EnableCache)
	assert.Equal(t, 360, config.Server.Retention.EphemeralMinutes)
	assert.Equal(t, 90, config.Server.Retention.PersistedDefaultDays)
	assert.Equal(t, 2, config.Server.Retention.CleanupIntervalHours)
	assert.Equal(t, 5, config.Server.RateLimit.RequestsPerMinute)
	assert.False(t, config.Server.Auth.WriteAuth.RequireNodeRegistration)
	assert.Equal(t, 60, config.Server.Auth.WriteAuth.PreAuthGracePeriodSeconds)
	assert.False(t, config.Server.Auth.WriteAuth.IPValidation.Enabled)
	assert.Equal(t, "strict", config.Server.Auth.WriteAuth.IPValidation.Mode)
	assert.False(t, config.Server.Auth.WriteAuth.IPValidation.AllowIPChanges)
	assert.Equal(t, 24, config.Server.Auth.WriteAuth.IPValidation.ValidationWindowHours)
	assert.Equal(t, 7, config.Server.Auth.WriteAuth.IPValidation.CleanupHistoryDays)
	assert.False(t, config.Server.Auth.WriteAuth.IPValidation.LogIPMismatches)
}

func TestLogtailConfigProductionProfile(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Production configuration values
	viper.Set("logtail.server.enabled", true)
	viper.Set("logtail.server.enable_cache", true)               // Cache enabled for performance
	viper.Set("logtail.server.retention.ephemeral_minutes", 720) // 12 hours
	viper.Set("logtail.server.retention.persisted_default_days", 30)
	viper.Set("logtail.server.rate_limit.requests_per_minute", 10)
	viper.Set("logtail.server.auth.write_auth.require_node_registration", true)
	viper.Set("logtail.server.auth.write_auth.ip_validation.enabled", true)
	viper.Set("logtail.server.auth.write_auth.ip_validation.mode", "relaxed")
	viper.Set("logtail.server.auth.write_auth.ip_validation.log_ip_mismatches", true)

	config := logtailConfig()

	assert.True(t, config.Server.Enabled)
	assert.True(t, config.Server.EnableCache)
	assert.True(t, config.Server.Auth.WriteAuth.RequireNodeRegistration)
	assert.True(t, config.Server.Auth.WriteAuth.IPValidation.Enabled)
	assert.Equal(t, "relaxed", config.Server.Auth.WriteAuth.IPValidation.Mode)
}

func TestLogtailConfigDevelopmentProfile(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Development configuration values (more permissive)
	viper.Set("logtail.server.enabled", true)
	viper.Set("logtail.server.enable_cache", true)
	viper.Set("logtail.server.retention.ephemeral_minutes", 60)                  // 1 hour for testing
	viper.Set("logtail.server.retention.persisted_default_days", 7)              // 1 week
	viper.Set("logtail.server.auth.write_auth.require_node_registration", false) // Allow all
	viper.Set("logtail.server.auth.write_auth.ip_validation.enabled", false)     // Disable for testing

	config := logtailConfig()

	assert.True(t, config.Server.Enabled)
	assert.False(t, config.Server.Auth.WriteAuth.RequireNodeRegistration)
	assert.False(t, config.Server.Auth.WriteAuth.IPValidation.Enabled)
	assert.Equal(t, 60, config.Server.Retention.EphemeralMinutes)
}

func TestLogtailConfigHighSecurityProfile(t *testing.T) {
	// Reset viper
	viper.Reset()

	// High security configuration values
	viper.Set("logtail.server.enabled", true)
	viper.Set("logtail.server.enable_cache", true)
	viper.Set("logtail.server.retention.ephemeral_minutes", 360) // 6 hours
	viper.Set("logtail.server.retention.persisted_default_days", 90)
	viper.Set("logtail.server.rate_limit.requests_per_minute", 5) // Stricter rate limit
	viper.Set("logtail.server.auth.write_auth.require_node_registration", true)
	viper.Set("logtail.server.auth.write_auth.pre_auth_grace_period_seconds", 60) // Shorter grace
	viper.Set("logtail.server.auth.write_auth.ip_validation.enabled", true)
	viper.Set("logtail.server.auth.write_auth.ip_validation.mode", "strict") // Strict IP matching
	viper.Set("logtail.server.auth.write_auth.ip_validation.allow_ip_changes", false)
	viper.Set("logtail.server.auth.write_auth.ip_validation.validation_window_hours", 24)

	config := logtailConfig()

	assert.True(t, config.Server.Enabled)
	assert.Equal(t, 5, config.Server.RateLimit.RequestsPerMinute)
	assert.Equal(t, 60, config.Server.Auth.WriteAuth.PreAuthGracePeriodSeconds)
	assert.Equal(t, "strict", config.Server.Auth.WriteAuth.IPValidation.Mode)
	assert.False(t, config.Server.Auth.WriteAuth.IPValidation.AllowIPChanges)
	assert.Equal(t, 24, config.Server.Auth.WriteAuth.IPValidation.ValidationWindowHours)
}

func TestLogtailConfigIPValidationModes(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{"strict mode", "strict"},
		{"relaxed mode", "relaxed"},
		{"none mode", "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("logtail.server.auth.write_auth.ip_validation.mode", tt.mode)

			config := logtailConfig()
			assert.Equal(t, tt.mode, config.Server.Auth.WriteAuth.IPValidation.Mode)
		})
	}
}

func TestLogtailConfigCacheToggle(t *testing.T) {
	tests := []struct {
		name        string
		enableCache bool
		description string
	}{
		{
			name:        "cache enabled",
			enableCache: true,
			description: "optimal performance with in-memory caching",
		},
		{
			name:        "cache disabled",
			enableCache: false,
			description: "troubleshooting mode with direct database access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("logtail.server.enable_cache", tt.enableCache)

			config := logtailConfig()
			assert.Equal(t, tt.enableCache, config.Server.EnableCache, tt.description)
		})
	}
}

func TestLogtailConfigRetentionValues(t *testing.T) {
	tests := []struct {
		name                 string
		ephemeralMinutes     int
		persistedDefaultDays int
		cleanupIntervalHours int
	}{
		{"minimal retention", 60, 7, 1},
		{"standard retention", 720, 30, 1},
		{"extended retention", 1440, 90, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("logtail.server.retention.ephemeral_minutes", tt.ephemeralMinutes)
			viper.Set("logtail.server.retention.persisted_default_days", tt.persistedDefaultDays)
			viper.Set("logtail.server.retention.cleanup_interval_hours", tt.cleanupIntervalHours)

			config := logtailConfig()
			assert.Equal(t, tt.ephemeralMinutes, config.Server.Retention.EphemeralMinutes)
			assert.Equal(t, tt.persistedDefaultDays, config.Server.Retention.PersistedDefaultDays)
			assert.Equal(t, tt.cleanupIntervalHours, config.Server.Retention.CleanupIntervalHours)
		})
	}
}

func TestLogtailConfigZeroValues(t *testing.T) {
	// Test that zero values are handled correctly
	viper.Reset()
	viper.Set("logtail.server.retention.ephemeral_minutes", 0)
	viper.Set("logtail.server.retention.persisted_default_days", 0)
	viper.Set("logtail.server.rate_limit.requests_per_minute", 0)
	viper.Set("logtail.server.auth.write_auth.pre_auth_grace_period_seconds", 0)

	config := logtailConfig()

	// Zero values should be preserved (validation happens elsewhere)
	assert.Equal(t, 0, config.Server.Retention.EphemeralMinutes)
	assert.Equal(t, 0, config.Server.Retention.PersistedDefaultDays)
	assert.Equal(t, 0, config.Server.RateLimit.RequestsPerMinute)
	assert.Equal(t, 0, config.Server.Auth.WriteAuth.PreAuthGracePeriodSeconds)
}

func TestLogtailConfigPartialConfiguration(t *testing.T) {
	// Test that partial configuration works with defaults
	viper.Reset()

	// Set defaults
	viper.SetDefault("logtail.server.retention.ephemeral_minutes", 720)
	viper.SetDefault("logtail.server.retention.persisted_default_days", 30)

	// Only override some values
	viper.Set("logtail.server.enabled", true)
	viper.Set("logtail.server.retention.ephemeral_minutes", 480)

	config := logtailConfig()

	assert.True(t, config.Server.Enabled)
	assert.Equal(t, 480, config.Server.Retention.EphemeralMinutes)    // Custom value
	assert.Equal(t, 30, config.Server.Retention.PersistedDefaultDays) // Default value
}
