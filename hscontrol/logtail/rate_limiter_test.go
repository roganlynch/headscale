package logtail

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create rate limits table
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

func TestNewRateLimiter(t *testing.T) {
	db := setupTestDB(t)

	rl := NewRateLimiter(db, 10)
	defer rl.Close()

	assert.NotNil(t, rl)
	assert.Equal(t, 10, rl.requestsPerMinute)
	assert.NotNil(t, rl.cleanupTicker)
}

func TestRateLimiter_FirstRequest(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)
	defer rl.Close()

	ctx := context.Background()
	allowed, err := rl.CheckLimit(ctx, "test-id-1")

	require.NoError(t, err)
	assert.True(t, allowed, "first request should be allowed")

	// Verify count
	count, err := rl.GetCurrentCount(ctx, "test-id-1")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRateLimiter_MultipleRequests(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 5)
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-id-2"

	// Make 5 requests - all should be allowed
	for i := 0; i < 5; i++ {
		allowed, err := rl.CheckLimit(ctx, privateID)
		require.NoError(t, err)
		assert.True(t, allowed, "request %d should be allowed", i+1)
	}

	// Verify count
	count, err := rl.GetCurrentCount(ctx, privateID)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestRateLimiter_ExceedLimit(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 3)
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-id-3"

	// Make 3 requests - all should be allowed
	for i := 0; i < 3; i++ {
		allowed, err := rl.CheckLimit(ctx, privateID)
		require.NoError(t, err)
		assert.True(t, allowed, "request %d should be allowed", i+1)
	}

	// 4th request should be denied
	allowed, err := rl.CheckLimit(ctx, privateID)
	require.NoError(t, err)
	assert.False(t, allowed, "request should be rate limited")

	// Count should still be 3 (not incremented)
	count, err := rl.GetCurrentCount(ctx, privateID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestRateLimiter_WindowReset(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 2)
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-id-4"

	// Make 2 requests
	for i := 0; i < 2; i++ {
		allowed, err := rl.CheckLimit(ctx, privateID)
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	// Manually update cache to simulate time passing (cache-first architecture)
	if val, ok := rl.cache.Load(privateID); ok {
		state := val.(*RateLimitState)
		state.mu.Lock()
		state.WindowStart = time.Now().Add(-2 * time.Minute)
		state.Dirty = true
		state.mu.Unlock()
	}

	// Next request should be allowed (window reset)
	allowed, err := rl.CheckLimit(ctx, privateID)
	require.NoError(t, err)
	assert.True(t, allowed, "request should be allowed after window reset")

	// Count should be 1 (reset)
	count, err := rl.GetCurrentCount(ctx, privateID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRateLimiter_MultiplePrivateIDs(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 2)
	defer rl.Close()

	ctx := context.Background()

	// Each private ID should have independent rate limits
	ids := []string{"id-1", "id-2", "id-3"}

	for _, id := range ids {
		// Make 2 requests for each ID
		for i := 0; i < 2; i++ {
			allowed, err := rl.CheckLimit(ctx, id)
			require.NoError(t, err)
			assert.True(t, allowed, "request for %s should be allowed", id)
		}

		// 3rd request should be denied
		allowed, err := rl.CheckLimit(ctx, id)
		require.NoError(t, err)
		assert.False(t, allowed, "3rd request for %s should be denied", id)
	}
}

func TestRateLimiter_ResetLimit(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 2)
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-id-5"

	// Make 2 requests to hit limit
	for i := 0; i < 2; i++ {
		allowed, err := rl.CheckLimit(ctx, privateID)
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	// Verify at limit
	count, err := rl.GetCurrentCount(ctx, privateID)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Reset limit
	err = rl.ResetLimit(ctx, privateID)
	require.NoError(t, err)

	// Count should be 0
	count, err = rl.GetCurrentCount(ctx, privateID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Should be able to make requests again
	allowed, err := rl.CheckLimit(ctx, privateID)
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestRateLimiter_GetCurrentCount_NonExistent(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)
	defer rl.Close()

	ctx := context.Background()

	// Query for non-existent private ID
	count, err := rl.GetCurrentCount(ctx, "non-existent")
	require.NoError(t, err)
	assert.Equal(t, 0, count, "count for non-existent ID should be 0")
}

func TestRateLimiter_Cleanup(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)
	defer rl.Close()

	ctx := context.Background()

	// Create some rate limit records
	privateIDs := []string{"id-1", "id-2", "id-3"}
	for _, id := range privateIDs {
		_, err := rl.CheckLimit(ctx, id)
		require.NoError(t, err)
	}

	// Manually set last_request to old time in cache for id-1 and id-2
	for _, id := range []string{"id-1", "id-2"} {
		if val, ok := rl.cache.Load(id); ok {
			state := val.(*RateLimitState)
			state.mu.Lock()
			state.LastRequest = time.Now().Add(-10 * time.Minute)
			state.mu.Unlock()
		}
	}

	// Run cleanup
	rl.cleanup()

	// Verify id-1 and id-2 were deleted from cache
	_, ok1 := rl.cache.Load("id-1")
	assert.False(t, ok1, "id-1 should be cleaned up from cache")

	_, ok2 := rl.cache.Load("id-2")
	assert.False(t, ok2, "id-2 should be cleaned up from cache")

	// Verify id-3 still exists in cache
	_, ok3 := rl.cache.Load("id-3")
	assert.True(t, ok3, "id-3 should still exist in cache")
}

func TestRateLimiter_ConcurrentRequests(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-concurrent"

	// Make concurrent requests
	const numGoroutines = 5
	results := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			allowed, err := rl.CheckLimit(ctx, privateID)
			require.NoError(t, err)
			results <- allowed
		}()
	}

	// Collect results
	allowedCount := 0
	for i := 0; i < numGoroutines; i++ {
		if <-results {
			allowedCount++
		}
	}

	// All should be allowed (under limit of 10)
	assert.Equal(t, numGoroutines, allowedCount)

	// Final count should match
	count, err := rl.GetCurrentCount(ctx, privateID)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines, count)
}

func TestRateLimiter_PeriodicFlush(t *testing.T) {
	db := setupTestDB(t)
	// Use very short flush interval for testing
	rl := &RateLimiter{
		db:                db,
		requestsPerMinute: 10,
		cleanupDone:       make(chan struct{}),
		flushDone:         make(chan struct{}),
	}

	// Start with short flush interval for testing
	rl.flushTicker = time.NewTicker(100 * time.Millisecond)
	go rl.flushLoop()
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-flush"

	// Make some requests to create dirty state
	allowed, err := rl.CheckLimit(ctx, privateID)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Wait for flush to occur
	time.Sleep(200 * time.Millisecond)

	// Verify data was written to DB
	var count int
	err = db.Raw("SELECT request_count FROM logtail_rate_limits WHERE private_id = ?", privateID).Scan(&count).Error
	require.NoError(t, err)
	assert.Equal(t, 1, count, "flush should have persisted to DB")

	// Verify dirty flag was cleared
	val, ok := rl.cache.Load(privateID)
	require.True(t, ok)
	state := val.(*RateLimitState)
	state.mu.Lock()
	dirty := state.Dirty
	state.mu.Unlock()
	assert.False(t, dirty, "dirty flag should be cleared after flush")
}

func TestRateLimiter_DirtyFlag(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)
	defer rl.Close()

	ctx := context.Background()
	privateID := "test-dirty"

	// First request should set dirty flag
	allowed, err := rl.CheckLimit(ctx, privateID)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Verify dirty flag is set
	val, ok := rl.cache.Load(privateID)
	require.True(t, ok)
	state := val.(*RateLimitState)
	state.mu.Lock()
	dirty := state.Dirty
	state.mu.Unlock()
	assert.True(t, dirty, "dirty flag should be set after modification")
}

func TestRateLimiter_GracefulShutdown(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)

	ctx := context.Background()
	privateID := "test-shutdown"

	// Make request to create dirty data
	allowed, err := rl.CheckLimit(ctx, privateID)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Close triggers final flush
	err = rl.Close()
	assert.NoError(t, err)

	// Give a small amount of time for the flush goroutine to complete
	time.Sleep(50 * time.Millisecond)

	// Verify data was persisted to DB
	var count int
	err = db.Raw("SELECT request_count FROM logtail_rate_limits WHERE private_id = ?", privateID).Scan(&count).Error
	require.NoError(t, err)
	assert.Equal(t, 1, count, "shutdown should have flushed dirty data to DB")
}

func TestRateLimiter_Close(t *testing.T) {
	db := setupTestDB(t)
	rl := NewRateLimiter(db, 10)

	// Verify tickers are running
	assert.NotNil(t, rl.cleanupTicker)
	assert.NotNil(t, rl.flushTicker)

	// Close should not error
	err := rl.Close()
	assert.NoError(t, err)
}
