package logtail

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// RateLimiter implements an in-memory cached sliding window rate limiter
// with periodic database persistence for durability
type RateLimiter struct {
	db                *gorm.DB
	requestsPerMinute int

	// In-memory cache (replaces direct DB access on hot path)
	cache sync.Map // key: privateID -> *RateLimitState

	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
	flushTicker   *time.Ticker  // NEW: Periodic DB flush
	flushDone     chan struct{} // NEW: Flush shutdown signal
}

// RateLimitState represents in-memory rate limit state
type RateLimitState struct {
	RequestCount int
	WindowStart  time.Time
	LastRequest  time.Time
	Dirty        bool // NEW: Track if needs DB sync
	mu           sync.Mutex
}

// NewRateLimiter creates a new rate limiter instance with in-memory cache
func NewRateLimiter(db *gorm.DB, requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		db:                db,
		requestsPerMinute: requestsPerMinute,
		cleanupDone:       make(chan struct{}),
		flushDone:         make(chan struct{}),
	}

	// Start cleanup goroutine (runs every 5 minutes) - cleans in-memory cache
	rl.cleanupTicker = time.NewTicker(5 * time.Minute)
	go rl.cleanupLoop()

	// Start flush goroutine (runs every 30 seconds) - persists to DB
	rl.flushTicker = time.NewTicker(30 * time.Second)
	go rl.flushLoop()

	return rl
}

// CheckLimit verifies if a request is allowed for the given private ID
// Uses in-memory cache - NO database queries on hot path
// Returns true if allowed, false if rate limited
func (rl *RateLimiter) CheckLimit(ctx context.Context, privateID string) (bool, error) {
	now := time.Now()
	windowStart := now.Add(-1 * time.Minute)

	// Load or create state from cache
	val, loaded := rl.cache.LoadOrStore(privateID, &RateLimitState{
		RequestCount: 0,
		WindowStart:  now,
		LastRequest:  now,
		Dirty:        false,
	})

	state := val.(*RateLimitState)
	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if we just created a new entry
	if !loaded {
		// First request for this private ID
		state.RequestCount = 1
		state.WindowStart = now
		state.LastRequest = now
		state.Dirty = true

		log.Debug().
			Str("private_id", privateID).
			Int("count", 1).
			Msg("Rate limit: first request (cached)")

		return true, nil
	}

	// Check if window has expired (older than 1 minute)
	if state.WindowStart.Before(windowStart) {
		// Reset window
		state.RequestCount = 1
		state.WindowStart = now
		state.LastRequest = now
		state.Dirty = true

		log.Debug().
			Str("private_id", privateID).
			Msg("Rate limit: window reset (cached)")

		return true, nil
	}

	// Window is still active - check limit
	if state.RequestCount >= rl.requestsPerMinute {
		log.Warn().
			Str("private_id", privateID).
			Int("count", state.RequestCount).
			Int("limit", rl.requestsPerMinute).
			Msg("Rate limit exceeded (cached)")

		return false, nil
	}

	// Increment counter (in-memory only)
	state.RequestCount++
	state.LastRequest = now
	state.Dirty = true

	log.Debug().
		Str("private_id", privateID).
		Int("count", state.RequestCount).
		Int("limit", rl.requestsPerMinute).
		Msg("Rate limit check passed (cached)")

	return true, nil
}

// GetCurrentCount returns the current request count for a private ID
// Reads from cache first, falls back to DB
// Useful for testing and monitoring
func (rl *RateLimiter) GetCurrentCount(ctx context.Context, privateID string) (int, error) {
	// Check cache first
	if val, ok := rl.cache.Load(privateID); ok {
		state := val.(*RateLimitState)
		state.mu.Lock()
		count := state.RequestCount
		state.mu.Unlock()
		return count, nil
	}

	// Cache miss - check DB
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	var count int
	err := rl.db.WithContext(ctx).
		Raw(`
            SELECT request_count 
            FROM logtail_rate_limits 
            WHERE private_id = ?
        `, privateID).
		Scan(&count).Error

	if err == gorm.ErrRecordNotFound {
		return 0, nil
	}

	if err != nil {
		return 0, fmt.Errorf("failed to get rate limit count: %w", err)
	}

	return count, nil
}

// ResetLimit resets the rate limit for a private ID
// Clears from cache and DB
// Useful for testing and administrative purposes
func (rl *RateLimiter) ResetLimit(ctx context.Context, privateID string) error {
	// Remove from cache
	rl.cache.Delete(privateID)

	// Remove from DB
	rl.mu.Lock()
	defer rl.mu.Unlock()

	err := rl.db.WithContext(ctx).
		Exec("DELETE FROM logtail_rate_limits WHERE private_id = ?", privateID).
		Error

	if err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	log.Debug().
		Str("private_id", privateID).
		Msg("Rate limit reset (cache and DB)")

	return nil
}

// cleanupLoop periodically removes expired rate limit records from cache
func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.cleanup()
		case <-rl.cleanupDone:
			return
		}
	}
}

// cleanup removes rate limit records older than 5 minutes from cache
func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-5 * time.Minute)

	deleted := 0
	rl.cache.Range(func(key, value interface{}) bool {
		state := value.(*RateLimitState)
		state.mu.Lock()
		lastRequest := state.LastRequest
		state.mu.Unlock()

		if lastRequest.Before(cutoff) {
			rl.cache.Delete(key)
			deleted++
		}
		return true
	})

	if deleted > 0 {
		log.Debug().
			Int("deleted", deleted).
			Msg("Cleaned up expired rate limit records from cache")
	}
}

// flushLoop periodically persists rate limit state to database
func (rl *RateLimiter) flushLoop() {
	for {
		select {
		case <-rl.flushTicker.C:
			rl.flushToDB()
		case <-rl.flushDone:
			// Final flush before shutdown
			rl.flushToDB()
			return
		}
	}
}

// flushToDB persists dirty rate limit state to database
func (rl *RateLimiter) flushToDB() {
	ctx := context.Background()
	flushed := 0

	rl.cache.Range(func(key, value interface{}) bool {
		privateID := key.(string)
		state := value.(*RateLimitState)

		state.mu.Lock()
		defer state.mu.Unlock()

		if !state.Dirty {
			return true // Skip clean entries
		}

		// Upsert to DB
		err := rl.db.WithContext(ctx).Exec(`
            INSERT INTO logtail_rate_limits (private_id, request_count, window_start, last_request)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(private_id) DO UPDATE SET
                request_count = excluded.request_count,
                window_start = excluded.window_start,
                last_request = excluded.last_request
        `, privateID, state.RequestCount, state.WindowStart, state.LastRequest).Error

		if err != nil {
			log.Error().
				Err(err).
				Str("private_id", privateID).
				Msg("Failed to flush rate limit to DB")
			return true
		}

		state.Dirty = false
		flushed++
		return true
	})

	if flushed > 0 {
		log.Debug().
			Int("flushed", flushed).
			Msg("Flushed rate limits to database")
	}
}

// Close stops the cleanup and flush goroutines, performs final flush
func (rl *RateLimiter) Close() error {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
	if rl.flushTicker != nil {
		rl.flushTicker.Stop()
	}

	// Signal shutdown
	close(rl.cleanupDone)
	close(rl.flushDone)

	// flushDone channel closure triggers final flush in flushLoop
	return nil
}
