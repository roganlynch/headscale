package logtail

import (
	"context"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// LogtailService orchestrates storage, caching, rate limiting, and authentication.
// This is the main service layer that coordinates all components.
type LogtailService struct {
	storage       Storage
	cache         *LogtailCache
	rateLimiter   *RateLimiter
	authenticator *Authenticator
	config        types.LogTailServerConfig
}

// NewLogtailService creates a new service with all components.
func NewLogtailService(
	storage Storage,
	rateLimiter *RateLimiter,
	config types.LogTailServerConfig,
) *LogtailService {
	return &LogtailService{
		storage:       storage,
		cache:         NewLogtailCache(),
		rateLimiter:   rateLimiter,
		authenticator: NewAuthenticator(config),
		config:        config,
	}
}

// AuthenticateWithCache performs authentication with multi-layer caching.
// This is the main cache orchestration method that eliminates most DB operations.
func (s *LogtailService) AuthenticateWithCache(
	ctx context.Context,
	privateID, clientIP, collection string,
) AuthResult {

	// STEP 1: Check authentication cache (1-minute TTL)
	if cached, ok := s.cache.authCache.Load(privateID); ok {
		entry := cached.(*CachedAuthResult)
		if time.Now().Before(entry.ExpiresAt) {
			log.Debug().
				Str("private_id", privateID).
				Msg("Authentication cache hit")
			return entry.Result // ~0 DB operations
		}
		s.cache.authCache.Delete(privateID) // Expired
	}

	log.Debug().
		Str("private_id", privateID).
		Msg("Authentication cache miss - loading from storage")

	// STEP 2: Load association (check cache first)
	var association *PrivateIDAssociation

	// Try recentIPs cache first
	if cachedIPs, ok := s.cache.recentIPs.Load(privateID); ok {
		// Have cached IPs - still need full association for node ID
		assoc, err := s.storage.GetPrivateIDAssociation(ctx, privateID)
		if err == nil && assoc != nil {
			assoc.RecentIPs = cachedIPs.([]string) // Use cached IPs
			association = assoc
			log.Debug().
				Str("private_id", privateID).
				Msg("Using cached recent IPs")
		}
	} else {
		// Full cache miss - load from DB
		assoc, err := s.storage.GetPrivateIDAssociation(ctx, privateID)
		if err == nil && assoc != nil {
			association = assoc
			// Cache the recent IPs for future requests
			if len(assoc.RecentIPs) > 0 {
				s.cache.recentIPs.Store(privateID, assoc.RecentIPs)
				log.Debug().
					Str("private_id", privateID).
					Int("ip_count", len(assoc.RecentIPs)).
					Msg("Cached recent IPs from DB")
			}
		}
	}

	// STEP 3: Load first-seen (check cache first)
	var firstSeen *FirstSeenRecord

	if cached, ok := s.cache.firstSeen.Load(privateID); ok {
		firstSeen = cached.(*FirstSeenRecord)
		log.Debug().
			Str("private_id", privateID).
			Msg("First-seen cache hit")
	} else {
		// Cache miss - load from DB
		record, err := s.storage.GetFirstSeen(ctx, privateID)
		if err == nil && record != nil {
			firstSeen = record
			// Cache for subsequent requests
			s.cache.firstSeen.Store(privateID, record)
			log.Debug().
				Str("private_id", privateID).
				Msg("Cached first-seen from DB")
		}
	}

	// STEP 4: Call authentication business logic (PR4)
	result := s.authenticator.AuthenticateLogWrite(
		association,
		firstSeen,
		clientIP,
	)

	// STEP 5: Cache the result (1-minute TTL)
	s.cache.authCache.Store(privateID, &CachedAuthResult{
		Result:    result,
		ExpiresAt: time.Now().Add(AuthCacheTTL),
	})

	log.Info().
		Str("private_id", privateID).
		Str("client_ip", clientIP).
		Bool("allowed", result.Allowed).
		Bool("grace_period", result.IsGracePeriod).
		Str("reason", result.Reason).
		Msg("Authentication complete")

	// STEP 6: Handle side effects (write-through caching)

	// If first time seeing this private ID, record it
	if result.Allowed && association == nil && firstSeen == nil {
		newFirstSeen := &FirstSeenRecord{
			PrivateID:   privateID,
			Collection:  collection,
			FirstSeenAt: time.Now(),
			FirstSeenIP: clientIP,
		}

		// Write-through: cache AND persist
		s.cache.firstSeen.Store(privateID, newFirstSeen)
		err := s.storage.RecordFirstSeen(ctx, newFirstSeen)
		if err != nil {
			log.Error().
				Err(err).
				Str("private_id", privateID).
				Msg("Failed to record first seen")
		}
	}

	// If authenticated and IP validation enabled, check if we need to update IPs
	if result.Allowed && association != nil {
		ipResult := s.authenticator.ValidateIP(association, clientIP)
		if s.authenticator.ShouldUpdateRecentIPs(association, clientIP, ipResult) {
			err := s.updateRecentIPsCached(ctx, privateID, clientIP)
			if err != nil {
				log.Error().
					Err(err).
					Str("private_id", privateID).
					Str("new_ip", clientIP).
					Msg("Failed to update recent IPs")
			}
		}
	}

	return result
}

// updateRecentIPsCached updates recent IPs with write-through caching.
func (s *LogtailService) updateRecentIPsCached(
	ctx context.Context,
	privateID, newIP string,
) error {

	// Update cache immediately
	if cachedIPs, ok := s.cache.recentIPs.Load(privateID); ok {
		ips := cachedIPs.([]string)

		// Check if IP already exists
		found := false
		for _, ip := range ips {
			if ip == newIP {
				found = true
				break
			}
		}

		if !found {
			// Add to front, keep last 10
			newIPs := append([]string{newIP}, ips...)
			if len(newIPs) > 10 {
				newIPs = newIPs[:10]
			}
			s.cache.recentIPs.Store(privateID, newIPs)

			log.Debug().
				Str("private_id", privateID).
				Str("new_ip", newIP).
				Msg("Updated cached recent IPs")
		}
	} else {
		// Initialize cache
		s.cache.recentIPs.Store(privateID, []string{newIP})
	}

	// Write-through to DB
	err := s.storage.UpdateRecentIPs(ctx, privateID, newIP)
	if err != nil {
		return fmt.Errorf("failed to update recent IPs in DB: %w", err)
	}

	// Evict auth cache since recent IPs changed
	s.cache.EvictAuth(privateID)

	return nil
}

// AssociatePrivateIDCached creates an association with cache invalidation.
func (s *LogtailService) AssociatePrivateIDCached(
	ctx context.Context,
	privateID string,
	nodeID uint64,
	collection, currentIP string,
) error {

	assoc := &PrivateIDAssociation{
		PrivateID:  privateID,
		NodeID:     nodeID,
		Collection: collection,
		CurrentIP:  currentIP,
		RecentIPs:  []string{currentIP},
	}

	// Store in DB
	err := s.storage.StorePrivateIDAssociation(ctx, assoc)
	if err != nil {
		return err
	}

	// Cache invalidation: evict all related caches
	s.cache.EvictFirstSeen(privateID)                       // No longer in grace period
	s.cache.EvictAuth(privateID)                            // Auth result changed
	s.cache.recentIPs.Store(privateID, []string{currentIP}) // Initialize recent IPs

	log.Info().
		Str("private_id", privateID).
		Uint64("node_id", nodeID).
		Str("collection", collection).
		Msg("Associated private ID with node (cache invalidated)")

	return nil
}

// StoreLogs stores logs using the storage layer.
func (s *LogtailService) StoreLogs(ctx context.Context, logs []LogEntry) error {
	return s.storage.StoreLogs(ctx, logs)
}

// QueryLogs queries logs using the storage layer.
func (s *LogtailService) QueryLogs(ctx context.Context, query LogQuery) ([]LogEntry, error) {
	return s.storage.QueryLogs(ctx, query)
}

// GetLogInstance retrieves instance metadata.
func (s *LogtailService) GetLogInstance(ctx context.Context, privateID, collection string) (*LogInstance, error) {
	return s.storage.GetLogInstance(ctx, privateID, collection)
}

// MigrateLogTier migrates logs from one tier to another.
func (s *LogtailService) MigrateLogTier(ctx context.Context, privateID, collection string, fromTier, toTier LogTier) error {
	// Perform migration
	err := s.storage.MigrateLogTier(ctx, privateID, collection, fromTier, toTier)
	if err != nil {
		return err
	}

	// Update cache
	tierKey := privateID + ":" + collection
	s.cache.instanceTiers.Store(tierKey, toTier)

	return nil
}
