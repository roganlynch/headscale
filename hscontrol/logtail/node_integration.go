package logtail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultCollection is the default logtail collection name
	DefaultCollection = "tailnode.log.tailscale.io"
)

// AssociateNodeWithLogtail creates an association between a node and its logtail private ID
// This is called during node registration and triggers comprehensive cache invalidation
func (s *LogtailService) AssociateNodeWithLogtail(
	node *types.Node,
	clientIP string,
) error {
	if !s.config.Enabled {
		return nil
	}

	// Derive the logtail private ID from node information
	privateID := DeriveLogPrivateIDFromNode(node)
	if privateID == "" {
		log.Warn().
			Uint64("node_id", uint64(node.ID)).
			Str("hostname", node.Hostname).
			Msg("Failed to derive logtail private ID from node")
		return fmt.Errorf("failed to derive logtail private ID")
	}

	collection := DefaultCollection

	log.Info().
		Uint64("node_id", uint64(node.ID)).
		Str("hostname", node.Hostname).
		Str("private_id", privateID).
		Str("client_ip", clientIP).
		Msg("Associating node with logtail")

	// Use cached association method from PR5 (handles cache + DB write-through)
	ctx := context.Background()
	err := s.AssociatePrivateIDCached(ctx, privateID, uint64(node.ID), collection, clientIP)
	if err != nil {
		log.Error().
			Err(err).
			Uint64("node_id", uint64(node.ID)).
			Str("private_id", privateID).
			Msg("Failed to store logtail association")
		return fmt.Errorf("failed to store association: %w", err)
	}

	// CRITICAL: Migrate grace period logs
	// This must happen after association is created but before returning
	err = s.MigrateGracePeriodLogsForNode(ctx, privateID, collection)
	if err != nil {
		// Log error but don't fail - association succeeded
		log.Error().
			Err(err).
			Uint64("node_id", uint64(node.ID)).
			Str("private_id", privateID).
			Msg("Failed to migrate grace period logs (non-fatal)")
	}

	// CRITICAL: Full cache invalidation for node registration event
	// This ensures subsequent writes use the authenticated state
	s.invalidateAllCachesForNode(privateID)

	log.Info().
		Uint64("node_id", uint64(node.ID)).
		Str("hostname", node.Hostname).
		Str("private_id", privateID).
		Msg("Successfully associated node with logtail, migrated logs, and invalidated caches")

	return nil
}

// MigrateGracePeriodLogsForNode migrates logs from grace period tier
// Intelligently determines target tier based on instance state and invalidates caches
func (s *LogtailService) MigrateGracePeriodLogsForNode(
	ctx context.Context,
	privateID, collection string,
) error {
	// Check if this instance already has persisted logs (re-authentication case)
	instance, err := s.storage.GetLogInstance(ctx, privateID, collection)
	if err != nil {
		return fmt.Errorf("failed to get instance: %w", err)
	}

	var targetTier LogTier

	if instance != nil && instance.Persisted {
		// Node was previously persisted - migrate directly to persisted tier
		targetTier = LogTierPersisted
		log.Info().
			Str("private_id", privateID).
			Str("collection", collection).
			Msg("Instance already persisted - migrating grace period logs to persisted tier")
	} else {
		// Standard path - migrate to ephemeral tier
		targetTier = LogTierEphemeral
		log.Debug().
			Str("private_id", privateID).
			Str("collection", collection).
			Msg("Migrating grace period logs to ephemeral tier")
	}

	// Perform the migration
	err = s.storage.MigrateLogTier(ctx, privateID, collection, LogTierGracePeriod, targetTier)
	if err != nil {
		return fmt.Errorf("failed to migrate log tier: %w", err)
	}

	// Update instance tier if not already persisted
	if targetTier == LogTierEphemeral {
		err = s.storage.UpdateInstanceTier(ctx, privateID, collection, LogTierEphemeral)
		if err != nil {
			return fmt.Errorf("failed to update instance tier: %w", err)
		}
	}

	// Clean up first-seen record (no longer needed after association)
	err = s.storage.DeleteFirstSeen(ctx, privateID)
	if err != nil {
		log.Warn().Err(err).Str("private_id", privateID).Msg("Failed to delete first-seen record")
		// Non-fatal
	}

	// Cache invalidation: tier changed, first-seen removed
	// Instance tier cache must be cleared so future writes use correct tier
	s.invalidateInstanceTierCache(privateID)
	s.invalidateFirstSeenCache(privateID)

	log.Info().
		Str("private_id", privateID).
		Str("collection", collection).
		Str("from_tier", string(LogTierGracePeriod)).
		Str("to_tier", string(targetTier)).
		Msg("Successfully migrated grace period logs and invalidated caches")

	return nil
}

// DeriveLogPrivateIDFromNode derives a logtail private ID from node information
// This uses the node's machine key to ensure consistency across re-registrations
func DeriveLogPrivateIDFromNode(node *types.Node) string {
	if node == nil {
		return ""
	}

	// Use node's machine key as the stable identifier
	// This ensures the same private ID across re-registrations
	machineKey := node.MachineKey.String()
	if machineKey == "" {
		log.Warn().
			Uint64("node_id", uint64(node.ID)).
			Msg("Node has no machine key, cannot derive private ID")
		return ""
	}

	// Create a deterministic private ID from the machine key
	// Format: "logtail-<first-32-chars-of-sha256>"
	hash := sha256.Sum256([]byte(machineKey))
	hexHash := hex.EncodeToString(hash[:])

	privateID := fmt.Sprintf("logtail-%s", hexHash[:32])

	return privateID
}

// DisassociateNodeFromLogtail removes the association when a node is deleted
// Performs comprehensive cache cleanup to prevent stale data
func (s *LogtailService) DisassociateNodeFromLogtail(node *types.Node) error {
	if !s.config.Enabled {
		return nil
	}

	privateID := DeriveLogPrivateIDFromNode(node)
	if privateID == "" {
		return nil
	}

	log.Info().
		Uint64("node_id", uint64(node.ID)).
		Str("hostname", node.Hostname).
		Str("private_id", privateID).
		Msg("Disassociating node from logtail")

	// Delete from DB
	ctx := context.Background()
	err := s.storage.DeletePrivateIDAssociation(ctx, privateID)
	if err != nil {
		log.Error().
			Err(err).
			Uint64("node_id", uint64(node.ID)).
			Msg("Failed to delete logtail association")
		return fmt.Errorf("failed to delete association: %w", err)
	}

	// CRITICAL: Full cache invalidation on node deletion
	// Prevents ghost authentication if node re-registers with same private ID
	s.invalidateAllCachesForNode(privateID)

	log.Info().
		Uint64("node_id", uint64(node.ID)).
		Str("private_id", privateID).
		Msg("Successfully disassociated node from logtail and invalidated all caches")

	return nil
}

// GetNodeAssociations returns all logtail associations for a node
// Useful for debugging and CLI commands
func (s *LogtailService) GetNodeAssociations(nodeID uint64) ([]PrivateIDAssociation, error) {
	if !s.config.Enabled {
		return nil, nil
	}

	ctx := context.Background()
	associations, err := s.storage.GetAssociationsByNodeID(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get associations: %w", err)
	}

	return associations, nil
}

// invalidateAllCachesForNode performs comprehensive cache cleanup for a node
// Called during registration (state change) and deletion (cleanup)
func (s *LogtailService) invalidateAllCachesForNode(privateID string) {
	s.invalidateAuthCache(privateID)
	s.invalidateFirstSeenCache(privateID)
	s.invalidateRecentIPsCache(privateID)
	s.invalidateInstanceTierCache(privateID)

	log.Debug().
		Str("private_id", privateID).
		Msg("Invalidated all caches for node")
}

// Cache invalidation helper methods for node integration
// Note: invalidateAuthCache is defined in read_handlers.go

func (s *LogtailService) invalidateFirstSeenCache(privateID string) {
	if s.cache != nil {
		s.cache.firstSeen.Delete(privateID)
	}
}

func (s *LogtailService) invalidateRecentIPsCache(privateID string) {
	if s.cache != nil {
		s.cache.recentIPs.Delete(privateID)
	}
}

func (s *LogtailService) invalidateInstanceTierCache(privateID string) {
	if s.cache == nil {
		return
	}

	// Instance tier cache uses "privateID:collection" as key
	// Delete all entries that start with this privateID
	prefix := privateID + ":"
	s.cache.instanceTiers.Range(func(key, value interface{}) bool {
		keyStr, ok := key.(string)
		if !ok {
			return true
		}

		// Check if key starts with our privateID prefix
		if len(keyStr) >= len(prefix) && keyStr[:len(prefix)] == prefix {
			s.cache.instanceTiers.Delete(key)
		}
		return true
	})
}
