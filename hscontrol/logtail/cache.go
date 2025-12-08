package logtail

import "time"

// Cache TTL constants
const (
	AuthCacheTTL = 1 * time.Minute // Authentication results cache
	FirstSeenTTL = 5 * time.Minute // First-seen records cache
	RecentIPsTTL = 48 * time.Hour  // Recent IPs cache window
)

// NewLogtailCache creates a new cache instance.
func NewLogtailCache() *LogtailCache {
	return &LogtailCache{}
}

// Evict removes all cache entries for a private ID (used on node deletion).
func (c *LogtailCache) Evict(privateID string) {
	c.authCache.Delete(privateID)
	c.firstSeen.Delete(privateID)
	c.recentIPs.Delete(privateID)
	// Note: instanceTiers uses composite key (privateID+collection),
	// so cannot be easily evicted here without knowing collections
}

// EvictAuth removes authentication cache entry.
func (c *LogtailCache) EvictAuth(privateID string) {
	c.authCache.Delete(privateID)
}

// EvictFirstSeen removes first-seen cache entry.
func (c *LogtailCache) EvictFirstSeen(privateID string) {
	c.firstSeen.Delete(privateID)
}

// EvictRecentIPs removes recent IPs cache entry.
func (c *LogtailCache) EvictRecentIPs(privateID string) {
	c.recentIPs.Delete(privateID)
}
