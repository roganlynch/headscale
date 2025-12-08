package logtail

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// Authenticator handles log write authentication with caching support
type Authenticator struct {
	config types.LogTailServerConfig

	// Cache for authentication results (used by service layer)
	// Not managed directly by Authenticator - this is pure business logic
	// Cache management happens in the service layer (PR5+)
}

// NewAuthenticator creates a new authenticator with the given configuration
func NewAuthenticator(config types.LogTailServerConfig) *Authenticator {
	return &Authenticator{
		config: config,
	}
}

// AuthenticateLogWrite checks if a log write request should be allowed
// This implements the hybrid authentication model:
// 1. Check if private ID is associated with a registered node
// 2. If associated, validate IP address
// 3. If not associated, check grace period
func (a *Authenticator) AuthenticateLogWrite(
	association *PrivateIDAssociation,
	firstSeen *FirstSeenRecord,
	clientIP string,
) AuthResult {

	// Step 1: Check if private ID is associated with a registered node
	if association != nil {
		return a.authenticateAssociatedNode(association, clientIP)
	}

	// Step 2: Not associated - check if registration is required
	if !a.config.Auth.WriteAuth.RequireNodeRegistration {
		return AuthResult{
			Allowed: true,
			Reason:  "node registration not required",
		}
	}

	// Step 3: Check grace period
	return a.checkGracePeriod(firstSeen)
}

// authenticateAssociatedNode validates an associated node's request
func (a *Authenticator) authenticateAssociatedNode(
	association *PrivateIDAssociation,
	clientIP string,
) AuthResult {

	// If IP validation is disabled, allow all requests from associated nodes
	if !a.config.Auth.WriteAuth.IPValidation.Enabled {
		return AuthResult{
			Allowed: true,
			Reason:  "associated node, IP validation disabled",
		}
	}

	// Validate IP address
	ipResult := a.ValidateIP(association, clientIP)

	if !ipResult.Allowed {
		// Log IP mismatch if configured
		if a.config.Auth.WriteAuth.IPValidation.LogIPMismatches {
			log.Warn().
				Str("private_id", association.PrivateID).
				Str("client_ip", clientIP).
				Uint64("node_id", association.NodeID).
				Strs("recent_ips", association.RecentIPs).
				Str("reason", ipResult.Reason).
				Msg("IP validation failed for authenticated log writer")
		}

		return AuthResult{
			Allowed: false,
			Reason:  fmt.Sprintf("IP validation failed: %s", ipResult.Reason),
		}
	}

	return AuthResult{
		Allowed: true,
		Reason:  fmt.Sprintf("associated node, %s", ipResult.Reason),
	}
}

// checkGracePeriod determines if a request is within the grace period
func (a *Authenticator) checkGracePeriod(firstSeen *FirstSeenRecord) AuthResult {
	now := time.Now()
	gracePeriod := time.Duration(
		a.config.Auth.WriteAuth.PreAuthGracePeriodSeconds,
	) * time.Second

	// First time seeing this private ID - start grace period
	if firstSeen == nil {
		return AuthResult{
			Allowed:       true,
			Reason:        "grace period started",
			IsGracePeriod: true,
		}
	}

	// Check if grace period has expired
	elapsed := now.Sub(firstSeen.FirstSeenAt)
	if elapsed > gracePeriod {
		return AuthResult{
			Allowed: false,
			Reason: fmt.Sprintf(
				"grace period expired (%s elapsed, %s allowed), node not registered",
				elapsed.Round(time.Second),
				gracePeriod,
			),
		}
	}

	// Within grace period
	remaining := gracePeriod - elapsed
	return AuthResult{
		Allowed:       true,
		Reason:        fmt.Sprintf("within grace period (%s remaining)", remaining.Round(time.Second)),
		IsGracePeriod: true,
	}
}

// ValidateIP checks if the client IP matches the node's known IPs
func (a *Authenticator) ValidateIP(
	association *PrivateIDAssociation,
	clientIP string,
) IPValidationResult {

	mode := a.config.Auth.WriteAuth.IPValidation.Mode

	// Validate mode is known - fail fast on invalid configuration
	if mode != "none" && mode != "strict" && mode != "relaxed" {
		return IPValidationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("unknown IP validation mode: %s", mode),
		}
	}

	// Mode: none - no IP validation
	if mode == "none" {
		return IPValidationResult{
			Allowed: true,
			Reason:  "IP validation disabled (mode: none)",
		}
	}

	// Check for exact IP match
	for _, recentIP := range association.RecentIPs {
		if recentIP == clientIP {
			return IPValidationResult{
				Allowed:      true,
				Reason:       "exact IP match",
				IsExactMatch: true,
			}
		}
	}

	// Strict mode - require exact match
	if mode == "strict" {
		return IPValidationResult{
			Allowed: false,
			Reason: fmt.Sprintf(
				"strict mode: client IP %s not in recent IPs %v",
				clientIP,
				association.RecentIPs,
			),
		}
	}

	// Relaxed mode - allow subnet matches
	return a.validateIPRelaxed(association, clientIP)
}

// validateIPRelaxed checks for /24 subnet matches (NAT/mobile friendly)
func (a *Authenticator) validateIPRelaxed(
	association *PrivateIDAssociation,
	clientIP string,
) IPValidationResult {

	// Parse client IP
	clientAddr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return IPValidationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("invalid client IP format: %s", clientIP),
		}
	}

	// Check each recent IP for subnet match
	for _, recentIP := range association.RecentIPs {
		recentAddr, err := netip.ParseAddr(recentIP)
		if err != nil {
			log.Warn().
				Str("recent_ip", recentIP).
				Str("private_id", association.PrivateID).
				Msg("Invalid IP in recent IPs, skipping")
			continue
		}

		// Check if both IPs are in the same /24 subnet
		if isSameSubnet24(clientAddr, recentAddr) {
			if !a.config.Auth.WriteAuth.IPValidation.AllowIPChanges {
				return IPValidationResult{
					Allowed: false,
					Reason: fmt.Sprintf(
						"subnet match found but IP changes not allowed (client: %s, recent: %s)",
						clientIP,
						recentIP,
					),
				}
			}

			return IPValidationResult{
				Allowed:       true,
				Reason:        fmt.Sprintf("subnet match (/24) with %s", recentIP),
				IsSubnetMatch: true,
			}
		}
	}

	// No match found
	return IPValidationResult{
		Allowed: false,
		Reason: fmt.Sprintf(
			"relaxed mode: client IP %s not in same /24 subnet as recent IPs %v",
			clientIP,
			association.RecentIPs,
		),
	}
}

// isSameSubnet24 checks if two IP addresses are in the same /24 subnet
func isSameSubnet24(a, b netip.Addr) bool {
	// Only works for IPv4
	if !a.Is4() || !b.Is4() {
		return false
	}

	// Compare first 3 octets (24 bits)
	aBytes := a.As4()
	bBytes := b.As4()

	return aBytes[0] == bBytes[0] &&
		aBytes[1] == bBytes[1] &&
		aBytes[2] == bBytes[2]
}

// ShouldUpdateRecentIPs determines if the recent IPs list should be updated
// Returns true if the client IP is not in recent IPs but passed validation
func (a *Authenticator) ShouldUpdateRecentIPs(
	association *PrivateIDAssociation,
	clientIP string,
	ipResult IPValidationResult,
) bool {

	// Don't update if validation failed
	if !ipResult.Allowed {
		return false
	}

	// Don't update if it's already an exact match
	if ipResult.IsExactMatch {
		return false
	}

	// Update if it's a subnet match (new IP in same subnet)
	if ipResult.IsSubnetMatch {
		return true
	}

	// Update if IP validation is disabled and this is a new IP
	if !a.config.Auth.WriteAuth.IPValidation.Enabled {
		for _, recentIP := range association.RecentIPs {
			if recentIP == clientIP {
				return false
			}
		}
		return true
	}

	return false
}
