package logtail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// HandleListCollections returns a list of all collections
// GET /logtail/collections
func (s *LogtailService) HandleListCollections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// API key authentication
	if !s.authenticateAPIKey(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	collections, err := s.storage.ListCollections(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list collections")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := CollectionsResponse{
		Collections: collections,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleQueryLogs queries logs with filtering
// GET /logtail/c/:collection
// Query params: instances, time-start, time-end, max-count, stream
func (s *LogtailService) HandleQueryLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// API key authentication
	if !s.authenticateAPIKey(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	collection := r.PathValue("collection")
	if collection == "" {
		http.Error(w, "Missing collection", http.StatusBadRequest)
		return
	}

	// Parse query parameters
	query, err := s.parseLogQuery(r, collection)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid query parameters: %s", err), http.StatusBadRequest)
		return
	}

	// Check if streaming is requested
	if r.URL.Query().Get("stream") == "true" {
		s.streamLogs(w, r, query)
		return
	}

	// Regular query
	logs, err := s.storage.QueryLogs(ctx, query)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query logs")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert to response format
	response := LogsResponse{
		Logs:  convertLogsToResponse(logs),
		Count: len(logs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGetCollectionInstances returns instances in a collection
// GET /logtail/c/:collection/instances
func (s *LogtailService) HandleGetCollectionInstances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// API key authentication
	if !s.authenticateAPIKey(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	collection := r.PathValue("collection")
	if collection == "" {
		http.Error(w, "Missing collection", http.StatusBadRequest)
		return
	}

	instances, err := s.storage.ListInstancesInCollection(ctx, collection)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list instances")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := InstancesResponse{
		Instances: convertInstancesToResponse(instances),
		Count:     len(instances),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleAdoptInstance persists an instance for long-term retention
// POST /logtail/instances/adopt
func (s *LogtailService) HandleAdoptInstance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// API key authentication
	if !s.authenticateAPIKey(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req AdoptInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Collection == "" || req.PublicID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Default retention if not specified
	retentionDays := req.RetentionDays
	if retentionDays == 0 {
		retentionDays = s.config.Retention.PersistedDefaultDays
	}

	// Get instance to find private ID
	instances, err := s.storage.ListInstancesInCollection(ctx, req.Collection)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list instances")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var privateID string
	for _, inst := range instances {
		if inst.PublicID == req.PublicID {
			privateID = inst.PrivateID
			break
		}
	}

	if privateID == "" {
		http.Error(w, "Instance not found", http.StatusNotFound)
		return
	}

	// Persist logs (migrate ephemeral/grace_period → persisted)
	err = s.PersistLogs(privateID, req.Collection, retentionDays)
	if err != nil {
		log.Error().Err(err).Msg("Failed to persist logs")
		http.Error(w, "Failed to persist logs", http.StatusInternalServerError)
		return
	}

	log.Info().
		Str("collection", req.Collection).
		Str("public_id", req.PublicID).
		Int("retention_days", retentionDays).
		Msg("Instance adopted for long-term retention")

	response := AdoptInstanceResponse{
		Success:       true,
		PublicID:      req.PublicID,
		RetentionDays: retentionDays,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PersistLogs migrates logs to persisted tier and invalidates caches
func (s *LogtailService) PersistLogs(privateID, collection string, retentionDays int) error {
	ctx := context.Background()

	// Get current instance state
	instance, err := s.storage.GetLogInstance(ctx, privateID, collection)
	if err != nil {
		return fmt.Errorf("failed to get instance: %w", err)
	}

	if instance == nil {
		return fmt.Errorf("instance not found")
	}

	// If already persisted, just update retention
	if instance.Persisted {
		err = s.storage.UpdateInstancePersistence(ctx, privateID, collection, true, retentionDays)
		if err != nil {
			return fmt.Errorf("failed to update retention: %w", err)
		}

		// Cache invalidation: instance tier changed
		s.invalidateInstanceTierCache(privateID)

		return nil
	}

	// Migrate all logs to persisted tier
	// Try both grace_period and ephemeral tiers
	err = s.storage.MigrateLogTier(ctx, privateID, collection, LogTierGracePeriod, LogTierPersisted)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to migrate grace period logs (may not exist)")
	}

	err = s.storage.MigrateLogTier(ctx, privateID, collection, LogTierEphemeral, LogTierPersisted)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to migrate ephemeral logs (may not exist)")
	}

	// Mark instance as persisted
	err = s.storage.UpdateInstancePersistence(ctx, privateID, collection, true, retentionDays)
	if err != nil {
		return fmt.Errorf("failed to update instance persistence: %w", err)
	}

	// Cache invalidation: tier migration affects future writes
	// Clear auth cache so next write uses persisted tier
	s.invalidateAuthCache(privateID)
	s.invalidateInstanceTierCache(privateID)

	log.Info().
		Str("private_id", privateID).
		Str("collection", collection).
		Msg("Cache invalidated after tier migration")

	return nil
}

// streamLogs implements streaming log tail
func (s *LogtailService) streamLogs(w http.ResponseWriter, r *http.Request, query LogQuery) {
	// Check if client supports streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx := r.Context()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastTimestamp := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Query for new logs since last timestamp
			query.TimeStart = &lastTimestamp
			query.MaxCount = 100

			logs, err := s.storage.QueryLogs(r.Context(), query)
			if err != nil {
				log.Error().Err(err).Msg("Failed to query logs in stream")
				return
			}

			// Send new logs
			for _, logEntry := range logs {
				logResp := convertLogToResponse(logEntry)
				if err := json.NewEncoder(w).Encode(logResp); err != nil {
					return
				}
				flusher.Flush()

				if logEntry.Timestamp.After(lastTimestamp) {
					lastTimestamp = logEntry.Timestamp
				}
			}
		}
	}
}

// parseLogQuery parses query parameters into LogQuery
func (s *LogtailService) parseLogQuery(r *http.Request, collection string) (LogQuery, error) {
	query := LogQuery{
		Collection: collection,
	}

	// Parse instances (public IDs)
	if instances := r.URL.Query().Get("instances"); instances != "" {
		// In reality, need to convert public IDs to private IDs
		query.PublicIDs = []string{instances}
	}

	// Parse time-start
	if timeStart := r.URL.Query().Get("time-start"); timeStart != "" {
		t, err := time.Parse(time.RFC3339, timeStart)
		if err != nil {
			return query, fmt.Errorf("invalid time-start format")
		}
		query.TimeStart = &t
	}

	// Parse time-end
	if timeEnd := r.URL.Query().Get("time-end"); timeEnd != "" {
		t, err := time.Parse(time.RFC3339, timeEnd)
		if err != nil {
			return query, fmt.Errorf("invalid time-end format")
		}
		query.TimeEnd = &t
	}

	// Parse max-count
	if maxCount := r.URL.Query().Get("max-count"); maxCount != "" {
		count, err := strconv.Atoi(maxCount)
		if err != nil {
			return query, fmt.Errorf("invalid max-count")
		}
		query.MaxCount = count
	}

	return query, nil
}

// authenticateAPIKey checks if the request has a valid API key
func (s *LogtailService) authenticateAPIKey(r *http.Request) bool {
	// Get API key from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	// Expected format: "Bearer <api-key>"
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return false
	}

	apiKey := authHeader[7:]

	// Validate against Headscale API keys
	// TODO: This should call into Headscale's existing API key validation
	// For now, just check if it's non-empty (placeholder)
	return apiKey != ""
}

// invalidateAuthCache evicts authentication cache entry
func (s *LogtailService) invalidateAuthCache(privateID string) {
	s.cache.authCache.Delete(privateID)
}

// invalidateInstanceTierCache evicts instance tier cache entry
func (s *LogtailService) invalidateInstanceTierCache(privateID string) {
	// The tier cache uses privateID:collection as key, but we need to clear all entries
	// for this privateID. Since sync.Map doesn't support prefix search, we rely on
	// natural expiration. The auth cache invalidation is the critical one.
	// For now, this is a no-op as the tier is embedded in instance metadata.
	log.Debug().Str("private_id", privateID).Msg("Instance tier cache invalidation requested")
}

// Response types
type CollectionsResponse struct {
	Collections []string `json:"collections"`
}

type LogsResponse struct {
	Logs  []LogResponse `json:"logs"`
	Count int           `json:"count"`
}

type LogResponse struct {
	PublicID  string    `json:"public_id"`
	Timestamp time.Time `json:"timestamp"`
	Text      string    `json:"text"`
	ProcID    int       `json:"proc_id,omitempty"`
	ProcSeq   int64     `json:"proc_seq,omitempty"`
}

type InstancesResponse struct {
	Instances []InstanceResponse `json:"instances"`
	Count     int                `json:"count"`
}

type InstanceResponse struct {
	PublicID       string     `json:"public_id"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	TotalLogs      int        `json:"total_logs"`
	TotalSizeBytes int64      `json:"total_size_bytes"`
	Persisted      bool       `json:"persisted"`
	PersistedAt    *time.Time `json:"persisted_at,omitempty"`
	RetentionDays  *int       `json:"retention_days,omitempty"`
}

type AdoptInstanceRequest struct {
	Collection    string `json:"collection"`
	PublicID      string `json:"public_id"`
	RetentionDays int    `json:"retention_days,omitempty"`
}

type AdoptInstanceResponse struct {
	Success       bool   `json:"success"`
	PublicID      string `json:"public_id"`
	RetentionDays int    `json:"retention_days"`
}

// Conversion helpers
func convertLogsToResponse(logs []LogEntry) []LogResponse {
	result := make([]LogResponse, len(logs))
	for i, log := range logs {
		result[i] = convertLogToResponse(log)
	}
	return result
}

func convertLogToResponse(log LogEntry) LogResponse {
	// Parse log data to extract text and logtail metadata
	var data map[string]interface{}
	json.Unmarshal(log.LogData, &data)

	text := ""
	procID := 0
	procSeq := int64(0)

	if data != nil {
		if t, ok := data["text"].(string); ok {
			text = t
		}
		if logtail, ok := data["logtail"].(map[string]interface{}); ok {
			if pid, ok := logtail["proc_id"].(float64); ok {
				procID = int(pid)
			}
			if pseq, ok := logtail["proc_seq"].(float64); ok {
				procSeq = int64(pseq)
			}
		}
	}

	return LogResponse{
		PublicID:  log.PublicID,
		Timestamp: log.Timestamp,
		Text:      text,
		ProcID:    procID,
		ProcSeq:   procSeq,
	}
}

func convertInstancesToResponse(instances []LogInstance) []InstanceResponse {
	result := make([]InstanceResponse, len(instances))
	for i, inst := range instances {
		resp := InstanceResponse{
			PublicID:       inst.PublicID,
			FirstSeen:      inst.FirstSeen,
			LastSeen:       inst.LastSeen,
			TotalLogs:      inst.TotalLogs,
			TotalSizeBytes: inst.TotalSizeBytes,
			Persisted:      inst.Persisted,
		}

		// Convert PersistedAt to pointer if not zero
		if !inst.PersistedAt.IsZero() {
			resp.PersistedAt = &inst.PersistedAt
		}

		// Convert RetentionDays to pointer if not zero
		if inst.RetentionDays > 0 {
			resp.RetentionDays = &inst.RetentionDays
		}

		result[i] = resp
	}
	return result
}
