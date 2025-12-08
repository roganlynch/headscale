package logtail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// API Request/Response Types

// UploadRequest represents a log upload request from a Tailscale node
type UploadRequest struct {
	// Collection is the log collection name (e.g., "logtail.tailscale.com")
	Collection string `json:"collection"`

	// PrivateID is the unique identifier for the logging session
	PrivateID string `json:"private_id"`

	// PublicID is the optionally visible identifier
	PublicID string `json:"public_id,omitempty"`

	// Logs is the array of log entries to upload
	Logs []LogEntryRequest `json:"logs"`
}

// LogEntryRequest represents a single log entry in an upload request
type LogEntryRequest struct {
	// Timestamp is when the log was generated (client time)
	Timestamp time.Time `json:"timestamp"`

	// Data is the log data (will be JSON-encoded for storage)
	Data map[string]interface{} `json:"data"`
}

// UploadResponse represents the response to a log upload request
type UploadResponse struct {
	// Success indicates whether the upload was successful
	Success bool `json:"success"`

	// Message provides additional information about the upload
	Message string `json:"message,omitempty"`

	// LogsAccepted is the number of logs successfully stored
	LogsAccepted int `json:"logs_accepted"`

	// LogsRejected is the number of logs rejected
	LogsRejected int `json:"logs_rejected,omitempty"`
}

// QueryRequest represents a log query request
type QueryRequest struct {
	// Collection is the log collection to query (required)
	Collection string `json:"collection"`

	// PrivateID is the private ID to query logs for (optional)
	PrivateID string `json:"private_id,omitempty"`

	// PublicID is the public ID to query logs for (optional)
	PublicID string `json:"public_id,omitempty"`

	// StartTime filters logs after this time (optional)
	StartTime *time.Time `json:"start_time,omitempty"`

	// EndTime filters logs before this time (optional)
	EndTime *time.Time `json:"end_time,omitempty"`

	// Limit is the maximum number of logs to return
	Limit int `json:"limit,omitempty"`

	// Tier specifies which storage tier to query (optional)
	Tier *LogTier `json:"tier,omitempty"`
}

// QueryResponse represents the response to a log query
type QueryResponse struct {
	// Success indicates whether the query was successful
	Success bool `json:"success"`

	// Message provides additional information about the query
	Message string `json:"message,omitempty"`

	// Logs is the array of log entries matching the query
	Logs []LogEntryResponse `json:"logs"`

	// Total is the total number of logs returned
	Total int `json:"total"`
}

// LogEntryResponse represents a log entry in a query response
type LogEntryResponse struct {
	// ID is the unique identifier for this log entry
	ID uint64 `json:"id"`

	// Collection is the log collection
	Collection string `json:"collection"`

	// PrivateID is the private ID associated with this log
	PrivateID string `json:"private_id"`

	// PublicID is the public ID (if available)
	PublicID string `json:"public_id,omitempty"`

	// Timestamp is when the log was generated
	Timestamp time.Time `json:"timestamp"`

	// Data is the log data
	Data json.RawMessage `json:"data"`

	// SizeBytes is the size of the log entry
	SizeBytes int `json:"size_bytes"`

	// Tier is the storage tier this log is currently in
	Tier LogTier `json:"tier"`

	// Persisted indicates if this log has been explicitly persisted
	Persisted bool `json:"persisted"`

	// CreatedAt is when the log was received by the server
	CreatedAt time.Time `json:"created_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// Handler is the HTTP handler for logtail endpoints
type Handler struct {
	service *LogtailService
}

// NewHandler creates a new logtail HTTP handler
func NewHandler(service *LogtailService) *Handler {
	return &Handler{
		service: service,
	}
}

// UploadHandler handles POST /api/v1/logtail/upload
func (h *Handler) UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract client IP
	clientIP := extractClientIP(r)
	if clientIP == "" {
		log.Warn().Str("remote_addr", r.RemoteAddr).Msg("failed to extract client IP")
		h.sendError(w, http.StatusBadRequest, "invalid client IP")
		return
	}

	// Read and parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error().Err(err).Msg("failed to read upload request body")
		h.sendError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req UploadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Error().Err(err).Msg("failed to parse upload request")
		h.sendError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate request
	if err := h.validateUploadRequest(&req); err != nil {
		log.Warn().Err(err).Str("private_id", req.PrivateID).Msg("invalid upload request")
		h.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check rate limits
	allowed, err := h.service.rateLimiter.CheckLimit(r.Context(), req.PrivateID)
	if err != nil {
		log.Error().Err(err).Str("private_id", req.PrivateID).Msg("rate limit check failed")
		h.sendError(w, http.StatusInternalServerError, "rate limit check failed")
		return
	}
	if !allowed {
		log.Warn().Str("private_id", req.PrivateID).Msg("rate limit exceeded")
		h.sendError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	// Authenticate with cache
	authResult := h.service.AuthenticateWithCache(r.Context(), req.PrivateID, clientIP, req.Collection)
	if !authResult.Allowed {
		log.Warn().
			Str("private_id", req.PrivateID).
			Str("client_ip", clientIP).
			Str("reason", authResult.Reason).
			Msg("authentication failed")

		h.sendError(w, http.StatusForbidden, authResult.Reason)
		return
	}

	// Determine tier based on authentication result
	tier := LogTierEphemeral
	if authResult.IsGracePeriod {
		tier = LogTierGracePeriod
	}

	// Convert and store logs
	logsAccepted := 0
	logsRejected := 0
	entries := make([]LogEntry, 0, len(req.Logs))

	for _, logReq := range req.Logs {
		// JSON-encode the log data
		logData, err := json.Marshal(logReq.Data)
		if err != nil {
			log.Error().Err(err).Msg("failed to marshal log data")
			logsRejected++
			continue
		}

		entry := LogEntry{
			Collection: req.Collection,
			PrivateID:  req.PrivateID,
			PublicID:   req.PublicID,
			Timestamp:  logReq.Timestamp,
			LogData:    logData,
			SizeBytes:  len(logData),
			Persisted:  false,
			LogTier:    tier,
			CreatedAt:  time.Now().UTC(),
		}

		// Set default timestamp if not provided
		if entry.Timestamp.IsZero() {
			entry.Timestamp = entry.CreatedAt
		}

		entries = append(entries, entry)
		logsAccepted++
	}

	// Store all logs in batch
	if len(entries) > 0 {
		if err := h.service.StoreLogs(r.Context(), entries); err != nil {
			log.Error().
				Err(err).
				Str("private_id", req.PrivateID).
				Int("count", len(entries)).
				Msg("failed to store logs")
			h.sendError(w, http.StatusInternalServerError, "failed to store logs")
			return
		}
	}

	// Send response
	resp := UploadResponse{
		Success:      logsAccepted > 0,
		Message:      fmt.Sprintf("accepted %d logs", logsAccepted),
		LogsAccepted: logsAccepted,
		LogsRejected: logsRejected,
	}

	if logsRejected > 0 {
		resp.Message = fmt.Sprintf("accepted %d logs, rejected %d logs", logsAccepted, logsRejected)
	}

	h.sendJSON(w, http.StatusOK, resp)

	log.Debug().
		Str("private_id", req.PrivateID).
		Str("collection", req.Collection).
		Str("client_ip", clientIP).
		Int("accepted", logsAccepted).
		Int("rejected", logsRejected).
		Bool("grace_period", authResult.IsGracePeriod).
		Msg("processed log upload")
}

// QueryHandler handles GET /api/v1/logtail/query
func (h *Handler) QueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse query parameters or JSON body
	var req QueryRequest
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("failed to read query request body")
			h.sendError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		if err := json.Unmarshal(body, &req); err != nil {
			log.Error().Err(err).Msg("failed to parse query request")
			h.sendError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
	} else {
		// Parse from URL query parameters
		if err := h.parseQueryParams(r, &req); err != nil {
			log.Warn().Err(err).Msg("invalid query parameters")
			h.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Validate request
	if err := h.validateQueryRequest(&req); err != nil {
		log.Warn().Err(err).Msg("invalid query request")
		h.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Set default limit if not specified
	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > 10000 {
		req.Limit = 10000
	}

	// Build query
	query := h.buildLogQuery(&req)

	// Execute query
	logs, err := h.service.QueryLogs(r.Context(), query)
	if err != nil {
		log.Error().Err(err).Msg("failed to query logs")
		h.sendError(w, http.StatusInternalServerError, "failed to query logs")
		return
	}

	// Convert to response format
	logResponses := make([]LogEntryResponse, 0, len(logs))
	for _, entry := range logs {
		logResponses = append(logResponses, LogEntryResponse{
			ID:         entry.ID,
			Collection: entry.Collection,
			PrivateID:  entry.PrivateID,
			PublicID:   entry.PublicID,
			Timestamp:  entry.Timestamp,
			Data:       json.RawMessage(entry.LogData),
			SizeBytes:  entry.SizeBytes,
			Tier:       entry.LogTier,
			Persisted:  entry.Persisted,
			CreatedAt:  entry.CreatedAt,
		})
	}

	// Send response
	resp := QueryResponse{
		Success: true,
		Logs:    logResponses,
		Total:   len(logResponses),
	}

	h.sendJSON(w, http.StatusOK, resp)

	log.Debug().
		Str("collection", req.Collection).
		Str("private_id", req.PrivateID).
		Int("count", len(logResponses)).
		Int("limit", req.Limit).
		Msg("processed log query")
}

// Helper functions

func (h *Handler) validateUploadRequest(req *UploadRequest) error {
	if req.Collection == "" {
		return fmt.Errorf("collection is required")
	}

	if req.PrivateID == "" {
		return fmt.Errorf("private_id is required")
	}

	if len(req.Logs) == 0 {
		return fmt.Errorf("at least one log entry is required")
	}

	if len(req.Logs) > 1000 {
		return fmt.Errorf("too many logs in single request (max 1000)")
	}

	for i, entry := range req.Logs {
		if entry.Data == nil || len(entry.Data) == 0 {
			return fmt.Errorf("log entry %d: data is required", i)
		}
	}

	return nil
}

func (h *Handler) validateQueryRequest(req *QueryRequest) error {
	if req.Collection == "" {
		return fmt.Errorf("collection is required")
	}

	if req.PrivateID == "" && req.PublicID == "" {
		return fmt.Errorf("either private_id or public_id must be specified")
	}

	if req.Limit < 0 {
		return fmt.Errorf("limit must be non-negative")
	}

	if req.StartTime != nil && req.EndTime != nil && req.EndTime.Before(*req.StartTime) {
		return fmt.Errorf("end_time must be after start_time")
	}

	return nil
}

func (h *Handler) parseQueryParams(r *http.Request, req *QueryRequest) error {
	q := r.URL.Query()

	// Parse collection
	req.Collection = q.Get("collection")

	// Parse private_id
	req.PrivateID = q.Get("private_id")

	// Parse public_id
	req.PublicID = q.Get("public_id")

	// Parse start_time
	if startTimeStr := q.Get("start_time"); startTimeStr != "" {
		startTime, err := time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			return fmt.Errorf("invalid start_time (use RFC3339 format): %w", err)
		}
		req.StartTime = &startTime
	}

	// Parse end_time
	if endTimeStr := q.Get("end_time"); endTimeStr != "" {
		endTime, err := time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			return fmt.Errorf("invalid end_time (use RFC3339 format): %w", err)
		}
		req.EndTime = &endTime
	}

	// Parse limit
	if limitStr := q.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			return fmt.Errorf("invalid limit: %w", err)
		}
		req.Limit = limit
	}

	// Parse tier
	if tierStr := q.Get("tier"); tierStr != "" {
		tier := LogTier(tierStr)
		req.Tier = &tier
	}

	return nil
}

func (h *Handler) buildLogQuery(req *QueryRequest) LogQuery {
	query := LogQuery{
		Collection: req.Collection,
		MaxCount:   req.Limit,
		TimeStart:  req.StartTime,
		TimeEnd:    req.EndTime,
		Tier:       req.Tier,
	}

	if req.PrivateID != "" {
		query.PrivateIDs = []string{req.PrivateID}
	}

	if req.PublicID != "" {
		query.PublicIDs = []string{req.PublicID}
	}

	return query
}

func (h *Handler) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("failed to encode JSON response")
	}
}

func (h *Handler) sendError(w http.ResponseWriter, status int, message string) {
	h.sendJSON(w, status, ErrorResponse{
		Success: false,
		Error:   message,
	})
}

// extractClientIP extracts the client IP address from the request
// It checks X-Forwarded-For and X-Real-IP headers, falling back to RemoteAddr
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (can be a comma-separated list)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		ips := splitIPs(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// splitIPs splits a comma-separated list of IPs and trims whitespace
func splitIPs(s string) []string {
	parts := []string{}
	for _, part := range splitString(s, ',') {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// splitString splits a string by a delimiter
func splitString(s string, delim rune) []string {
	parts := []string{}
	current := ""
	for _, r := range s {
		if r == delim {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// trimSpace trims whitespace from a string
func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && isSpace(s[start]) {
		start++
	}

	for end > start && isSpace(s[end-1]) {
		end--
	}

	return s[start:end]
}

// isSpace checks if a byte is a whitespace character
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// GetInstanceHandler handles GET /api/v1/logtail/instance
// Returns metadata about a log instance
func (h *Handler) GetInstanceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	collection := r.URL.Query().Get("collection")
	privateID := r.URL.Query().Get("private_id")

	if collection == "" {
		h.sendError(w, http.StatusBadRequest, "collection is required")
		return
	}

	if privateID == "" {
		h.sendError(w, http.StatusBadRequest, "private_id is required")
		return
	}

	instance, err := h.service.GetLogInstance(context.Background(), privateID, collection)
	if err != nil {
		log.Error().Err(err).Str("private_id", privateID).Str("collection", collection).Msg("failed to get log instance")
		h.sendError(w, http.StatusInternalServerError, "failed to get log instance")
		return
	}

	if instance == nil {
		h.sendError(w, http.StatusNotFound, "instance not found")
		return
	}

	h.sendJSON(w, http.StatusOK, instance)
}
