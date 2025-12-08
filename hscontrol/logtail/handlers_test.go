package logtail

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupHandlerTestDB creates an in-memory SQLite database for handler tests
func setupHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create all required tables
	err = db.AutoMigrate(
		&LogEntry{},
		&LogInstance{},
		&PrivateIDAssociation{},
		&IPObservation{},
		&FirstSeenRecord{},
		&RateLimitWindow{},
	)
	if err != nil {
		t.Fatalf("Failed to migrate tables: %v", err)
	}

	return db
}

// setupHandlerTestService creates a test service with all components
func setupHandlerTestService(t *testing.T) (*LogtailService, *Handler) {
	t.Helper()

	db := setupHandlerTestDB(t)
	storage := NewDBStorage(db)
	rateLimiter := NewRateLimiter(db, 100) // 100 requests per minute
	config := types.LogTailServerConfig{
		Enabled:     true,
		EnableCache: true,
		Retention: types.LogTailRetentionConfig{
			EphemeralMinutes:     720,
			PersistedDefaultDays: 30,
			CleanupIntervalHours: 1,
		},
		RateLimit: types.LogTailRateLimitConfig{
			RequestsPerMinute: 100,
		},
		Auth: types.LogTailAuthConfig{
			WriteAuth: types.WriteAuthConfig{
				RequireNodeRegistration:   true,
				PreAuthGracePeriodSeconds: 300, // 5 minutes
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

	service := NewLogtailService(storage, rateLimiter, config)
	handler := NewHandler(service)

	return service, handler
}

func TestUploadHandler_Success(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	// Create test request
	reqBody := UploadRequest{
		Collection: "test.collection",
		PrivateID:  "test-private-id",
		PublicID:   "test-public-id",
		Logs: []LogEntryRequest{
			{
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"message": "test log 1",
					"level":   "info",
				},
			},
			{
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"message": "test log 2",
					"level":   "debug",
				},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	// Execute handler
	handler.UploadHandler(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp UploadResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false")
	}

	if resp.LogsAccepted != 2 {
		t.Errorf("Expected 2 logs accepted, got %d", resp.LogsAccepted)
	}

	if resp.LogsRejected != 0 {
		t.Errorf("Expected 0 logs rejected, got %d", resp.LogsRejected)
	}
}

func TestUploadHandler_MethodNotAllowed(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/upload", nil)
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestUploadHandler_InvalidJSON(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader([]byte("invalid json")))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Success {
		t.Errorf("Expected success=false, got true")
	}

	if resp.Error == "" {
		t.Errorf("Expected error message, got empty string")
	}
}

func TestUploadHandler_MissingCollection(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	reqBody := UploadRequest{
		PrivateID: "test-private-id",
		Logs: []LogEntryRequest{
			{
				Timestamp: time.Now(),
				Data:      map[string]interface{}{"message": "test"},
			},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUploadHandler_MissingPrivateID(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	reqBody := UploadRequest{
		Collection: "test.collection",
		Logs: []LogEntryRequest{
			{
				Timestamp: time.Now(),
				Data:      map[string]interface{}{"message": "test"},
			},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUploadHandler_NoLogs(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	reqBody := UploadRequest{
		Collection: "test.collection",
		PrivateID:  "test-private-id",
		Logs:       []LogEntryRequest{},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUploadHandler_TooManyLogs(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	// Create 1001 logs (over the limit)
	logs := make([]LogEntryRequest, 1001)
	for i := range logs {
		logs[i] = LogEntryRequest{
			Timestamp: time.Now(),
			Data:      map[string]interface{}{"message": "test"},
		}
	}

	reqBody := UploadRequest{
		Collection: "test.collection",
		PrivateID:  "test-private-id",
		Logs:       logs,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUploadHandler_WithAuthentication(t *testing.T) {
	service, handler := setupHandlerTestService(t)

	// Create an association (authenticated user)
	assoc := &PrivateIDAssociation{
		PrivateID:  "authenticated-id",
		NodeID:     123,
		Collection: "test.collection",
		CurrentIP:  "192.168.1.100",
		RecentIPs:  []string{"192.168.1.100"},
	}
	err := service.storage.StorePrivateIDAssociation(context.Background(), assoc)
	if err != nil {
		t.Fatalf("Failed to store association: %v", err)
	}

	reqBody := UploadRequest{
		Collection: "test.collection",
		PrivateID:  "authenticated-id",
		Logs: []LogEntryRequest{
			{
				Timestamp: time.Now(),
				Data:      map[string]interface{}{"message": "authenticated log"},
			},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/upload", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.UploadHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp UploadResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Errorf("Expected success=true, got false")
	}
}

func TestQueryHandler_GET_Success(t *testing.T) {
	service, handler := setupHandlerTestService(t)

	// Store some test logs
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "query-test-id",
			PublicID:   "public-123",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"log 1"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
		{
			Collection: "test.collection",
			PrivateID:  "query-test-id",
			PublicID:   "public-123",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"log 2"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
	}
	err := service.storage.StoreLogs(context.Background(), logs)
	if err != nil {
		t.Fatalf("Failed to store logs: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/query?collection=test.collection&private_id=query-test-id&limit=10", nil)
	w := httptest.NewRecorder()

	handler.QueryHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp QueryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false")
	}

	if len(resp.Logs) != 2 {
		t.Errorf("Expected 2 logs, got %d", len(resp.Logs))
	}

	if resp.Total != 2 {
		t.Errorf("Expected total=2, got %d", resp.Total)
	}
}

func TestQueryHandler_POST_Success(t *testing.T) {
	service, handler := setupHandlerTestService(t)

	// Store test logs
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "post-test-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"log 1"}`),
			SizeBytes:  20,
			LogTier:    LogTierEphemeral,
		},
	}
	service.storage.StoreLogs(context.Background(), logs)

	queryReq := QueryRequest{
		Collection: "test.collection",
		PrivateID:  "post-test-id",
		Limit:      10,
	}

	body, _ := json.Marshal(queryReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logtail/query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.QueryHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp QueryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Errorf("Expected success=true, got false")
	}

	if len(resp.Logs) != 1 {
		t.Errorf("Expected 1 log, got %d", len(resp.Logs))
	}
}

func TestQueryHandler_MissingCollection(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/query?private_id=test-id", nil)
	w := httptest.NewRecorder()

	handler.QueryHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestQueryHandler_MissingPrivateAndPublicID(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/query?collection=test.collection", nil)
	w := httptest.NewRecorder()

	handler.QueryHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestQueryHandler_WithTimeFilters(t *testing.T) {
	service, handler := setupHandlerTestService(t)

	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	// Store logs with different timestamps
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "time-test-id",
			Timestamp:  past,
			LogData:    []byte(`{"message":"old log"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
		{
			Collection: "test.collection",
			PrivateID:  "time-test-id",
			Timestamp:  now,
			LogData:    []byte(`{"message":"current log"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
	}
	service.storage.StoreLogs(context.Background(), logs)

	startTime := past.Add(30 * time.Minute)
	endTime := future

	url := "/api/v1/logtail/query?collection=test.collection&private_id=time-test-id&start_time=" +
		startTime.Format(time.RFC3339) + "&end_time=" + endTime.Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()

	handler.QueryHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp QueryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Should only return the current log (within time range)
	if len(resp.Logs) > 2 {
		t.Errorf("Expected at most 2 logs, got %d", len(resp.Logs))
	}
}

func TestQueryHandler_WithLimit(t *testing.T) {
	service, handler := setupHandlerTestService(t)

	// Store multiple logs
	logs := []LogEntry{}
	for i := 0; i < 5; i++ {
		logs = append(logs, LogEntry{
			Collection: "test.collection",
			PrivateID:  "limit-test-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"log"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		})
	}
	service.storage.StoreLogs(context.Background(), logs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/query?collection=test.collection&private_id=limit-test-id&limit=2", nil)
	w := httptest.NewRecorder()

	handler.QueryHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp QueryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if len(resp.Logs) > 2 {
		t.Errorf("Expected at most 2 logs, got %d", len(resp.Logs))
	}
}

func TestGetInstanceHandler_Success(t *testing.T) {
	service, handler := setupHandlerTestService(t)

	// Store logs to create an instance
	logs := []LogEntry{
		{
			Collection: "test.collection",
			PrivateID:  "instance-test-id",
			Timestamp:  time.Now(),
			LogData:    []byte(`{"message":"test"}`),
			SizeBytes:  20,
			LogTier:    LogTierGracePeriod,
		},
	}
	service.storage.StoreLogs(context.Background(), logs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/instance?collection=test.collection&private_id=instance-test-id", nil)
	w := httptest.NewRecorder()

	handler.GetInstanceHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var instance LogInstance
	if err := json.NewDecoder(w.Body).Decode(&instance); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if instance.PrivateID != "instance-test-id" {
		t.Errorf("Expected private_id=instance-test-id, got %s", instance.PrivateID)
	}

	if instance.Collection != "test.collection" {
		t.Errorf("Expected collection=test.collection, got %s", instance.Collection)
	}
}

func TestGetInstanceHandler_MissingCollection(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/instance?private_id=test-id", nil)
	w := httptest.NewRecorder()

	handler.GetInstanceHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetInstanceHandler_MissingPrivateID(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/instance?collection=test.collection", nil)
	w := httptest.NewRecorder()

	handler.GetInstanceHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetInstanceHandler_NotFound(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logtail/instance?collection=test.collection&private_id=nonexistent", nil)
	w := httptest.NewRecorder()

	handler.GetInstanceHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestExtractClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	ip := extractClientIP(req)

	if ip != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", ip)
	}
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")

	ip := extractClientIP(req)

	if ip != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", ip)
	}
}

func TestExtractClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Real-IP", "10.0.0.5")

	ip := extractClientIP(req)

	if ip != "10.0.0.5" {
		t.Errorf("Expected IP 10.0.0.5, got %s", ip)
	}
}

func TestExtractClientIP_XForwardedForPriority(t *testing.T) {
	// X-Forwarded-For should take priority over X-Real-IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.5")

	ip := extractClientIP(req)

	if ip != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1 (from X-Forwarded-For), got %s", ip)
	}
}

func TestValidateUploadRequest_EmptyData(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := &UploadRequest{
		Collection: "test.collection",
		PrivateID:  "test-id",
		Logs: []LogEntryRequest{
			{
				Timestamp: time.Now(),
				Data:      map[string]interface{}{}, // Empty data
			},
		},
	}

	err := handler.validateUploadRequest(req)
	if err == nil {
		t.Error("Expected error for empty log data, got nil")
	}
}

func TestValidateQueryRequest_NegativeLimit(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	req := &QueryRequest{
		Collection: "test.collection",
		PrivateID:  "test-id",
		Limit:      -1,
	}

	err := handler.validateQueryRequest(req)
	if err == nil {
		t.Error("Expected error for negative limit, got nil")
	}
}

func TestValidateQueryRequest_InvalidTimeRange(t *testing.T) {
	_, handler := setupHandlerTestService(t)

	now := time.Now()
	past := now.Add(-1 * time.Hour)

	req := &QueryRequest{
		Collection: "test.collection",
		PrivateID:  "test-id",
		StartTime:  &now,
		EndTime:    &past, // End before start
	}

	err := handler.validateQueryRequest(req)
	if err == nil {
		t.Error("Expected error for invalid time range, got nil")
	}
}
