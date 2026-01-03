package breitheamh

import (
	"context"
	"testing"
	"time"
)

func TestMemoryAuditLogger(t *testing.T) {
	logger := NewMemoryAuditLogger(100)
	ctx := context.Background()

	event := &AuditEvent{
		Type:      EventLoginSuccess,
		UserID:    "123",
		Username:  "testuser",
		IP:        "127.0.0.1",
		GuardName: "web",
		Result:    "success",
	}

	err := logger.Log(ctx, event)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	events := logger.GetAll()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].UserID != "123" {
		t.Errorf("Expected UserID 123, got %s", events[0].UserID)
	}

	if events[0].ID == "" {
		t.Error("Expected event ID to be generated")
	}

	if events[0].Timestamp.IsZero() {
		t.Error("Expected timestamp to be set")
	}
}

func TestAuditLoggerQuery(t *testing.T) {
	logger := NewMemoryAuditLogger(100)
	ctx := context.Background()

	// Log multiple events
	events := []*AuditEvent{
		{Type: EventLoginSuccess, UserID: "user1", IP: "127.0.0.1", Result: "success"},
		{Type: EventLoginFailed, UserID: "user2", IP: "127.0.0.2", Result: "failure"},
		{Type: EventLogout, UserID: "user1", IP: "127.0.0.1", Result: "success"},
		{Type: Event2FAEnabled, UserID: "user1", IP: "127.0.0.1", Result: "success"},
	}

	for _, e := range events {
		logger.Log(ctx, e)
	}

	// Query by user ID
	results, err := logger.Query(ctx, &AuditFilter{UserID: "user1"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("Expected 3 events for user1, got %d", len(results))
	}

	// Query by event type
	results, err = logger.Query(ctx, &AuditFilter{
		EventTypes: []AuditEventType{EventLoginSuccess, EventLoginFailed},
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 login events, got %d", len(results))
	}

	// Query by IP
	results, err = logger.Query(ctx, &AuditFilter{IP: "127.0.0.2"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 event from IP, got %d", len(results))
	}

	// Query by result
	results, err = logger.Query(ctx, &AuditFilter{Result: "failure"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 failure event, got %d", len(results))
	}
}

func TestAuditLoggerPagination(t *testing.T) {
	logger := NewMemoryAuditLogger(100)
	ctx := context.Background()

	// Log 10 events
	for i := 0; i < 10; i++ {
		logger.Log(ctx, &AuditEvent{
			Type:   EventLoginSuccess,
			UserID: "user1",
			Result: "success",
		})
	}

	// Test limit
	results, err := logger.Query(ctx, &AuditFilter{Limit: 5})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 5 {
		t.Errorf("Expected 5 events, got %d", len(results))
	}

	// Test offset
	results, err = logger.Query(ctx, &AuditFilter{Offset: 5, Limit: 5})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 5 {
		t.Errorf("Expected 5 events, got %d", len(results))
	}

	// Test offset beyond total
	results, err = logger.Query(ctx, &AuditFilter{Offset: 20})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 events, got %d", len(results))
	}
}

func TestAuditLoggerTimeFilter(t *testing.T) {
	logger := NewMemoryAuditLogger(100)
	ctx := context.Background()

	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	// Log events at different times
	logger.Log(ctx, &AuditEvent{
		Type:      EventLoginSuccess,
		UserID:    "user1",
		Timestamp: past,
	})
	logger.Log(ctx, &AuditEvent{
		Type:      EventLoginSuccess,
		UserID:    "user1",
		Timestamp: now,
	})
	logger.Log(ctx, &AuditEvent{
		Type:      EventLoginSuccess,
		UserID:    "user1",
		Timestamp: future,
	})

	// Query with start time
	results, err := logger.Query(ctx, &AuditFilter{StartTime: &now})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 events after start time, got %d", len(results))
	}

	// Query with end time
	results, err = logger.Query(ctx, &AuditFilter{EndTime: &now})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 events before end time, got %d", len(results))
	}

	// Query with time range
	results, err = logger.Query(ctx, &AuditFilter{StartTime: &past, EndTime: &now})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 events in time range, got %d", len(results))
	}
}

func TestAuditLoggerMaxSize(t *testing.T) {
	logger := NewMemoryAuditLogger(5)
	ctx := context.Background()

	// Log 10 events
	for i := 0; i < 10; i++ {
		logger.Log(ctx, &AuditEvent{
			Type:   EventLoginSuccess,
			UserID: "user1",
		})
	}

	events := logger.GetAll()
	if len(events) != 5 {
		t.Errorf("Expected logger to keep only 5 events, got %d", len(events))
	}
}

func TestAuditLoggerClear(t *testing.T) {
	logger := NewMemoryAuditLogger(100)
	ctx := context.Background()

	logger.Log(ctx, &AuditEvent{Type: EventLoginSuccess})
	logger.Log(ctx, &AuditEvent{Type: EventLoginSuccess})

	if len(logger.GetAll()) != 2 {
		t.Error("Expected 2 events before clear")
	}

	logger.Clear()

	if len(logger.GetAll()) != 0 {
		t.Error("Expected 0 events after clear")
	}
}

func TestNoOpAuditLogger(t *testing.T) {
	logger := &NoOpAuditLogger{}
	ctx := context.Background()

	err := logger.Log(ctx, &AuditEvent{Type: EventLoginSuccess})
	if err != nil {
		t.Errorf("NoOpAuditLogger.Log should not return error, got %v", err)
	}

	events, err := logger.Query(ctx, &AuditFilter{})
	if err != nil {
		t.Errorf("NoOpAuditLogger.Query should not return error, got %v", err)
	}
	if len(events) != 0 {
		t.Errorf("NoOpAuditLogger.Query should return empty slice, got %d events", len(events))
	}
}

func TestMultiAuditLogger(t *testing.T) {
	logger1 := NewMemoryAuditLogger(100)
	logger2 := NewMemoryAuditLogger(100)
	multiLogger := NewMultiAuditLogger(logger1, logger2)

	ctx := context.Background()
	event := &AuditEvent{
		Type:   EventLoginSuccess,
		UserID: "user1",
	}

	err := multiLogger.Log(ctx, event)
	if err != nil {
		t.Fatalf("MultiAuditLogger.Log failed: %v", err)
	}

	// Check both loggers received the event
	if len(logger1.GetAll()) != 1 {
		t.Error("Expected logger1 to have 1 event")
	}
	if len(logger2.GetAll()) != 1 {
		t.Error("Expected logger2 to have 1 event")
	}

	// Query should return from first logger
	results, err := multiLogger.Query(ctx, &AuditFilter{})
	if err != nil {
		t.Fatalf("MultiAuditLogger.Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result from query, got %d", len(results))
	}
}

func TestAuditEventTypes(t *testing.T) {
	// Just verify all event types are defined and unique
	eventTypes := []AuditEventType{
		EventLoginSuccess,
		EventLoginFailed,
		EventLogout,
		EventTokenRefresh,
		EventTokenRevoked,
		EventPasswordChanged,
		EventPasswordResetRequest,
		EventPasswordReset,
		EventPermissionDenied,
		EventRoleAssigned,
		EventRoleRevoked,
		EventPermissionGranted,
		EventPermissionRevoked,
		Event2FAEnabled,
		Event2FADisabled,
		Event2FASuccess,
		Event2FAFailed,
		EventBackupCodeUsed,
		EventBackupCodeRegen,
		EventAccountLocked,
		EventAccountUnlocked,
		EventBruteForce,
		EventRateLimited,
		EventIPBlocked,
		EventCSRFViolation,
	}

	seen := make(map[AuditEventType]bool)
	for _, et := range eventTypes {
		if seen[et] {
			t.Errorf("Duplicate event type: %s", et)
		}
		seen[et] = true
		if et == "" {
			t.Error("Event type should not be empty")
		}
	}
}
