package breitheamh

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AuditEventType represents the type of security event
type AuditEventType string

const (
	// Authentication events
	EventLoginSuccess         AuditEventType = "login.success"
	EventLoginFailed          AuditEventType = "login.failed"
	EventLogout               AuditEventType = "logout"
	EventTokenRefresh         AuditEventType = "token.refresh"
	EventTokenRevoked         AuditEventType = "token.revoked"
	EventPasswordChanged      AuditEventType = "password.changed"
	EventPasswordResetRequest AuditEventType = "password.reset.requested"
	EventPasswordReset        AuditEventType = "password.reset.completed"

	// Authorization events
	EventPermissionDenied  AuditEventType = "permission.denied"
	EventRoleAssigned      AuditEventType = "role.assigned"
	EventRoleRevoked       AuditEventType = "role.revoked"
	EventPermissionGranted AuditEventType = "permission.granted"
	EventPermissionRevoked AuditEventType = "permission.revoked"

	// 2FA events
	Event2FAEnabled      AuditEventType = "2fa.enabled"
	Event2FADisabled     AuditEventType = "2fa.disabled"
	Event2FASuccess      AuditEventType = "2fa.success"
	Event2FAFailed       AuditEventType = "2fa.failed"
	EventBackupCodeUsed  AuditEventType = "backup_code.used"
	EventBackupCodeRegen AuditEventType = "backup_code.regenerated"

	// Security events
	EventAccountLocked   AuditEventType = "account.locked"
	EventAccountUnlocked AuditEventType = "account.unlocked"
	EventBruteForce      AuditEventType = "brute_force.detected"
	EventRateLimited     AuditEventType = "rate_limit.exceeded"
	EventIPBlocked       AuditEventType = "ip.blocked"
	EventCSRFViolation   AuditEventType = "csrf.violation"
)

// AuditEvent represents a security event that occurred in the system
type AuditEvent struct {
	ID          string
	Type        AuditEventType
	UserID      string
	Username    string
	IP          string
	UserAgent   string
	GuardName   string
	Resource    string
	Action      string
	Result      string // "success", "failure", "denied"
	Reason      string
	Metadata    map[string]interface{}
	Timestamp   time.Time
	ContextData map[string]interface{}
}

// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	Log(ctx context.Context, event *AuditEvent) error
	Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)
}

// AuditFilter defines filters for querying audit events
type AuditFilter struct {
	UserID     string
	EventTypes []AuditEventType
	StartTime  *time.Time
	EndTime    *time.Time
	IP         string
	Result     string
	Limit      int
	Offset     int
}

// MemoryAuditLogger stores audit events in memory (for testing/development)
type MemoryAuditLogger struct {
	mu      sync.RWMutex
	events  []*AuditEvent
	maxSize int
}

// NewMemoryAuditLogger creates a new in-memory audit logger
func NewMemoryAuditLogger(maxSize int) *MemoryAuditLogger {
	if maxSize == 0 {
		maxSize = 10000
	}
	return &MemoryAuditLogger{
		events:  make([]*AuditEvent, 0),
		maxSize: maxSize,
	}
}

// Log records an audit event
func (l *MemoryAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.ID == "" {
		event.ID = generateID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	l.events = append(l.events, event)

	// Evict oldest events if max size exceeded
	if len(l.events) > l.maxSize {
		l.events = l.events[len(l.events)-l.maxSize:]
	}

	return nil
}

// Query retrieves audit events matching the filter
func (l *MemoryAuditLogger) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var results []*AuditEvent

	for _, event := range l.events {
		if l.matchesFilter(event, filter) {
			results = append(results, event)
		}
	}

	// Apply pagination
	if filter != nil && filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return []*AuditEvent{}, nil
		}
		results = results[filter.Offset:]
	}

	if filter != nil && filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results, nil
}

func (l *MemoryAuditLogger) matchesFilter(event *AuditEvent, filter *AuditFilter) bool {
	if filter == nil {
		return true
	}

	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}

	if filter.IP != "" && event.IP != filter.IP {
		return false
	}

	if filter.Result != "" && event.Result != filter.Result {
		return false
	}

	if len(filter.EventTypes) > 0 {
		found := false
		for _, t := range filter.EventTypes {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

// GetAll returns all events (for testing)
func (l *MemoryAuditLogger) GetAll() []*AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]*AuditEvent{}, l.events...)
}

// Clear removes all events (for testing)
func (l *MemoryAuditLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = make([]*AuditEvent, 0)
}

// NoOpAuditLogger is a no-op implementation that does nothing
type NoOpAuditLogger struct{}

func (l *NoOpAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	return nil
}

func (l *NoOpAuditLogger) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error) {
	return []*AuditEvent{}, nil
}

// MultiAuditLogger sends events to multiple loggers
type MultiAuditLogger struct {
	loggers []AuditLogger
}

// NewMultiAuditLogger creates a logger that sends to multiple destinations
func NewMultiAuditLogger(loggers ...AuditLogger) *MultiAuditLogger {
	return &MultiAuditLogger{loggers: loggers}
}

func (l *MultiAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	var firstError error
	for _, logger := range l.loggers {
		if err := logger.Log(ctx, event); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (l *MultiAuditLogger) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error) {
	if len(l.loggers) == 0 {
		return []*AuditEvent{}, nil
	}
	// Query from first logger only
	return l.loggers[0].Query(ctx, filter)
}

// AuditableGuard wraps a guard with audit logging
type AuditableGuard struct {
	Guard
	logger AuditLogger
}

// NewAuditableGuard wraps a guard with audit logging
func NewAuditableGuard(guard Guard, logger AuditLogger) *AuditableGuard {
	return &AuditableGuard{
		Guard:  guard,
		logger: logger,
	}
}

// Authenticate wraps guard Authenticate with audit logging
func (g *AuditableGuard) Authenticate(ctx context.Context, credentials interface{}) (User, error) {
	user, err := g.Guard.Authenticate(ctx, credentials)

	event := &AuditEvent{
		Type:      EventLoginSuccess,
		GuardName: g.Name(),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	if ip, ok := ctx.Value("ip").(string); ok {
		event.IP = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok {
		event.UserAgent = ua
	}

	if err != nil {
		event.Type = EventLoginFailed
		event.Result = "failure"
		event.Reason = err.Error()
		// Try to extract username from credentials
		if creds, ok := credentials.(map[string]interface{}); ok {
			if username, ok := creds["username"].(string); ok {
				event.Username = username
			}
		}
	} else {
		event.UserID = user.GetID()
		event.Username = user.GetAuthIdentifier()
		event.Result = "success"
	}

	_ = g.logger.Log(ctx, event)
	return user, err
}

// Logout wraps guard Logout with audit logging
func (g *AuditableGuard) Logout(ctx context.Context, user User) error {
	err := g.Guard.Logout(ctx, user)

	event := &AuditEvent{
		Type:      EventLogout,
		GuardName: g.Name(),
		Result:    "success",
		Timestamp: time.Now(),
	}

	if user != nil {
		event.UserID = user.GetID()
		event.Username = user.GetAuthIdentifier()
	}

	if ip, ok := ctx.Value("ip").(string); ok {
		event.IP = ip
	}

	_ = g.logger.Log(ctx, event)
	return err
}

// Helper function to generate a simple ID
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
