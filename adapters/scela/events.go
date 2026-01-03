package scela

import (
	"context"
	"encoding/json"
	"time"
)

// Bus represents the Scéla event bus interface
type Bus interface {
	Publish(ctx context.Context, topic string, payload interface{}) error
}

// EventPublisher publishes authentication events to Scéla
type EventPublisher struct {
	bus Bus
}

// NewEventPublisher creates a new event publisher
func NewEventPublisher(bus Bus) *EventPublisher {
	return &EventPublisher{
		bus: bus,
	}
}

// AuthEvent represents an authentication event
type AuthEvent struct {
	Type      string                 `json:"type"`
	UserID    string                 `json:"user_id"`
	Guard     string                 `json:"guard"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// PublishLoginEvent publishes a user login event
func (p *EventPublisher) PublishLoginEvent(ctx context.Context, userID, guard string, metadata map[string]interface{}) error {
	event := AuthEvent{
		Type:      "auth.login",
		UserID:    userID,
		Guard:     guard,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.login", event)
}

// PublishLogoutEvent publishes a user logout event
func (p *EventPublisher) PublishLogoutEvent(ctx context.Context, userID, guard string, metadata map[string]interface{}) error {
	event := AuthEvent{
		Type:      "auth.logout",
		UserID:    userID,
		Guard:     guard,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.logout", event)
}

// PublishFailedLoginEvent publishes a failed login attempt event
func (p *EventPublisher) PublishFailedLoginEvent(ctx context.Context, identifier, guard string, metadata map[string]interface{}) error {
	event := AuthEvent{
		Type:      "auth.login.failed",
		UserID:    identifier,
		Guard:     guard,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.login.failed", event)
}

// PublishPasswordResetEvent publishes a password reset event
func (p *EventPublisher) PublishPasswordResetEvent(ctx context.Context, userID string, metadata map[string]interface{}) error {
	event := AuthEvent{
		Type:      "auth.password.reset",
		UserID:    userID,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.password.reset", event)
}

// PublishEmailVerifiedEvent publishes an email verified event
func (p *EventPublisher) PublishEmailVerifiedEvent(ctx context.Context, userID string, metadata map[string]interface{}) error {
	event := AuthEvent{
		Type:      "auth.email.verified",
		UserID:    userID,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.email.verified", event)
}

// PublishPermissionGrantedEvent publishes a permission granted event
func (p *EventPublisher) PublishPermissionGrantedEvent(ctx context.Context, userID, permission string, metadata map[string]interface{}) error {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["permission"] = permission

	event := AuthEvent{
		Type:      "auth.permission.granted",
		UserID:    userID,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.permission.granted", event)
}

// PublishRoleAssignedEvent publishes a role assigned event
func (p *EventPublisher) PublishRoleAssignedEvent(ctx context.Context, userID, role string, metadata map[string]interface{}) error {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["role"] = role

	event := AuthEvent{
		Type:      "auth.role.assigned",
		UserID:    userID,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	return p.bus.Publish(ctx, "auth.role.assigned", event)
}

// MarshalJSON implements json.Marshaler for AuthEvent
func (e AuthEvent) MarshalJSON() ([]byte, error) {
	type Alias AuthEvent
	return json.Marshal(struct {
		Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias:     (Alias)(e),
		Timestamp: e.Timestamp.Format(time.RFC3339),
	})
}
