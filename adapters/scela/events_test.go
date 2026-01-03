package scela

import (
	"context"
	"testing"
)

type mockBus struct {
	events []mockEvent
}

type mockEvent struct {
	topic   string
	payload interface{}
}

func (m *mockBus) Publish(ctx context.Context, topic string, payload interface{}) error {
	m.events = append(m.events, mockEvent{topic: topic, payload: payload})
	return nil
}

func TestEventPublisher(t *testing.T) {
	bus := &mockBus{}
	publisher := NewEventPublisher(bus)
	ctx := context.Background()

	t.Run("PublishLoginEvent", func(t *testing.T) {
		err := publisher.PublishLoginEvent(ctx, "user1", "web", map[string]interface{}{
			"ip": "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("Failed to publish login event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		if bus.events[0].topic != "auth.login" {
			t.Errorf("Expected topic auth.login, got %s", bus.events[0].topic)
		}

		event := bus.events[0].payload.(AuthEvent)
		if event.Type != "auth.login" {
			t.Errorf("Expected type auth.login, got %s", event.Type)
		}
		if event.UserID != "user1" {
			t.Errorf("Expected UserID user1, got %s", event.UserID)
		}
	})

	t.Run("PublishLogoutEvent", func(t *testing.T) {
		bus.events = []mockEvent{} // Reset
		err := publisher.PublishLogoutEvent(ctx, "user1", "web", nil)
		if err != nil {
			t.Fatalf("Failed to publish logout event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		if bus.events[0].topic != "auth.logout" {
			t.Errorf("Expected topic auth.logout, got %s", bus.events[0].topic)
		}
	})

	t.Run("PublishFailedLoginEvent", func(t *testing.T) {
		bus.events = []mockEvent{} // Reset
		err := publisher.PublishFailedLoginEvent(ctx, "user@example.com", "web", map[string]interface{}{
			"reason": "invalid_password",
		})
		if err != nil {
			t.Fatalf("Failed to publish failed login event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		if bus.events[0].topic != "auth.login.failed" {
			t.Errorf("Expected topic auth.login.failed, got %s", bus.events[0].topic)
		}
	})

	t.Run("PublishPasswordResetEvent", func(t *testing.T) {
		bus.events = []mockEvent{} // Reset
		err := publisher.PublishPasswordResetEvent(ctx, "user1", nil)
		if err != nil {
			t.Fatalf("Failed to publish password reset event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		if bus.events[0].topic != "auth.password.reset" {
			t.Errorf("Expected topic auth.password.reset, got %s", bus.events[0].topic)
		}
	})

	t.Run("PublishEmailVerifiedEvent", func(t *testing.T) {
		bus.events = []mockEvent{} // Reset
		err := publisher.PublishEmailVerifiedEvent(ctx, "user1", nil)
		if err != nil {
			t.Fatalf("Failed to publish email verified event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		if bus.events[0].topic != "auth.email.verified" {
			t.Errorf("Expected topic auth.email.verified, got %s", bus.events[0].topic)
		}
	})

	t.Run("PublishPermissionGrantedEvent", func(t *testing.T) {
		bus.events = []mockEvent{} // Reset
		err := publisher.PublishPermissionGrantedEvent(ctx, "user1", "posts.create", nil)
		if err != nil {
			t.Fatalf("Failed to publish permission granted event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		event := bus.events[0].payload.(AuthEvent)
		if event.Metadata["permission"] != "posts.create" {
			t.Errorf("Expected permission posts.create in metadata")
		}
	})

	t.Run("PublishRoleAssignedEvent", func(t *testing.T) {
		bus.events = []mockEvent{} // Reset
		err := publisher.PublishRoleAssignedEvent(ctx, "user1", "admin", nil)
		if err != nil {
			t.Fatalf("Failed to publish role assigned event: %v", err)
		}

		if len(bus.events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(bus.events))
		}

		event := bus.events[0].payload.(AuthEvent)
		if event.Metadata["role"] != "admin" {
			t.Errorf("Expected role admin in metadata")
		}
	})
}
