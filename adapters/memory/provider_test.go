package memory

import (
	"context"
	"testing"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func TestMemoryProvider(t *testing.T) {
	provider := NewProvider()
	ctx := context.Background()

	user1 := breitheamh.NewBaseUser("user-1", "user1@example.com", "password1")
	user2 := breitheamh.NewBaseUser("user-2", "user2@example.com", "password2")

	t.Run("Add and find by ID", func(t *testing.T) {
		provider.AddUser(user1)

		found, err := provider.FindByID(ctx, "user-1")
		if err != nil {
			t.Fatalf("Failed to find user: %v", err)
		}

		if found.GetID() != user1.GetID() {
			t.Errorf("Found user ID = %q, expected %q", found.GetID(), user1.GetID())
		}
	})

	t.Run("Find by credentials", func(t *testing.T) {
		provider.AddUser(user2)

		found, err := provider.FindByCredentials(ctx, map[string]interface{}{
			"email": "user2@example.com",
		})
		if err != nil {
			t.Fatalf("Failed to find user: %v", err)
		}

		if found.GetID() != user2.GetID() {
			t.Errorf("Found user ID = %q, expected %q", found.GetID(), user2.GetID())
		}
	})

	t.Run("Find non-existent user", func(t *testing.T) {
		_, err := provider.FindByID(ctx, "non-existent")
		if err != breitheamh.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("Update user", func(t *testing.T) {
		user1.Email = "updated@example.com"

		err := provider.UpdateUser(ctx, user1)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		found, err := provider.FindByID(ctx, user1.GetID())
		if err != nil {
			t.Fatalf("Failed to find user: %v", err)
		}

		baseUser := found.(*breitheamh.BaseUser)
		if baseUser.Email != "updated@example.com" {
			t.Errorf("Email = %q, expected %q", baseUser.Email, "updated@example.com")
		}
	})

	t.Run("Remove user", func(t *testing.T) {
		provider.RemoveUser(user1.GetID())

		_, err := provider.FindByID(ctx, user1.GetID())
		if err != breitheamh.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound after removal, got %v", err)
		}
	})

	t.Run("Count users", func(t *testing.T) {
		provider.Clear()
		if provider.Count() != 0 {
			t.Errorf("Count = %d, expected 0 after clear", provider.Count())
		}

		provider.AddUser(user1)
		provider.AddUser(user2)

		if provider.Count() != 2 {
			t.Errorf("Count = %d, expected 2", provider.Count())
		}
	})

	t.Run("Clear users", func(t *testing.T) {
		provider.Clear()

		if provider.Count() != 0 {
			t.Errorf("Count = %d, expected 0 after clear", provider.Count())
		}
	})
}

func TestMemoryProviderConcurrency(t *testing.T) {
	provider := NewProvider()
	ctx := context.Background()

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id string) {
			user := breitheamh.NewBaseUser(id, id+"@example.com", "password")
			provider.AddUser(user)
			done <- true
		}(string(rune('a' + i)))
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if provider.Count() != 10 {
		t.Errorf("Count = %d, expected 10 after concurrent writes", provider.Count())
	}

	// Test concurrent reads
	for i := 0; i < 10; i++ {
		go func(id string) {
			_, _ = provider.FindByID(ctx, id)
			done <- true
		}(string(rune('a' + i)))
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
