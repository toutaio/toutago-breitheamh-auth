package breitheamh

import (
	"context"
	"testing"
	"time"
)

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()

	session := &Session{
		ID:        "session-1",
		UserID:    "user-1",
		Data:      make(map[string]interface{}),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		LastSeen:  time.Now(),
	}

	t.Run("Create and get session", func(t *testing.T) {
		err := store.Create(ctx, session)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		retrieved, err := store.Get(ctx, "session-1")
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}

		if retrieved.ID != session.ID {
			t.Errorf("Session ID = %q, expected %q", retrieved.ID, session.ID)
		}
	})

	t.Run("Get non-existent session", func(t *testing.T) {
		_, err := store.Get(ctx, "non-existent")
		if err != ErrSessionNotFound {
			t.Errorf("Expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("Update session", func(t *testing.T) {
		session.Data["key"] = "value"
		err := store.Update(ctx, session)
		if err != nil {
			t.Fatalf("Failed to update session: %v", err)
		}

		retrieved, _ := store.Get(ctx, "session-1")
		if retrieved.Data["key"] != "value" {
			t.Error("Session data not updated")
		}
	})

	t.Run("Delete session", func(t *testing.T) {
		err := store.Delete(ctx, "session-1")
		if err != nil {
			t.Fatalf("Failed to delete session: %v", err)
		}

		_, err = store.Get(ctx, "session-1")
		if err != ErrSessionNotFound {
			t.Errorf("Expected ErrSessionNotFound after deletion, got %v", err)
		}
	})

	t.Run("Delete by user ID", func(t *testing.T) {
		session1 := &Session{ID: "s1", UserID: "user-1", ExpiresAt: time.Now().Add(1 * time.Hour)}
		session2 := &Session{ID: "s2", UserID: "user-1", ExpiresAt: time.Now().Add(1 * time.Hour)}
		session3 := &Session{ID: "s3", UserID: "user-2", ExpiresAt: time.Now().Add(1 * time.Hour)}

		store.Create(ctx, session1)
		store.Create(ctx, session2)
		store.Create(ctx, session3)

		err := store.DeleteByUserID(ctx, "user-1")
		if err != nil {
			t.Fatalf("Failed to delete sessions: %v", err)
		}

		_, err = store.Get(ctx, "s1")
		if err != ErrSessionNotFound {
			t.Error("Session s1 should be deleted")
		}

		_, err = store.Get(ctx, "s3")
		if err != nil {
			t.Error("Session s3 should still exist")
		}
	})

	t.Run("Cleanup expired sessions", func(t *testing.T) {
		expiredSession := &Session{
			ID:        "expired",
			UserID:    "user-1",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		validSession := &Session{
			ID:        "valid",
			UserID:    "user-1",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		store.Create(ctx, expiredSession)
		store.Create(ctx, validSession)

		err := store.Cleanup(ctx)
		if err != nil {
			t.Fatalf("Failed to cleanup: %v", err)
		}

		_, err = store.Get(ctx, "expired")
		if err != ErrSessionNotFound {
			t.Error("Expired session should be removed")
		}

		_, err = store.Get(ctx, "valid")
		if err != nil {
			t.Error("Valid session should still exist")
		}
	})
}

func TestSessionExpiration(t *testing.T) {
	session := &Session{
		ID:        "session-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	if !session.IsExpired() {
		t.Error("Session should be expired")
	}

	session.ExpiresAt = time.Now().Add(1 * time.Hour)
	if session.IsExpired() {
		t.Error("Session should not be expired")
	}
}

func TestSessionGuard(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)

	provider := newMockUserProvider()
	provider.AddUser(user)

	store := NewMemorySessionStore()
	config := DefaultSessionConfig()

	guard := NewSessionGuard("session", provider, store, hasher, config)

	ctx := context.Background()

	t.Run("Login creates session", func(t *testing.T) {
		authUser, session, err := guard.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		if authUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", authUser.GetID(), user.GetID())
		}

		if session.ID == "" {
			t.Error("Session ID should not be empty")
		}

		if session.UserID != user.GetID() {
			t.Errorf("Session UserID = %q, expected %q", session.UserID, user.GetID())
		}
	})

	t.Run("Validate session", func(t *testing.T) {
		_, session, _ := guard.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		validatedUser, err := guard.Validate(ctx, session.ID)
		if err != nil {
			t.Fatalf("Failed to validate session: %v", err)
		}

		if validatedUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", validatedUser.GetID(), user.GetID())
		}
	})

	t.Run("Validate invalid session", func(t *testing.T) {
		_, err := guard.Validate(ctx, "invalid-session")
		if err != ErrSessionNotFound {
			t.Errorf("Expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("Logout deletes sessions", func(t *testing.T) {
		_, session, _ := guard.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		err := guard.Logout(ctx, user)
		if err != nil {
			t.Fatalf("Logout failed: %v", err)
		}

		_, err = guard.Validate(ctx, session.ID)
		if err != ErrSessionNotFound {
			t.Error("Session should be deleted after logout")
		}
	})

	t.Run("Login with invalid credentials", func(t *testing.T) {
		_, _, err := guard.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "wrongpassword",
		})

		if err != ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("Login with locked account", func(t *testing.T) {
		lockedUser := NewBaseUser("locked", "locked@example.com", hashedPassword)
		lockUntil := time.Now().Add(24 * time.Hour)
		lockedUser.LockedUntil = &lockUntil
		provider.AddUser(lockedUser)

		_, _, err := guard.Login(ctx, Credentials{
			Email:    "locked@example.com",
			Password: "secret123",
		})

		if err != ErrAccountLocked {
			t.Errorf("Expected ErrAccountLocked, got %v", err)
		}
	})

	t.Run("Guard name", func(t *testing.T) {
		if guard.Name() != "session" {
			t.Errorf("Guard name = %q, expected %q", guard.Name(), "session")
		}
	})
}

func TestSessionConfig(t *testing.T) {
	config := DefaultSessionConfig()

	if config.SessionTTL != 24*time.Hour {
		t.Errorf("SessionTTL = %v, expected %v", config.SessionTTL, 24*time.Hour)
	}

	if config.CookieName != "session_id" {
		t.Errorf("CookieName = %q, expected %q", config.CookieName, "session_id")
	}
}
