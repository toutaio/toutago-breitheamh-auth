package breitheamh

import (
	"context"
	"testing"
	"time"
)

func TestAPIToken(t *testing.T) {
	t.Run("IsExpired returns false for non-expiring token", func(t *testing.T) {
		token := &APIToken{
			ID:        "token-1",
			Token:     "test-token",
			ExpiresAt: nil,
		}

		if token.IsExpired() {
			t.Error("Token should not be expired")
		}
	})

	t.Run("IsExpired returns false for future expiry", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		token := &APIToken{
			ID:        "token-1",
			Token:     "test-token",
			ExpiresAt: &future,
		}

		if token.IsExpired() {
			t.Error("Token should not be expired")
		}
	})

	t.Run("IsExpired returns true for past expiry", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		token := &APIToken{
			ID:        "token-1",
			Token:     "test-token",
			ExpiresAt: &past,
		}

		if !token.IsExpired() {
			t.Error("Token should be expired")
		}
	})

	t.Run("CanPerform with wildcard", func(t *testing.T) {
		token := &APIToken{
			Abilities: []string{"*"},
		}

		if !token.CanPerform("posts.create") {
			t.Error("Token with * should be able to perform any action")
		}
	})

	t.Run("CanPerform with specific ability", func(t *testing.T) {
		token := &APIToken{
			Abilities: []string{"posts.create", "posts.read"},
		}

		if !token.CanPerform("posts.create") {
			t.Error("Token should be able to perform posts.create")
		}

		if token.CanPerform("posts.delete") {
			t.Error("Token should not be able to perform posts.delete")
		}
	})
}

func TestMemoryAPITokenStore(t *testing.T) {
	store := NewMemoryAPITokenStore()
	ctx := context.Background()

	token := &APIToken{
		ID:        "token-1",
		UserID:    "user-1",
		Token:     "test-token-123",
		Name:      "Test Token",
		Abilities: []string{"posts.create"},
		CreatedAt: time.Now(),
	}

	t.Run("Create and find token", func(t *testing.T) {
		err := store.Create(ctx, token)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		retrieved, err := store.FindByToken(ctx, "test-token-123")
		if err != nil {
			t.Fatalf("Failed to find token: %v", err)
		}

		if retrieved.ID != token.ID {
			t.Errorf("Token ID = %q, expected %q", retrieved.ID, token.ID)
		}
	})

	t.Run("Find non-existent token", func(t *testing.T) {
		_, err := store.FindByToken(ctx, "non-existent")
		if err != ErrInvalidAPIToken {
			t.Errorf("Expected ErrInvalidAPIToken, got %v", err)
		}
	})

	t.Run("Update token", func(t *testing.T) {
		token.Name = "Updated Token"
		err := store.Update(ctx, token)
		if err != nil {
			t.Fatalf("Failed to update token: %v", err)
		}

		retrieved, _ := store.FindByToken(ctx, "test-token-123")
		if retrieved.Name != "Updated Token" {
			t.Error("Token name not updated")
		}
	})

	t.Run("Find tokens by user ID", func(t *testing.T) {
		token2 := &APIToken{
			ID:     "token-2",
			UserID: "user-1",
			Token:  "test-token-456",
		}
		store.Create(ctx, token2)

		tokens, err := store.FindByUserID(ctx, "user-1")
		if err != nil {
			t.Fatalf("Failed to find tokens: %v", err)
		}

		if len(tokens) != 2 {
			t.Errorf("Expected 2 tokens, got %d", len(tokens))
		}
	})

	t.Run("Delete token by ID", func(t *testing.T) {
		err := store.Delete(ctx, "token-1")
		if err != nil {
			t.Fatalf("Failed to delete token: %v", err)
		}

		_, err = store.FindByToken(ctx, "test-token-123")
		if err != ErrInvalidAPIToken {
			t.Error("Token should be deleted")
		}
	})

	t.Run("Delete all tokens by user ID", func(t *testing.T) {
		err := store.DeleteByUserID(ctx, "user-1")
		if err != nil {
			t.Fatalf("Failed to delete tokens: %v", err)
		}

		tokens, _ := store.FindByUserID(ctx, "user-1")
		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(tokens))
		}
	})

	t.Run("Find expired token returns error", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		expiredToken := &APIToken{
			ID:        "expired",
			Token:     "expired-token",
			ExpiresAt: &past,
		}
		store.Create(ctx, expiredToken)

		_, err := store.FindByToken(ctx, "expired-token")
		if err != ErrInvalidAPIToken {
			t.Errorf("Expected ErrInvalidAPIToken for expired token, got %v", err)
		}
	})
}

func TestAPITokenGuard(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	provider := newMockUserProvider()
	provider.AddUser(user)

	store := NewMemoryAPITokenStore()
	guard := NewAPITokenGuard("api", provider, store)

	ctx := context.Background()

	t.Run("Create token", func(t *testing.T) {
		token, err := guard.CreateToken(ctx, user, "Test Token", []string{"posts.create"}, nil)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		if token.UserID != user.GetID() {
			t.Errorf("Token UserID = %q, expected %q", token.UserID, user.GetID())
		}

		if token.Token == "" {
			t.Error("Token value should not be empty")
		}

		if token.Name != "Test Token" {
			t.Errorf("Token name = %q, expected %q", token.Name, "Test Token")
		}
	})

	t.Run("Validate token", func(t *testing.T) {
		token, _ := guard.CreateToken(ctx, user, "Valid Token", []string{"*"}, nil)

		validatedUser, err := guard.Validate(ctx, token.Token)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		if validatedUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", validatedUser.GetID(), user.GetID())
		}
	})

	t.Run("Validate invalid token", func(t *testing.T) {
		_, err := guard.Validate(ctx, "invalid-token")
		if err != ErrInvalidAPIToken {
			t.Errorf("Expected ErrInvalidAPIToken, got %v", err)
		}
	})

	t.Run("Validate updates last used", func(t *testing.T) {
		token, _ := guard.CreateToken(ctx, user, "Track Usage", []string{"*"}, nil)

		if token.LastUsed != nil {
			t.Error("LastUsed should be nil initially")
		}

		guard.Validate(ctx, token.Token)

		retrieved, _ := store.FindByToken(ctx, token.Token)
		if retrieved.LastUsed == nil {
			t.Error("LastUsed should be set after validation")
		}
	})

	t.Run("Create token with expiry", func(t *testing.T) {
		expiry := time.Now().Add(1 * time.Hour)
		token, err := guard.CreateToken(ctx, user, "Expiring Token", []string{"posts.read"}, &expiry)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		if token.ExpiresAt == nil {
			t.Error("ExpiresAt should be set")
		}
	})

	t.Run("Revoke token", func(t *testing.T) {
		token, _ := guard.CreateToken(ctx, user, "Revoke Me", []string{"*"}, nil)

		err := guard.RevokeToken(ctx, token.ID)
		if err != nil {
			t.Fatalf("Failed to revoke token: %v", err)
		}

		_, err = guard.Validate(ctx, token.Token)
		if err != ErrInvalidAPIToken {
			t.Error("Token should be invalid after revocation")
		}
	})

	t.Run("Revoke all tokens", func(t *testing.T) {
		guard.CreateToken(ctx, user, "Token 1", []string{"*"}, nil)
		guard.CreateToken(ctx, user, "Token 2", []string{"*"}, nil)

		err := guard.RevokeAllTokens(ctx, user)
		if err != nil {
			t.Fatalf("Failed to revoke all tokens: %v", err)
		}

		tokens, _ := guard.GetUserTokens(ctx, user)
		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(tokens))
		}
	})

	t.Run("Get user tokens", func(t *testing.T) {
		guard.CreateToken(ctx, user, "Token A", []string{"posts.create"}, nil)
		guard.CreateToken(ctx, user, "Token B", []string{"posts.read"}, nil)

		tokens, err := guard.GetUserTokens(ctx, user)
		if err != nil {
			t.Fatalf("Failed to get user tokens: %v", err)
		}

		if len(tokens) != 2 {
			t.Errorf("Expected 2 tokens, got %d", len(tokens))
		}
	})

	t.Run("Validate with locked account", func(t *testing.T) {
		lockedUser := NewBaseUser("locked", "locked@example.com", "password")
		lockUntil := time.Now().Add(24 * time.Hour)
		lockedUser.LockedUntil = &lockUntil
		provider.AddUser(lockedUser)

		token, _ := guard.CreateToken(ctx, lockedUser, "Locked User Token", []string{"*"}, nil)

		_, err := guard.Validate(ctx, token.Token)
		if err != ErrAccountLocked {
			t.Errorf("Expected ErrAccountLocked, got %v", err)
		}
	})

	t.Run("Guard name", func(t *testing.T) {
		if guard.Name() != "api" {
			t.Errorf("Guard name = %q, expected %q", guard.Name(), "api")
		}
	})

	t.Run("Authenticate not supported", func(t *testing.T) {
		_, err := guard.Authenticate(ctx, Credentials{})
		if err == nil {
			t.Error("Authenticate should not be supported")
		}
	})
}
