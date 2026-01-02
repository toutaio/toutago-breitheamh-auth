package breitheamh

import (
	"context"
	"testing"
	"time"
)

// mockUserProvider is a simple mock for testing the guard.
type mockUserProvider struct {
	users map[string]User
}

func newMockUserProvider() *mockUserProvider {
	return &mockUserProvider{
		users: make(map[string]User),
	}
}

func (m *mockUserProvider) AddUser(user User) {
	m.users[user.GetID()] = user
}

func (m *mockUserProvider) FindByID(ctx context.Context, id string) (User, error) {
	user, exists := m.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *mockUserProvider) FindByCredentials(ctx context.Context, credentials map[string]interface{}) (User, error) {
	email, ok := credentials["email"].(string)
	if !ok {
		return nil, ErrUserNotFound
	}

	for _, user := range m.users {
		if user.GetAuthIdentifier() == email {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

func (m *mockUserProvider) UpdateUser(ctx context.Context, user User) error {
	m.users[user.GetID()] = user
	return nil
}

func TestJWTGuard(t *testing.T) {
	// Setup
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)

	provider := newMockUserProvider()
	provider.AddUser(user)

	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)

	guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	ctx := context.Background()

	t.Run("Authenticate with valid credentials", func(t *testing.T) {
		creds := Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		}

		authUser, err := guard.Authenticate(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to authenticate: %v", err)
		}

		if authUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", authUser.GetID(), user.GetID())
		}
	})

	t.Run("Authenticate with invalid password", func(t *testing.T) {
		creds := Credentials{
			Email:    "test@example.com",
			Password: "wrongpassword",
		}

		_, err := guard.Authenticate(ctx, creds)
		if err != ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("Authenticate with non-existent user", func(t *testing.T) {
		creds := Credentials{
			Email:    "nonexistent@example.com",
			Password: "secret123",
		}

		_, err := guard.Authenticate(ctx, creds)
		if err != ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("Authenticate with map credentials", func(t *testing.T) {
		creds := map[string]interface{}{
			"email":    "test@example.com",
			"password": "secret123",
		}

		authUser, err := guard.Authenticate(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to authenticate: %v", err)
		}

		if authUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", authUser.GetID(), user.GetID())
		}
	})

	t.Run("Attempt authentication and get token", func(t *testing.T) {
		creds := Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		}

		authUser, token, err := guard.Attempt(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to attempt: %v", err)
		}

		if authUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", authUser.GetID(), user.GetID())
		}

		if token.AccessToken == "" {
			t.Error("Access token should not be empty")
		}

		if token.RefreshToken == "" {
			t.Error("Refresh token should not be empty")
		}
	})

	t.Run("Validate token", func(t *testing.T) {
		creds := Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		}

		_, token, err := guard.Attempt(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to attempt: %v", err)
		}

		validatedUser, err := guard.Validate(ctx, token.AccessToken)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		if validatedUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", validatedUser.GetID(), user.GetID())
		}
	})

	t.Run("Validate invalid token", func(t *testing.T) {
		_, err := guard.Validate(ctx, "invalid.token.here")
		if err == nil {
			t.Error("Expected error for invalid token")
		}
	})

	t.Run("Guard name", func(t *testing.T) {
		if guard.Name() != "jwt" {
			t.Errorf("Guard name = %q, expected %q", guard.Name(), "jwt")
		}
	})

	t.Run("Authenticate locked account", func(t *testing.T) {
		// Create a locked user
		lockedUser := NewBaseUser("locked-user", "locked@example.com", hashedPassword)
		lockedUntil := lockedUser.CreatedAt.Add(24 * 365 * 100 * time.Hour) // Lock for 100 years
		lockedUser.LockedUntil = &lockedUntil
		provider.AddUser(lockedUser)

		creds := Credentials{
			Email:    "locked@example.com",
			Password: "secret123",
		}

		_, err := guard.Authenticate(ctx, creds)
		if err != ErrAccountLocked {
			t.Errorf("Expected ErrAccountLocked, got %v", err)
		}
	})
}

func TestGuardManager(t *testing.T) {
	manager := NewGuardManager()

	hasher := NewHasher(AlgorithmBcrypt)
	provider := newMockUserProvider()
	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)

	jwtGuard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	t.Run("Register guard", func(t *testing.T) {
		manager.RegisterGuard("jwt", jwtGuard)

		guard := manager.Guard("jwt")
		if guard.Name() != "jwt" {
			t.Errorf("Guard name = %q, expected %q", guard.Name(), "jwt")
		}
	})

	t.Run("Default guard", func(t *testing.T) {
		defaultGuard := manager.DefaultGuard()
		if defaultGuard.Name() != "jwt" {
			t.Errorf("Default guard name = %q, expected %q", defaultGuard.Name(), "jwt")
		}
	})

	t.Run("Set default guard", func(t *testing.T) {
		apiGuard := NewJWTGuard("api", provider, tokenManager, hasher)
		manager.RegisterGuard("api", apiGuard)
		manager.SetDefaultGuard("api")

		defaultGuard := manager.DefaultGuard()
		if defaultGuard.Name() != "api" {
			t.Errorf("Default guard name = %q, expected %q", defaultGuard.Name(), "api")
		}
	})
}
