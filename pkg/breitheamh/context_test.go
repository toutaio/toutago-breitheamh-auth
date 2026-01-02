package breitheamh

import (
	"context"
	"testing"
)

func TestAuthContext(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)

	provider := newMockUserProvider()
	provider.AddUser(user)

	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)
	guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	authCtx := NewAuthContext(guard)
	ctx := context.Background()

	t.Run("Login stores user in context", func(t *testing.T) {
		newCtx, loginUser, err := authCtx.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		if loginUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", loginUser.GetID(), user.GetID())
		}

		retrievedUser := GetUser(newCtx)
		if retrievedUser == nil {
			t.Error("User should be stored in context")
		}
	})

	t.Run("User retrieves from context", func(t *testing.T) {
		newCtx, _, _ := authCtx.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		retrievedUser, err := authCtx.User(newCtx)
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if retrievedUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", retrievedUser.GetID(), user.GetID())
		}
	})

	t.Run("User returns error when not authenticated", func(t *testing.T) {
		_, err := authCtx.User(ctx)
		if err != ErrNoAuthenticatedUser {
			t.Errorf("Expected ErrNoAuthenticatedUser, got %v", err)
		}
	})

	t.Run("Check returns true when authenticated", func(t *testing.T) {
		newCtx, _, _ := authCtx.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if !authCtx.Check(newCtx) {
			t.Error("Check should return true for authenticated context")
		}
	})

	t.Run("Check returns false when not authenticated", func(t *testing.T) {
		if authCtx.Check(ctx) {
			t.Error("Check should return false for unauthenticated context")
		}
	})

	t.Run("Guest returns true when not authenticated", func(t *testing.T) {
		if !authCtx.Guest(ctx) {
			t.Error("Guest should return true for unauthenticated context")
		}
	})

	t.Run("Guest returns false when authenticated", func(t *testing.T) {
		newCtx, _, _ := authCtx.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if authCtx.Guest(newCtx) {
			t.Error("Guest should return false for authenticated context")
		}
	})

	t.Run("ID returns user ID", func(t *testing.T) {
		newCtx, _, _ := authCtx.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		id, err := authCtx.ID(newCtx)
		if err != nil {
			t.Fatalf("Failed to get ID: %v", err)
		}

		if id != user.GetID() {
			t.Errorf("ID = %q, expected %q", id, user.GetID())
		}
	})

	t.Run("ID returns error when not authenticated", func(t *testing.T) {
		_, err := authCtx.ID(ctx)
		if err != ErrNoAuthenticatedUser {
			t.Errorf("Expected ErrNoAuthenticatedUser, got %v", err)
		}
	})

	t.Run("Attempt authenticates without storing", func(t *testing.T) {
		attemptUser, err := authCtx.Attempt(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if err != nil {
			t.Fatalf("Attempt failed: %v", err)
		}

		if attemptUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", attemptUser.GetID(), user.GetID())
		}

		if authCtx.Check(ctx) {
			t.Error("Attempt should not store user in context")
		}
	})

	t.Run("LoginUsingID authenticates by ID", func(t *testing.T) {
		newCtx, loginUser, err := authCtx.LoginUsingID(ctx, provider, "user-1")

		if err != nil {
			t.Fatalf("LoginUsingID failed: %v", err)
		}

		if loginUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", loginUser.GetID(), user.GetID())
		}

		if !authCtx.Check(newCtx) {
			t.Error("User should be in context after LoginUsingID")
		}
	})

	t.Run("Once authenticates for single request", func(t *testing.T) {
		newCtx, onceUser, err := authCtx.Once(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if err != nil {
			t.Fatalf("Once failed: %v", err)
		}

		if onceUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", onceUser.GetID(), user.GetID())
		}

		if !authCtx.Check(newCtx) {
			t.Error("User should be in context after Once")
		}
	})

	t.Run("SetUser manually sets user", func(t *testing.T) {
		newCtx := authCtx.SetUser(ctx, user)

		if !authCtx.Check(newCtx) {
			t.Error("User should be in context after SetUser")
		}

		retrievedUser, _ := authCtx.User(newCtx)
		if retrievedUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", retrievedUser.GetID(), user.GetID())
		}
	})

	t.Run("Logout removes user from context", func(t *testing.T) {
		newCtx, _, _ := authCtx.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		loggedOutCtx := authCtx.Logout(newCtx)

		if authCtx.Check(loggedOutCtx) {
			t.Error("User should not be in context after Logout")
		}
	})
}

func TestAuthManager(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)

	provider := newMockUserProvider()
	provider.AddUser(user)

	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)
	jwtGuard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	sessionStore := NewMemorySessionStore()
	sessionGuard := NewSessionGuard("session", provider, sessionStore, hasher, nil)

	manager := NewAuthManager()
	ctx := context.Background()

	t.Run("RegisterGuard and Guard retrieval", func(t *testing.T) {
		manager.RegisterGuard("jwt", jwtGuard)
		manager.RegisterGuard("session", sessionGuard)

		retrievedGuard := manager.Guard("jwt")
		if retrievedGuard == nil {
			t.Error("Guard should be registered")
		}

		if retrievedGuard.Name() != "jwt" {
			t.Errorf("Guard name = %q, expected %q", retrievedGuard.Name(), "jwt")
		}
	})

	t.Run("First registered guard becomes default", func(t *testing.T) {
		newManager := NewAuthManager()
		newManager.RegisterGuard("jwt", jwtGuard)

		defaultGuard := newManager.DefaultGuard()
		if defaultGuard == nil {
			t.Error("Default guard should be set")
		}

		if defaultGuard.Name() != "jwt" {
			t.Errorf("Default guard = %q, expected %q", defaultGuard.Name(), "jwt")
		}
	})

	t.Run("SetDefaultGuard changes default", func(t *testing.T) {
		manager.SetDefaultGuard("session")

		defaultGuard := manager.DefaultGuard()
		if defaultGuard.Name() != "session" {
			t.Errorf("Default guard = %q, expected %q", defaultGuard.Name(), "session")
		}

		// Set it back for other tests
		manager.SetDefaultGuard("jwt")
	})

	t.Run("Login with default guard", func(t *testing.T) {
		newCtx, loginUser, err := manager.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		if loginUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", loginUser.GetID(), user.GetID())
		}

		if !manager.Check(newCtx) {
			t.Error("User should be authenticated")
		}
	})

	t.Run("Attempt with default guard", func(t *testing.T) {
		attemptUser, err := manager.Attempt(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if err != nil {
			t.Fatalf("Attempt failed: %v", err)
		}

		if attemptUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", attemptUser.GetID(), user.GetID())
		}
	})

	t.Run("User retrieves authenticated user", func(t *testing.T) {
		newCtx, _, _ := manager.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		retrievedUser, err := manager.User(newCtx)
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if retrievedUser.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", retrievedUser.GetID(), user.GetID())
		}
	})

	t.Run("Check returns authentication status", func(t *testing.T) {
		if manager.Check(ctx) {
			t.Error("Check should return false for unauthenticated")
		}

		newCtx, _, _ := manager.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if !manager.Check(newCtx) {
			t.Error("Check should return true for authenticated")
		}
	})

	t.Run("Guest returns opposite of Check", func(t *testing.T) {
		if !manager.Guest(ctx) {
			t.Error("Guest should return true for unauthenticated")
		}

		newCtx, _, _ := manager.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		if manager.Guest(newCtx) {
			t.Error("Guest should return false for authenticated")
		}
	})

	t.Run("SetUser manually sets user", func(t *testing.T) {
		newCtx := manager.SetUser(ctx, user)

		if !manager.Check(newCtx) {
			t.Error("User should be authenticated after SetUser")
		}
	})

	t.Run("Logout removes user", func(t *testing.T) {
		newCtx, _, _ := manager.Login(ctx, Credentials{
			Email:    "test@example.com",
			Password: "secret123",
		})

		loggedOutCtx := manager.Logout(newCtx)

		if manager.Check(loggedOutCtx) {
			t.Error("User should not be authenticated after Logout")
		}
	})
}
