package main

import (
	"context"
	"fmt"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
	fmt.Println("Session-Based Authentication Example")
	fmt.Println("=====================================")
	fmt.Println()

	// Create hasher and hash password
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	// Create users
	alice := breitheamh.NewBaseUser("user-1", "alice@example.com", hashedPassword)
	bob := breitheamh.NewBaseUser("user-2", "bob@example.com", hashedPassword)

	// Setup user provider
	provider := memory.NewProvider()
	provider.AddUser(alice)
	provider.AddUser(bob)

	// Create session store
	sessionStore := breitheamh.NewMemorySessionStore()

	// Configure sessions
	config := breitheamh.DefaultSessionConfig()
	config.SessionTTL = 30 * time.Minute
	fmt.Printf("Session TTL: %v\n", config.SessionTTL)
	fmt.Println()

	// Create session guard
	guard := breitheamh.NewSessionGuard("session", provider, sessionStore, hasher, config)

	ctx := context.Background()

	// Alice logs in
	fmt.Println("Alice logs in...")
	aliceUser, aliceSession, err := guard.Login(ctx, breitheamh.Credentials{
		Email:    "alice@example.com",
		Password: "secret123",
	})
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}

	fmt.Printf("  Session ID: %s...\n", aliceSession.ID[:20])
	fmt.Printf("  User: %s\n", aliceUser.GetAuthIdentifier())
	fmt.Printf("  Expires: %s\n", aliceSession.ExpiresAt.Format(time.RFC3339))
	fmt.Println()

	// Bob logs in
	fmt.Println("Bob logs in...")
	bobUser, bobSession, err := guard.Login(ctx, breitheamh.Credentials{
		Email:    "bob@example.com",
		Password: "secret123",
	})
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}

	fmt.Printf("  Session ID: %s...\n", bobSession.ID[:20])
	fmt.Printf("  User: %s\n", bobUser.GetAuthIdentifier())
	fmt.Println()

	// Validate Alice's session
	fmt.Println("Validating Alice's session...")
	validatedUser, err := guard.Validate(ctx, aliceSession.ID)
	if err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		return
	}
	fmt.Printf("  Valid! User: %s\n", validatedUser.GetAuthIdentifier())
	fmt.Println()

	// Try invalid session
	fmt.Println("Trying invalid session...")
	_, err = guard.Validate(ctx, "invalid-session-id")
	if err != nil {
		fmt.Printf("  Expected error: %v\n", err)
	}
	fmt.Println()

	// Session data storage
	fmt.Println("Storing data in session...")
	retrievedSession, _ := sessionStore.Get(ctx, aliceSession.ID)
	retrievedSession.Data["cart_items"] = 3
	retrievedSession.Data["last_page"] = "/products"
	sessionStore.Update(ctx, retrievedSession)
	fmt.Println("  Stored: cart_items=3, last_page=/products")
	fmt.Println()

	// Retrieve session data
	fmt.Println("Retrieving session data...")
	updatedSession, _ := sessionStore.Get(ctx, aliceSession.ID)
	fmt.Printf("  cart_items: %v\n", updatedSession.Data["cart_items"])
	fmt.Printf("  last_page: %v\n", updatedSession.Data["last_page"])
	fmt.Println()

	// Logout Alice
	fmt.Println("Alice logs out...")
	err = guard.Logout(ctx, aliceUser)
	if err != nil {
		fmt.Printf("Logout failed: %v\n", err)
		return
	}
	fmt.Println("  Logged out successfully")
	fmt.Println()

	// Try to validate Alice's session after logout
	fmt.Println("Trying to use Alice's session after logout...")
	_, err = guard.Validate(ctx, aliceSession.ID)
	if err != nil {
		fmt.Printf("  Expected error: %v\n", err)
	}
	fmt.Println()

	// Bob's session should still work
	fmt.Println("Bob's session should still work...")
	validatedBob, err := guard.Validate(ctx, bobSession.ID)
	if err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		return
	}
	fmt.Printf("  Valid! User: %s\n", validatedBob.GetAuthIdentifier())
	fmt.Println()

	// Demonstrate multi-guard setup
	fmt.Println("Multi-Guard Setup:")
	guardManager := breitheamh.NewGuardManager()

	// Create JWT guard
	jwtConfig := breitheamh.DefaultJWTConfig("secret-key-min-32-chars-long-here")
	tokenManager := breitheamh.NewJWTTokenManager(jwtConfig)
	jwtGuard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)

	// Register both guards
	guardManager.RegisterGuard("session", guard)
	guardManager.RegisterGuard("jwt", jwtGuard)

	fmt.Printf("  Registered guards: session, jwt\n")
	fmt.Printf("  Default guard: %s\n", guardManager.DefaultGuard().Name())
	fmt.Println()

	// Use specific guard
	sessionGuardFromManager := guardManager.Guard("session")
	fmt.Printf("  Using session guard: %s\n", sessionGuardFromManager.Name())
	fmt.Println()

	fmt.Println("Example completed successfully")
}
