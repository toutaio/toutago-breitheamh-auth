package main

import (
	"context"
	"fmt"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
	fmt.Println("API Token Authentication Example")
	fmt.Println("=================================")
	fmt.Println()

	// Setup
	provider := memory.NewProvider()
	tokenStore := breitheamh.NewMemoryAPITokenStore()
	guard := breitheamh.NewAPITokenGuard("api", provider, tokenStore)

	ctx := context.Background()

	// Create users
	alice := breitheamh.NewBaseUser("user-1", "alice@example.com", "password")
	bob := breitheamh.NewBaseUser("user-2", "bob@example.com", "password")

	provider.AddUser(alice)
	provider.AddUser(bob)

	// Example 1: Create API token with full access
	fmt.Println("1. Creating API token with full access (*) for Alice...")
	aliceToken, err := guard.CreateToken(ctx, alice, "Alice's Full Access Token", []string{"*"}, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Token created: %s\n", aliceToken.Token[:40]+"...")
	fmt.Printf("   Abilities: %v\n", aliceToken.Abilities)
	fmt.Println()

	// Example 2: Create API token with limited abilities
	fmt.Println("2. Creating API token with limited abilities for Bob...")
	bobToken, err := guard.CreateToken(ctx, bob, "Bob's Read-Only Token", []string{"posts.read", "comments.read"}, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Token created: %s\n", bobToken.Token[:40]+"...")
	fmt.Printf("   Abilities: %v\n", bobToken.Abilities)
	fmt.Println()

	// Example 3: Create expiring token
	fmt.Println("3. Creating expiring token for Alice...")
	expiresAt := time.Now().Add(24 * time.Hour)
	expiringToken, err := guard.CreateToken(ctx, alice, "24-Hour Token", []string{"posts.create"}, &expiresAt)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Token created: %s\n", expiringToken.Token[:40]+"...")
	fmt.Printf("   Expires at: %s\n", expiringToken.ExpiresAt.Format(time.RFC3339))
	fmt.Println()

	// Example 4: Validate token
	fmt.Println("4. Validating Alice's token...")
	validatedUser, err := guard.Validate(ctx, aliceToken.Token)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Valid! User: %s\n", validatedUser.GetAuthIdentifier())
	fmt.Println()

	// Example 5: Check token abilities
	fmt.Println("5. Checking token abilities...")
	fmt.Printf("   Alice's token can perform 'posts.create': %v\n", aliceToken.CanPerform("posts.create"))
	fmt.Printf("   Alice's token can perform 'anything': %v\n", aliceToken.CanPerform("anything"))
	fmt.Printf("   Bob's token can perform 'posts.read': %v\n", bobToken.CanPerform("posts.read"))
	fmt.Printf("   Bob's token can perform 'posts.create': %v\n", bobToken.CanPerform("posts.create"))
	fmt.Println()

	// Example 6: Track last used
	fmt.Println("6. Tracking token usage...")
	fmt.Printf("   Bob's token last used before validation: %v\n", bobToken.LastUsed)
	guard.Validate(ctx, bobToken.Token)
	// Retrieve updated token
	updatedBobToken, _ := tokenStore.FindByToken(ctx, bobToken.Token)
	fmt.Printf("   Bob's token last used after validation: %s\n", updatedBobToken.LastUsed.Format(time.RFC3339))
	fmt.Println()

	// Example 7: List user's tokens
	fmt.Println("7. Listing Alice's tokens...")
	aliceTokens, err := guard.GetUserTokens(ctx, alice)
	if err != nil {
		panic(err)
	}
	fmt.Printf("   Alice has %d token(s):\n", len(aliceTokens))
	for i, token := range aliceTokens {
		fmt.Printf("   %d. %s - Abilities: %v\n", i+1, token.Name, token.Abilities)
	}
	fmt.Println()

	// Example 8: Revoke specific token
	fmt.Println("8. Revoking Alice's expiring token...")
	err = guard.RevokeToken(ctx, expiringToken.ID)
	if err != nil {
		panic(err)
	}
	fmt.Println("   Token revoked successfully")

	// Try to use revoked token
	_, err = guard.Validate(ctx, expiringToken.Token)
	if err != nil {
		fmt.Printf("   Expected error when using revoked token: %v\n", err)
	}
	fmt.Println()

	// Example 9: Revoke all user tokens
	fmt.Println("9. Creating multiple tokens for Bob...")
	guard.CreateToken(ctx, bob, "Token 1", []string{"posts.create"}, nil)
	guard.CreateToken(ctx, bob, "Token 2", []string{"comments.create"}, nil)
	guard.CreateToken(ctx, bob, "Token 3", []string{"users.read"}, nil)

	bobTokens, _ := guard.GetUserTokens(ctx, bob)
	fmt.Printf("   Bob now has %d tokens\n", len(bobTokens))

	fmt.Println("   Revoking all Bob's tokens...")
	guard.RevokeAllTokens(ctx, bob)

	bobTokensAfter, _ := guard.GetUserTokens(ctx, bob)
	fmt.Printf("   Bob now has %d tokens\n", len(bobTokensAfter))
	fmt.Println()

	// Example 10: Use with AuthManager
	fmt.Println("10. Using API token guard with AuthManager...")
	manager := breitheamh.NewAuthManager()
	manager.RegisterGuard("api", guard)

	// Create new token
	newToken, _ := guard.CreateToken(ctx, alice, "Manager Test Token", []string{"*"}, nil)

	// Validate using token (manually add to context)
	validUser, _ := guard.Validate(ctx, newToken.Token)
	ctx = manager.SetUser(ctx, validUser)

	if manager.Check(ctx) {
		user, _ := manager.User(ctx)
		fmt.Printf("   User authenticated via manager: %s\n", user.GetAuthIdentifier())
	}
	fmt.Println()

	// Example 11: Token expiration
	fmt.Println("11. Testing token expiration...")
	pastTime := time.Now().Add(-1 * time.Hour)
	expiredToken, _ := guard.CreateToken(ctx, alice, "Expired Token", []string{"*"}, &pastTime)

	fmt.Printf("   Token expired: %v\n", expiredToken.IsExpired())

	_, err = guard.Validate(ctx, expiredToken.Token)
	if err != nil {
		fmt.Printf("   Expected error for expired token: %v\n", err)
	}
	fmt.Println()

	// Example 12: Practical use case - API client
	fmt.Println("12. Practical Use Case: Third-Party API Client")
	fmt.Println("    Creating token for external service...")

	externalServiceToken, _ := guard.CreateToken(
		ctx,
		alice,
		"External Analytics Service",
		[]string{"analytics.read", "analytics.write"},
		nil,
	)

	fmt.Printf("    Token: %s...\n", externalServiceToken.Token[:40])
	fmt.Printf("    Use this token in HTTP requests:\n")
	fmt.Printf("    Authorization: Bearer %s\n", externalServiceToken.Token)
	fmt.Println()

	fmt.Println("Example completed successfully!")
	fmt.Println()
	fmt.Println("Key Takeaways:")
	fmt.Println("- API tokens are perfect for third-party integrations")
	fmt.Println("- Abilities control what each token can do")
	fmt.Println("- Tokens can be scoped and time-limited")
	fmt.Println("- Easy to track usage and revoke access")
	fmt.Println("- Works seamlessly with HTTP middleware")
}
