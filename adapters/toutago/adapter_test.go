package toutago

import (
	"context"
	"testing"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func TestAdapter(t *testing.T) {
	// Setup
	provider := memory.NewProvider()
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret")

	user := breitheamh.NewBaseUser("1", "test@example.com", hashedPassword)
	provider.AddUser(user)

	guardManager := breitheamh.NewGuardManager()
	tokenManager := breitheamh.NewJWTTokenManager(breitheamh.DefaultJWTConfig("testsecret"))
	jwtGuard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)
	guardManager.RegisterGuard("jwt", jwtGuard)

	adapter := NewAdapter(guardManager)
	ctx := context.Background()

	t.Run("GuardManager", func(t *testing.T) {
		if adapter.GuardManager() == nil {
			t.Error("Expected guard manager to be set")
		}
	})

	t.Run("Guard", func(t *testing.T) {
		guard := adapter.Guard("jwt")
		if guard == nil {
			t.Fatal("Expected guard to be set")
		}
		if guard.Name() != "jwt" {
			t.Errorf("Expected guard name jwt, got %s", guard.Name())
		}
	})

	t.Run("DefaultGuard", func(t *testing.T) {
		guard := adapter.DefaultGuard()
		if guard == nil {
			t.Fatal("Expected default guard to be set")
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		guard := adapter.Guard("jwt")
		jwtG := guard.(*breitheamh.JWTGuard)

		authUser, token, err := jwtG.Attempt(ctx, breitheamh.Credentials{
			Email:    "test@example.com",
			Password: "secret",
		})
		if err != nil {
			t.Fatalf("Authentication failed: %v", err)
		}
		if authUser == nil {
			t.Fatal("Expected user to be authenticated")
		}
		if token == nil {
			t.Fatal("Expected token to be generated")
		}
	})
}
