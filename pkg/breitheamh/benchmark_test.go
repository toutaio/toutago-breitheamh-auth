package breitheamh

import (
	"context"
	"testing"
	"time"
)

func BenchmarkJWTGuard(b *testing.B) {
	provider := NewMemoryProvider()
	user := &BaseUser{
		ID:       1,
		Email:    "test@example.com",
		Password: "hashed_password",
	}
	provider.AddUser(user)

	secret := []byte("test-secret-key")
	guard := NewJWTGuard(provider, secret, JWTConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	ctx := context.Background()

	b.Run("GenerateToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := guard.GenerateToken(user)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	token, _ := guard.GenerateToken(user)

	b.Run("ValidateToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := guard.ValidateToken(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Attempt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := guard.Attempt(ctx, map[string]interface{}{
				"email":    "test@example.com",
				"password": "password",
			})
			if err == nil {
				b.Fatal("expected error for wrong password")
			}
		}
	})
}

func BenchmarkPasswordHashing(b *testing.B) {
	password := "secure_password_123"

	b.Run("BcryptHash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := HashPassword(password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	hashedPassword, _ := HashPassword(password)

	b.Run("BcryptVerify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !CheckPasswordHash(password, hashedPassword) {
				b.Fatal("password verification failed")
			}
		}
	})

	b.Run("Argon2Hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := HashPasswordArgon2(password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	argon2Hash, _ := HashPasswordArgon2(password)

	b.Run("Argon2Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !CheckPasswordHashArgon2(password, argon2Hash) {
				b.Fatal("password verification failed")
			}
		}
	})
}

func BenchmarkPermissionMatching(b *testing.B) {
	trie := NewPermissionTrie()
	
	permissions := []string{
		"posts.create",
		"posts.read",
		"posts.update",
		"posts.delete",
		"users.create",
		"users.read",
		"users.update",
		"users.delete",
		"admin.*",
		"reports.*",
	}

	for _, perm := range permissions {
		trie.Add(perm)
	}

	b.Run("ExactMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !trie.Match("posts.create") {
				b.Fatal("expected match")
			}
		}
	})

	b.Run("WildcardMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !trie.Match("admin.users.delete") {
				b.Fatal("expected wildcard match")
			}
		}
	})

	b.Run("NoMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if trie.Match("comments.create") {
				b.Fatal("expected no match")
			}
		}
	})
}

func BenchmarkPolicyAuthorization(b *testing.B) {
	type Post struct {
		ID     int
		UserID int
		Title  string
	}

	type PostPolicy struct{}

	func (p *PostPolicy) Update(user Authenticatable, post *Post) bool {
		return post.UserID == user.GetAuthIdentifier().(int)
	}

	manager := &PolicyManager{
		policies: make(map[string]interface{}),
		cache:    NewPolicyCache(5 * time.Minute),
	}

	manager.RegisterPolicy("Post", &PostPolicy{})

	user := &BaseUser{ID: 1}
	post := &Post{ID: 1, UserID: 1, Title: "Test"}

	b.Run("AuthorizeWithCache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !manager.Authorize(user, "update", post) {
				b.Fatal("expected authorization")
			}
		}
	})
}

func BenchmarkRateLimiter(b *testing.B) {
	limiter := NewRateLimiter(100, time.Minute)

	b.Run("Allow", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			limiter.Allow("benchmark-key")
		}
	})

	b.Run("AllowParallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				limiter.Allow("parallel-key")
				i++
			}
		})
	})
}

func BenchmarkConcurrentAuth(b *testing.B) {
	provider := NewMemoryProvider()
	secret := []byte("test-secret")
	guard := NewJWTGuard(provider, secret, JWTConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	for i := 0; i < 100; i++ {
		user := &BaseUser{
			ID:       i,
			Email:    "user" + string(rune(i)) + "@example.com",
			Password: "hashed",
		}
		provider.AddUser(user)
	}

	ctx := context.Background()

	b.Run("ParallelAttempt", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				guard.Attempt(ctx, map[string]interface{}{
					"email":    "user" + string(rune(i%100)) + "@example.com",
					"password": "wrong",
				})
				i++
			}
		})
	})
}
