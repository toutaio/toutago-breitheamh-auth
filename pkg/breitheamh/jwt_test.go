package breitheamh

import (
	"testing"
	"time"
)

func TestJWTTokenManager(t *testing.T) {
	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tm := NewJWTTokenManager(config)

	user := NewBaseUser("user-1", "test@example.com", "password")

	t.Run("Generate token", func(t *testing.T) {
		token, err := tm.Generate(user, 0)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if token.AccessToken == "" {
			t.Error("Access token should not be empty")
		}

		if token.RefreshToken == "" {
			t.Error("Refresh token should not be empty")
		}

		if token.TokenType != "Bearer" {
			t.Errorf("Token type = %q, expected %q", token.TokenType, "Bearer")
		}

		if token.ExpiresIn != int64(config.AccessTokenTTL.Seconds()) {
			t.Errorf("ExpiresIn = %d, expected %d", token.ExpiresIn, int64(config.AccessTokenTTL.Seconds()))
		}
	})

	t.Run("Validate token", func(t *testing.T) {
		token, err := tm.Generate(user, 0)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		claims, err := tm.Validate(token.AccessToken)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		if claims.UserID != user.GetID() {
			t.Errorf("UserID = %q, expected %q", claims.UserID, user.GetID())
		}

		if claims.Email != user.Email {
			t.Errorf("Email = %q, expected %q", claims.Email, user.Email)
		}
	})

	t.Run("Validate expired token", func(t *testing.T) {
		shortConfig := DefaultJWTConfig("test-secret-key-min-32-chars-long")
		shortConfig.AccessTokenTTL = -1 * time.Second // Set to past
		shortTM := NewJWTTokenManager(shortConfig)

		token, err := shortTM.Generate(user, 0)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		_, err = shortTM.Validate(token.AccessToken)
		if err != ErrExpiredToken {
			t.Errorf("Expected ErrExpiredToken, got %v", err)
		}
	})

	t.Run("Validate invalid token", func(t *testing.T) {
		_, err := tm.Validate("invalid.token.here")
		if err == nil {
			t.Error("Expected error for invalid token")
		}
	})

	t.Run("Refresh token", func(t *testing.T) {
		token, err := tm.Generate(user, 0)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		newToken, err := tm.Refresh(token.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to refresh token: %v", err)
		}

		if newToken.AccessToken == "" {
			t.Error("New access token should not be empty")
		}

		if newToken.RefreshToken == "" {
			t.Error("New refresh token should not be empty")
		}

		// Old refresh token should be revoked
		revoked, err := tm.IsRevoked(token.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to check revocation: %v", err)
		}
		if !revoked {
			t.Error("Old refresh token should be revoked")
		}
	})

	t.Run("Revoke refresh token", func(t *testing.T) {
		token, err := tm.Generate(user, 0)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = tm.Revoke(token.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to revoke token: %v", err)
		}

		revoked, err := tm.IsRevoked(token.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to check revocation: %v", err)
		}
		if !revoked {
			t.Error("Token should be revoked")
		}

		// Should not be able to refresh a revoked token
		_, err = tm.Refresh(token.RefreshToken)
		if err != ErrTokenRevoked {
			t.Errorf("Expected ErrTokenRevoked, got %v", err)
		}
	})
}

func TestJWTEncoding(t *testing.T) {
	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tm := NewJWTTokenManager(config)

	payload := jwtPayload{
		Sub: "user-1",
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iss: "test",
		Jti: "token-id",
		Email: "test@example.com",
	}

	token, err := tm.encodeJWT(payload)
	if err != nil {
		t.Fatalf("Failed to encode JWT: %v", err)
	}

	decoded, err := tm.decodeJWT(token)
	if err != nil {
		t.Fatalf("Failed to decode JWT: %v", err)
	}

	if decoded.Sub != payload.Sub {
		t.Errorf("Sub = %q, expected %q", decoded.Sub, payload.Sub)
	}

	if decoded.Email != payload.Email {
		t.Errorf("Email = %q, expected %q", decoded.Email, payload.Email)
	}
}

func BenchmarkJWTGenerate(b *testing.B) {
	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tm := NewJWTTokenManager(config)
	user := NewBaseUser("user-1", "test@example.com", "password")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.Generate(user, 0)
	}
}

func BenchmarkJWTValidate(b *testing.B) {
	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tm := NewJWTTokenManager(config)
	user := NewBaseUser("user-1", "test@example.com", "password")

	token, _ := tm.Generate(user, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.Validate(token.AccessToken)
	}
}
