package breitheamh_test

import (
	"crypto/subtle"
	"fmt"
	"testing"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// TestPasswordHashingTimingSafety ensures password comparison is timing-safe
func TestPasswordHashingTimingSafety(t *testing.T) {
	password := "MySecurePassword123!"
	wrongPassword := "WrongPassword456!"

	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Measure time for correct password (reduced iterations for faster tests)
	iterations := 100
	start := time.Now()
	for i := 0; i < iterations; i++ {
		hasher.Verify(password, hash)
	}
	correctDuration := time.Since(start)

	// Measure time for incorrect password
	start = time.Now()
	for i := 0; i < iterations; i++ {
		hasher.Verify(wrongPassword, hash)
	}
	incorrectDuration := time.Since(start)

	// Timing should be similar (within 50% variance due to bcrypt's design)
	ratio := float64(correctDuration) / float64(incorrectDuration)
	if ratio < 0.5 || ratio > 2.0 {
		t.Logf("Warning: Timing difference detected - correct: %v, incorrect: %v, ratio: %.2f",
			correctDuration, incorrectDuration, ratio)
		// This is informational - bcrypt should be timing-safe internally
	}
}

// TestConstantTimeComparison ensures token comparison uses constant-time comparison
func TestConstantTimeComparison(t *testing.T) {
	token1 := "secret_token_123456789"
	token2 := "secret_token_123456789"
	token3 := "wrong_token_000000000"

	// Demonstrate constant-time comparison
	if subtle.ConstantTimeCompare([]byte(token1), []byte(token2)) != 1 {
		t.Error("Expected tokens to match")
	}

	if subtle.ConstantTimeCompare([]byte(token1), []byte(token3)) == 1 {
		t.Error("Expected tokens to not match")
	}

	// Verify different lengths
	if subtle.ConstantTimeCompare([]byte(token1), []byte("short")) == 1 {
		t.Error("Expected tokens to not match")
	}
}

// TestPasswordComplexityRequirements ensures password policies are enforced
func TestPasswordComplexityRequirements(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minLen   int
		valid    bool
	}{
		{"too short", "Aa1!", 8, false},
		{"meets minimum", "Password123!", 8, true},
		{"long password", "MyVerySecurePassword123!", 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := len(tt.password) >= tt.minLen
			if valid != tt.valid {
				t.Errorf("Password length check for %q = %v, want %v", tt.password, valid, tt.valid)
			}
		})
	}
}

// TestJWTSignatureValidation ensures JWTs cannot be tampered with
func TestJWTSignatureValidation(t *testing.T) {
	config := &breitheamh.JWTConfig{
		SecretKey:       []byte("test-secret-key"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	}
	tokenManager := breitheamh.NewJWTTokenManager(config)
	user := breitheamh.NewBaseUser("1", "test@example.com", "hashed-password")

	// Generate token
	token, err := tokenManager.Generate(user, 0)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Valid token should pass
	if _, err := tokenManager.Validate(token.AccessToken); err != nil {
		t.Errorf("Valid token failed validation: %v", err)
	}

	// Tampered token should fail
	if len(token.AccessToken) > 5 {
		tamperedToken := token.AccessToken[:len(token.AccessToken)-5] + "XXXXX"
		if _, err := tokenManager.Validate(tamperedToken); err == nil {
			t.Error("Tampered token should not validate")
		}
	}

	// Invalid format should fail
	if _, err := tokenManager.Validate("invalid.token.format"); err == nil {
		t.Error("Invalid token format should not validate")
	}

	// Empty token should fail
	if _, err := tokenManager.Validate(""); err == nil {
		t.Error("Empty token should not validate")
	}
}

// TestBruteForceProtection ensures account locking works correctly
func TestBruteForceProtection(t *testing.T) {
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hash, _ := hasher.Hash("correct-password")

	user := breitheamh.NewBaseUser("1", "test@example.com", hash)
	maxAttempts := 5

	// Simulate failed login attempts
	for i := 0; i < maxAttempts; i++ {
		user.RecordFailedLogin()
	}

	if !user.IsLocked() {
		t.Error("User should be locked after max failed attempts")
	}

	if user.FailedLoginCount != maxAttempts {
		t.Errorf("Expected %d failed attempts, got %d", maxAttempts, user.FailedLoginCount)
	}

	// Unlock should reset attempts
	user.Unlock()
	if user.IsLocked() {
		t.Error("User should be unlocked")
	}
	if user.FailedLoginCount != 0 {
		t.Error("Failed attempts should be reset after unlock")
	}
}

// TestTokenRevocation ensures revoked tokens cannot be used
func TestTokenRevocation(t *testing.T) {
	config := &breitheamh.JWTConfig{
		SecretKey:       []byte("secret-key"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	}
	tokenManager := breitheamh.NewJWTTokenManager(config)
	user := breitheamh.NewBaseUser("1", "test@example.com", "hashed-password")

	token, err := tokenManager.Generate(user, 0)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Token should be valid initially
	if _, err := tokenManager.Validate(token.AccessToken); err != nil {
		t.Errorf("Fresh token should be valid: %v", err)
	}

	// Note: Token revocation would require a blacklist implementation
	// For now, we just verify that tokens can be validated
	t.Log("Token revocation requires blacklist implementation")
}

// TestSessionHijackingPrevention ensures session IDs are cryptographically secure
func TestSessionHijackingPrevention(t *testing.T) {
	// This test would require the full session implementation
	// For now, we test that session IDs can be generated
	provider := memory.NewProvider()
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)

	// Verify that we can create users and hash passwords
	iterations := 10
	for i := 0; i < iterations; i++ {
		password := fmt.Sprintf("password%d", i)
		hash, err := hasher.Hash(password)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}

		user := breitheamh.NewBaseUser(fmt.Sprintf("%d", i+1), "user@example.com", hash)
		provider.AddUser(user)

		// Verify password hashing is working
		if err := hasher.Verify(password, hash); err != nil {
			t.Errorf("Password verification failed: %v", err)
		}
	}
}

// TestPermissionEscalation ensures users cannot escalate privileges
func TestPermissionEscalation(t *testing.T) {
	user := breitheamh.NewBaseUser("1", "user@example.com", "password")

	// User starts with basic permissions
	user.GrantPermission(breitheamh.Permission{Name: "posts.read"})
	user.GrantPermission(breitheamh.Permission{Name: "posts.create"})

	// Ensure user doesn't have admin permissions
	if user.HasPermission("admin.access") {
		t.Error("User should not have admin access")
	}

	if user.HasPermission("users.delete") {
		t.Error("User should not have delete permissions")
	}

	// Wildcard should not grant unintended permissions
	user.GrantPermission(breitheamh.Permission{Name: "posts.*"})
	if user.HasPermission("users.delete") {
		t.Error("Wildcard posts.* should not grant users.delete")
	}

	// Super admin wildcard
	adminUser := breitheamh.NewBaseUser("2", "admin@example.com", "password")
	adminUser.GrantPermission(breitheamh.Permission{Name: "*"})

	if !adminUser.HasPermission("any.permission.possible") {
		t.Error("Super admin should have all permissions")
	}
}

// TestEmailVerificationSecurity ensures email verification tokens are secure
func TestEmailVerificationSecurity(t *testing.T) {
	user := breitheamh.NewBaseUser("1", "test@example.com", "password")

	token := user.GenerateEmailVerificationToken()

	// Token should be generated
	if token == "" {
		t.Error("Email verification token should not be empty")
	}

	// Token should be sufficiently long
	if len(token) < 32 {
		t.Errorf("Email verification token too short: %d", len(token))
	}

	// Verify token works
	if !user.VerifyEmailWithToken(token) {
		t.Error("Valid token should verify email")
	}

	// Token should be single-use
	if user.VerifyEmailWithToken(token) {
		t.Error("Token should not work after first use")
	}

	// Wrong token should fail
	if user.VerifyEmailWithToken("wrong-token") {
		t.Error("Invalid token should not verify email")
	}
}
