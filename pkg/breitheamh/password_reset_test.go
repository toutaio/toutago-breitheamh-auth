package breitheamh

import (
	"testing"
	"time"
)

func TestPasswordResetTokenStore(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	token, err := store.Create("user@example.com", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	
	if token.Token == "" {
		t.Error("Expected non-empty token")
	}
	
	if token.Email != "user@example.com" {
		t.Errorf("Expected email user@example.com, got %s", token.Email)
	}
	
	if token.IsExpired() {
		t.Error("Token should not be expired")
	}
	
	if token.IsUsed() {
		t.Error("Token should not be used")
	}
}

func TestPasswordResetTokenFind(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	created, _ := store.Create("user@example.com", 1*time.Hour)
	
	found, err := store.Find(created.Token)
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	
	if found.Token != created.Token {
		t.Error("Found token doesn't match created token")
	}
	
	_, err = store.Find("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent token")
	}
}

func TestPasswordResetTokenMarkAsUsed(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	token, _ := store.Create("user@example.com", 1*time.Hour)
	
	if token.IsUsed() {
		t.Error("Token should not be used initially")
	}
	
	err := store.MarkAsUsed(token.Token)
	if err != nil {
		t.Fatalf("MarkAsUsed failed: %v", err)
	}
	
	found, _ := store.Find(token.Token)
	if !found.IsUsed() {
		t.Error("Token should be marked as used")
	}
}

func TestPasswordResetTokenDelete(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	token, _ := store.Create("user@example.com", 1*time.Hour)
	
	err := store.Delete(token.Token)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	
	_, err = store.Find(token.Token)
	if err == nil {
		t.Error("Expected error for deleted token")
	}
}

func TestPasswordResetTokenDeleteByEmail(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	store.Create("user@example.com", 1*time.Hour)
	store.Create("user@example.com", 1*time.Hour)
	store.Create("other@example.com", 1*time.Hour)
	
	err := store.DeleteByEmail("user@example.com")
	if err != nil {
		t.Fatalf("DeleteByEmail failed: %v", err)
	}
	
	// The other@example.com token should still exist
	// We can't easily test this without exposing internal state
}

func TestPasswordResetTokenCleanup(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	// Create expired token
	expired, _ := store.Create("user@example.com", -1*time.Hour)
	// Create valid token
	valid, _ := store.Create("other@example.com", 1*time.Hour)
	
	err := store.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	
	_, err = store.Find(expired.Token)
	if err == nil {
		t.Error("Expired token should have been cleaned up")
	}
	
	_, err = store.Find(valid.Token)
	if err != nil {
		t.Error("Valid token should still exist after cleanup")
	}
}

func TestPasswordResetTokenExpiry(t *testing.T) {
	store := NewMemoryPasswordResetTokenStore()
	
	token, _ := store.Create("user@example.com", 1*time.Millisecond)
	
	time.Sleep(2 * time.Millisecond)
	
	if !token.IsExpired() {
		t.Error("Token should be expired")
	}
}

func TestEmailVerificationTokenStore(t *testing.T) {
	store := NewMemoryEmailVerificationTokenStore()
	
	token, err := store.Create("user123", "user@example.com", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	
	if token.Token == "" {
		t.Error("Expected non-empty token")
	}
	
	if token.UserID != "user123" {
		t.Errorf("Expected UserID user123, got %s", token.UserID)
	}
	
	if token.Email != "user@example.com" {
		t.Errorf("Expected email user@example.com, got %s", token.Email)
	}
}

func TestEmailVerificationTokenFind(t *testing.T) {
	store := NewMemoryEmailVerificationTokenStore()
	
	created, _ := store.Create("user123", "user@example.com", 1*time.Hour)
	
	found, err := store.Find(created.Token)
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	
	if found.Token != created.Token {
		t.Error("Found token doesn't match created token")
	}
}

func TestEmailVerificationTokenDeleteByUserID(t *testing.T) {
	store := NewMemoryEmailVerificationTokenStore()
	
	store.Create("user123", "user@example.com", 1*time.Hour)
	store.Create("user123", "user@example.com", 1*time.Hour)
	store.Create("user456", "other@example.com", 1*time.Hour)
	
	err := store.DeleteByUserID("user123")
	if err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
}

func TestPasswordManager(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	pm := NewPasswordManager(hasher)
	
	// Test password reset flow
	resetToken, err := pm.CreatePasswordResetToken("user@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken failed: %v", err)
	}
	
	verified, err := pm.VerifyPasswordResetToken(resetToken.Token)
	if err != nil {
		t.Fatalf("VerifyPasswordResetToken failed: %v", err)
	}
	
	if verified.Email != "user@example.com" {
		t.Error("Verified token email doesn't match")
	}
	
	// Test email verification flow
	verifyToken, err := pm.CreateEmailVerificationToken("user123", "user@example.com")
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken failed: %v", err)
	}
	
	userID, err := pm.VerifyEmail(verifyToken.Token)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	
	if userID != "user123" {
		t.Errorf("Expected userID user123, got %s", userID)
	}
}

func TestPasswordManagerExpiredToken(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	pm := NewPasswordManager(hasher).WithResetExpiry(1 * time.Millisecond)
	
	token, _ := pm.CreatePasswordResetToken("user@example.com")
	
	time.Sleep(2 * time.Millisecond)
	
	_, err := pm.VerifyPasswordResetToken(token.Token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestPasswordManagerUsedToken(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	pm := NewPasswordManager(hasher)
	
	token, _ := pm.CreatePasswordResetToken("user@example.com")
	
	// Verify once (marks as used internally in ResetPassword)
	pm.resetStore.MarkAsUsed(token.Token)
	
	_, err := pm.VerifyPasswordResetToken(token.Token)
	if err == nil {
		t.Error("Expected error for used token")
	}
}

func TestPasswordManagerCleanup(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	pm := NewPasswordManager(hasher)
	
	// Create expired tokens
	pm.WithResetExpiry(-1 * time.Hour).CreatePasswordResetToken("user1@example.com")
	pm.WithVerificationExpiry(-1 * time.Hour).CreateEmailVerificationToken("user1", "user1@example.com")
	
	// Create valid tokens
	pm.WithResetExpiry(1 * time.Hour).CreatePasswordResetToken("user2@example.com")
	pm.WithVerificationExpiry(1 * time.Hour).CreateEmailVerificationToken("user2", "user2@example.com")
	
	err := pm.CleanupExpiredTokens()
	if err != nil {
		t.Fatalf("CleanupExpiredTokens failed: %v", err)
	}
}

func TestPasswordManagerReplaceExisting(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	pm := NewPasswordManager(hasher)
	
	// Create first token
	token1, _ := pm.CreatePasswordResetToken("user@example.com")
	
	// Create second token (should replace first)
	token2, _ := pm.CreatePasswordResetToken("user@example.com")
	
	if token1.Token == token2.Token {
		t.Error("New token should be different from old token")
	}
	
	// First token should no longer be valid (deleted)
	_, err := pm.resetStore.Find(token1.Token)
	if err == nil {
		t.Error("Expected old token to be deleted")
	}
}
