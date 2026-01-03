package breitheamh

import (
	"testing"
)

func TestPasswordHistoryStore(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	userID := "user123"

	// Add password to history
	err := store.Add(userID, "hash1")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Get history
	history, err := store.Get(userID, 0)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(history) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(history))
	}

	if history[0].Password != "hash1" {
		t.Errorf("Expected hash1, got %s", history[0].Password)
	}
}

func TestPasswordHistoryLimit(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	userID := "user123"

	// Add multiple passwords
	for i := 0; i < 10; i++ {
		store.Add(userID, "hash"+string(rune('0'+i)))
	}

	// Get last 5
	history, err := store.Get(userID, 5)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(history) != 5 {
		t.Errorf("Expected 5 entries, got %d", len(history))
	}
}

func TestPasswordHistoryWasUsedRecently(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	userID := "user123"

	// Add passwords
	store.Add(userID, "hash1")
	store.Add(userID, "hash2")
	store.Add(userID, "hash3")

	// Check if hash2 was used recently (last 3)
	wasUsed, err := store.WasUsedRecently(userID, "hash2", 3)
	if err != nil {
		t.Fatalf("WasUsedRecently failed: %v", err)
	}

	if !wasUsed {
		t.Error("Expected hash2 to be in recent history")
	}

	// Check if hash4 was used recently
	wasUsed, err = store.WasUsedRecently(userID, "hash4", 3)
	if err != nil {
		t.Fatalf("WasUsedRecently failed: %v", err)
	}

	if wasUsed {
		t.Error("Expected hash4 to not be in recent history")
	}
}

func TestPasswordHistoryClear(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	userID := "user123"

	// Add passwords
	store.Add(userID, "hash1")
	store.Add(userID, "hash2")

	// Clear history
	err := store.Clear(userID)
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify empty
	history, err := store.Get(userID, 0)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(history) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", len(history))
	}
}

func TestPasswordHistoryChecker(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	hasher := NewHasher(AlgorithmBcrypt)
	checker := NewPasswordHistoryChecker(store, hasher, 3)

	userID := "user123"
	password1 := "Password123!"
	password2 := "NewPassword456!"

	// Change password first time
	hash1, err := checker.ChangePassword(userID, password1)
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}

	// Try to reuse same password
	_, err = checker.ChangePassword(userID, password1)
	if err == nil {
		t.Error("Expected error when reusing password")
	}

	// Change to different password
	hash2, err := checker.ChangePassword(userID, password2)
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	if hash2 == hash1 {
		t.Error("Different passwords should produce different hashes")
	}

	// Try to reuse second password
	_, err = checker.ChangePassword(userID, password2)
	if err == nil {
		t.Error("Expected error when reusing password")
	}
}

func TestPasswordHistoryCheckerLimit(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	hasher := NewHasher(AlgorithmBcrypt)
	checker := NewPasswordHistoryChecker(store, hasher, 2)

	userID := "user123"

	// Change password 3 times
	checker.ChangePassword(userID, "Password1!")
	checker.ChangePassword(userID, "Password2!")
	checker.ChangePassword(userID, "Password3!")

	// Should be able to reuse first password (outside limit of 2)
	// Last 2 are: Password2 and Password3
	_, err := checker.ChangePassword(userID, "Password1!")
	if err != nil {
		t.Errorf("Should be able to reuse password outside history limit: %v", err)
	}

	// Now history has: Password2, Password3, Password1
	// Last 2 are: Password3 and Password1
	// Should not be able to reuse Password3 (within limit)
	_, err = checker.ChangePassword(userID, "Password3!")
	if err == nil {
		t.Error("Should not be able to reuse password within history limit")
	}
}

func TestPasswordHistoryCheckerCheckPassword(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	hasher := NewHasher(AlgorithmBcrypt)
	checker := NewPasswordHistoryChecker(store, hasher, 3)

	userID := "user123"
	password := "Password123!"

	// Add password to history
	hash, _ := hasher.Hash(password)
	store.Add(userID, hash)

	// Check if password was used
	err := checker.CheckPassword(userID, password)
	if err == nil {
		t.Error("Expected error for recently used password")
	}

	// Check new password
	err = checker.CheckPassword(userID, "NewPassword456!")
	if err != nil {
		t.Errorf("New password should be allowed: %v", err)
	}
}

func TestPasswordHistoryCheckerDefaultLimit(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	hasher := NewHasher(AlgorithmBcrypt)
	checker := NewPasswordHistoryChecker(store, hasher, 0)

	if checker.GetLimit() != 5 {
		t.Errorf("Expected default limit of 5, got %d", checker.GetLimit())
	}
}

func TestPasswordHistoryCheckerWithLimit(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	hasher := NewHasher(AlgorithmBcrypt)
	checker := NewPasswordHistoryChecker(store, hasher, 3)

	newChecker := checker.WithLimit(10)

	if newChecker.GetLimit() != 10 {
		t.Errorf("Expected limit of 10, got %d", newChecker.GetLimit())
	}
}

func TestPasswordHistoryEmptyHistory(t *testing.T) {
	store := NewMemoryPasswordHistoryStore()
	userID := "user123"

	// Get history for user with no history
	history, err := store.Get(userID, 5)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(history) != 0 {
		t.Errorf("Expected 0 entries for new user, got %d", len(history))
	}

	// Check WasUsedRecently for user with no history
	wasUsed, err := store.WasUsedRecently(userID, "hash1", 5)
	if err != nil {
		t.Fatalf("WasUsedRecently failed: %v", err)
	}

	if wasUsed {
		t.Error("Expected false for user with no history")
	}
}
