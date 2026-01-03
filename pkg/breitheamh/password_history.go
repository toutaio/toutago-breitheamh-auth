package breitheamh

import (
	"fmt"
	"sync"
	"time"
)

// PasswordHistory represents a password change record
type PasswordHistory struct {
	UserID    string
	Password  string
	CreatedAt time.Time
}

// PasswordHistoryStore defines the interface for storing password history
type PasswordHistoryStore interface {
	Add(userID, hashedPassword string) error
	Get(userID string, limit int) ([]*PasswordHistory, error)
	WasUsedRecently(userID, hashedPassword string, limit int) (bool, error)
	Clear(userID string) error
}

// MemoryPasswordHistoryStore stores password history in memory
type MemoryPasswordHistoryStore struct {
	mu      sync.RWMutex
	history map[string][]*PasswordHistory
}

// NewMemoryPasswordHistoryStore creates a new in-memory password history store
func NewMemoryPasswordHistoryStore() *MemoryPasswordHistoryStore {
	return &MemoryPasswordHistoryStore{
		history: make(map[string][]*PasswordHistory),
	}
}

// Add adds a password to the user's history
func (s *MemoryPasswordHistoryStore) Add(userID, hashedPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := &PasswordHistory{
		UserID:    userID,
		Password:  hashedPassword,
		CreatedAt: time.Now(),
	}

	s.history[userID] = append(s.history[userID], entry)
	return nil
}

// Get retrieves the password history for a user, limited to the last N entries
func (s *MemoryPasswordHistoryStore) Get(userID string, limit int) ([]*PasswordHistory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userHistory, exists := s.history[userID]
	if !exists {
		return []*PasswordHistory{}, nil
	}

	// Return the last N entries
	if limit > 0 && len(userHistory) > limit {
		userHistory = userHistory[len(userHistory)-limit:]
	}

	// Return a copy to avoid external modifications
	result := make([]*PasswordHistory, len(userHistory))
	copy(result, userHistory)
	return result, nil
}

// WasUsedRecently checks if a password hash was used in the last N password changes
func (s *MemoryPasswordHistoryStore) WasUsedRecently(userID, hashedPassword string, limit int) (bool, error) {
	history, err := s.Get(userID, limit)
	if err != nil {
		return false, err
	}

	for _, entry := range history {
		if entry.Password == hashedPassword {
			return true, nil
		}
	}

	return false, nil
}

// Clear removes all password history for a user
func (s *MemoryPasswordHistoryStore) Clear(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.history, userID)
	return nil
}

// PasswordHistoryChecker enforces password history rules
type PasswordHistoryChecker struct {
	store  PasswordHistoryStore
	hasher *Hasher
	limit  int
}

// NewPasswordHistoryChecker creates a new password history checker
func NewPasswordHistoryChecker(store PasswordHistoryStore, hasher *Hasher, limit int) *PasswordHistoryChecker {
	if limit <= 0 {
		limit = 5 // Default to remember last 5 passwords
	}
	return &PasswordHistoryChecker{
		store:  store,
		hasher: hasher,
		limit:  limit,
	}
}

// CheckPassword validates that a password hasn't been used recently
func (c *PasswordHistoryChecker) CheckPassword(userID, plainPassword string) error {
	history, err := c.store.Get(userID, c.limit)
	if err != nil {
		return fmt.Errorf("failed to get password history: %w", err)
	}

	for _, entry := range history {
		if err := c.hasher.Verify(plainPassword, entry.Password); err == nil {
			return fmt.Errorf("password was used recently and cannot be reused")
		}
	}

	return nil
}

// RecordPassword adds a password to the history after a successful change
func (c *PasswordHistoryChecker) RecordPassword(userID, hashedPassword string) error {
	if err := c.store.Add(userID, hashedPassword); err != nil {
		return fmt.Errorf("failed to record password: %w", err)
	}
	return nil
}

// ChangePassword changes a user's password with history checking
func (c *PasswordHistoryChecker) ChangePassword(userID, plainPassword string) (string, error) {
	// Check if password was used recently
	if err := c.CheckPassword(userID, plainPassword); err != nil {
		return "", err
	}

	// Hash the new password
	hashedPassword, err := c.hasher.Hash(plainPassword)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Record in history
	if err := c.RecordPassword(userID, hashedPassword); err != nil {
		return "", err
	}

	return hashedPassword, nil
}

// WithLimit sets the number of previous passwords to remember
func (c *PasswordHistoryChecker) WithLimit(limit int) *PasswordHistoryChecker {
	c.limit = limit
	return c
}

// GetLimit returns the current history limit
func (c *PasswordHistoryChecker) GetLimit() int {
	return c.limit
}
