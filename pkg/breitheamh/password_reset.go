package breitheamh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	Token     string
	Email     string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
}

// IsExpired checks if the token has expired
func (t *PasswordResetToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsUsed checks if the token has been used
func (t *PasswordResetToken) IsUsed() bool {
	return t.UsedAt != nil
}

// PasswordResetTokenStore defines the interface for storing password reset tokens
type PasswordResetTokenStore interface {
	Create(email string, expiresIn time.Duration) (*PasswordResetToken, error)
	Find(token string) (*PasswordResetToken, error)
	MarkAsUsed(token string) error
	Delete(token string) error
	DeleteByEmail(email string) error
	Cleanup() error // Remove expired tokens
}

// MemoryPasswordResetTokenStore stores tokens in memory
type MemoryPasswordResetTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*PasswordResetToken
}

// NewMemoryPasswordResetTokenStore creates a new in-memory token store
func NewMemoryPasswordResetTokenStore() *MemoryPasswordResetTokenStore {
	return &MemoryPasswordResetTokenStore{
		tokens: make(map[string]*PasswordResetToken),
	}
}

// Create generates a new password reset token
func (s *MemoryPasswordResetTokenStore) Create(email string, expiresIn time.Duration) (*PasswordResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	tokenStr := hex.EncodeToString(tokenBytes)

	token := &PasswordResetToken{
		Token:     tokenStr,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiresIn),
	}

	s.tokens[tokenStr] = token
	return token, nil
}

// Find retrieves a token by its string value
func (s *MemoryPasswordResetTokenStore) Find(token string) (*PasswordResetToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, exists := s.tokens[token]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	return t, nil
}

// MarkAsUsed marks a token as used
func (s *MemoryPasswordResetTokenStore) MarkAsUsed(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, exists := s.tokens[token]
	if !exists {
		return fmt.Errorf("token not found")
	}

	now := time.Now()
	t.UsedAt = &now
	return nil
}

// Delete removes a token
func (s *MemoryPasswordResetTokenStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	return nil
}

// DeleteByEmail removes all tokens for an email
func (s *MemoryPasswordResetTokenStore) DeleteByEmail(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, t := range s.tokens {
		if t.Email == email {
			delete(s.tokens, token)
		}
	}

	return nil
}

// Cleanup removes expired tokens
func (s *MemoryPasswordResetTokenStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, token)
		}
	}

	return nil
}

// EmailVerificationToken represents an email verification token
type EmailVerificationToken struct {
	Token     string
	Email     string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
}

// IsExpired checks if the token has expired
func (t *EmailVerificationToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsUsed checks if the token has been used
func (t *EmailVerificationToken) IsUsed() bool {
	return t.UsedAt != nil
}

// EmailVerificationTokenStore defines the interface for storing email verification tokens
type EmailVerificationTokenStore interface {
	Create(userID, email string, expiresIn time.Duration) (*EmailVerificationToken, error)
	Find(token string) (*EmailVerificationToken, error)
	MarkAsUsed(token string) error
	Delete(token string) error
	DeleteByUserID(userID string) error
	Cleanup() error
}

// MemoryEmailVerificationTokenStore stores tokens in memory
type MemoryEmailVerificationTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*EmailVerificationToken
}

// NewMemoryEmailVerificationTokenStore creates a new in-memory token store
func NewMemoryEmailVerificationTokenStore() *MemoryEmailVerificationTokenStore {
	return &MemoryEmailVerificationTokenStore{
		tokens: make(map[string]*EmailVerificationToken),
	}
}

// Create generates a new email verification token
func (s *MemoryEmailVerificationTokenStore) Create(userID, email string, expiresIn time.Duration) (*EmailVerificationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	tokenStr := hex.EncodeToString(tokenBytes)

	token := &EmailVerificationToken{
		Token:     tokenStr,
		UserID:    userID,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiresIn),
	}

	s.tokens[tokenStr] = token
	return token, nil
}

// Find retrieves a token by its string value
func (s *MemoryEmailVerificationTokenStore) Find(token string) (*EmailVerificationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, exists := s.tokens[token]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	return t, nil
}

// MarkAsUsed marks a token as used
func (s *MemoryEmailVerificationTokenStore) MarkAsUsed(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, exists := s.tokens[token]
	if !exists {
		return fmt.Errorf("token not found")
	}

	now := time.Now()
	t.UsedAt = &now
	return nil
}

// Delete removes a token
func (s *MemoryEmailVerificationTokenStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	return nil
}

// DeleteByUserID removes all tokens for a user
func (s *MemoryEmailVerificationTokenStore) DeleteByUserID(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, t := range s.tokens {
		if t.UserID == userID {
			delete(s.tokens, token)
		}
	}

	return nil
}

// Cleanup removes expired tokens
func (s *MemoryEmailVerificationTokenStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, token)
		}
	}

	return nil
}

// PasswordManager handles password reset and email verification flows
type PasswordManager struct {
	resetStore         PasswordResetTokenStore
	verificationStore  EmailVerificationTokenStore
	hasher             *Hasher
	resetExpiry        time.Duration
	verificationExpiry time.Duration
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(hasher *Hasher) *PasswordManager {
	return &PasswordManager{
		resetStore:         NewMemoryPasswordResetTokenStore(),
		verificationStore:  NewMemoryEmailVerificationTokenStore(),
		hasher:             hasher,
		resetExpiry:        1 * time.Hour,
		verificationExpiry: 24 * time.Hour,
	}
}

// WithResetStore sets a custom password reset token store
func (pm *PasswordManager) WithResetStore(store PasswordResetTokenStore) *PasswordManager {
	pm.resetStore = store
	return pm
}

// WithVerificationStore sets a custom email verification token store
func (pm *PasswordManager) WithVerificationStore(store EmailVerificationTokenStore) *PasswordManager {
	pm.verificationStore = store
	return pm
}

// WithResetExpiry sets the expiry duration for password reset tokens
func (pm *PasswordManager) WithResetExpiry(expiry time.Duration) *PasswordManager {
	pm.resetExpiry = expiry
	return pm
}

// WithVerificationExpiry sets the expiry duration for email verification tokens
func (pm *PasswordManager) WithVerificationExpiry(expiry time.Duration) *PasswordManager {
	pm.verificationExpiry = expiry
	return pm
}

// CreatePasswordResetToken creates a new password reset token
func (pm *PasswordManager) CreatePasswordResetToken(email string) (*PasswordResetToken, error) {
	// Delete any existing tokens for this email
	_ = pm.resetStore.DeleteByEmail(email)

	return pm.resetStore.Create(email, pm.resetExpiry)
}

// VerifyPasswordResetToken validates a password reset token
func (pm *PasswordManager) VerifyPasswordResetToken(token string) (*PasswordResetToken, error) {
	t, err := pm.resetStore.Find(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if t.IsExpired() {
		return nil, fmt.Errorf("token has expired")
	}

	if t.IsUsed() {
		return nil, fmt.Errorf("token has already been used")
	}

	return t, nil
}

// ResetPassword resets a user's password using a token
func (pm *PasswordManager) ResetPassword(token, newPassword string) error {
	t, err := pm.VerifyPasswordResetToken(token)
	if err != nil {
		return err
	}

	// Mark token as used
	if err := pm.resetStore.MarkAsUsed(token); err != nil {
		return err
	}

	// Note: In a real implementation, you would update the user's password here
	// This requires integration with the UserProvider
	_ = t // Token contains the email to identify the user
	_ = newPassword

	return nil
}

// CreateEmailVerificationToken creates a new email verification token
func (pm *PasswordManager) CreateEmailVerificationToken(userID, email string) (*EmailVerificationToken, error) {
	// Delete any existing tokens for this user
	_ = pm.verificationStore.DeleteByUserID(userID)

	return pm.verificationStore.Create(userID, email, pm.verificationExpiry)
}

// VerifyEmailToken validates an email verification token
func (pm *PasswordManager) VerifyEmailToken(token string) (*EmailVerificationToken, error) {
	t, err := pm.verificationStore.Find(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if t.IsExpired() {
		return nil, fmt.Errorf("token has expired")
	}

	if t.IsUsed() {
		return nil, fmt.Errorf("token has already been used")
	}

	return t, nil
}

// VerifyEmail marks an email as verified using a token
func (pm *PasswordManager) VerifyEmail(token string) (string, error) {
	t, err := pm.VerifyEmailToken(token)
	if err != nil {
		return "", err
	}

	// Mark token as used
	if err := pm.verificationStore.MarkAsUsed(token); err != nil {
		return "", err
	}

	return t.UserID, nil
}

// CleanupExpiredTokens removes expired tokens from both stores
func (pm *PasswordManager) CleanupExpiredTokens() error {
	if err := pm.resetStore.Cleanup(); err != nil {
		return err
	}
	return pm.verificationStore.Cleanup()
}
