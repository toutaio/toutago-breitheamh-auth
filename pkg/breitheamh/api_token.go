package breitheamh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// ErrInvalidAPIToken indicates that the API token is invalid
	ErrInvalidAPIToken = errors.New("invalid API token")
)

// APIToken represents an API token for authentication.
type APIToken struct {
	ID        string
	UserID    string
	Token     string
	Name      string
	Abilities []string
	CreatedAt time.Time
	ExpiresAt *time.Time
	LastUsed  *time.Time
}

// IsExpired checks if the token has expired.
func (t *APIToken) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// CanPerform checks if the token has a specific ability.
func (t *APIToken) CanPerform(ability string) bool {
	// Check for wildcard
	for _, a := range t.Abilities {
		if a == "*" {
			return true
		}
		if a == ability {
			return true
		}
	}
	return false
}

// APITokenStore defines the interface for API token storage.
type APITokenStore interface {
	// Create creates a new API token
	Create(ctx context.Context, token *APIToken) error

	// FindByToken retrieves a token by its value
	FindByToken(ctx context.Context, token string) (*APIToken, error)

	// Update updates a token
	Update(ctx context.Context, token *APIToken) error

	// Delete deletes a token
	Delete(ctx context.Context, tokenID string) error

	// DeleteByUserID deletes all tokens for a user
	DeleteByUserID(ctx context.Context, userID string) error

	// FindByUserID finds all tokens for a user
	FindByUserID(ctx context.Context, userID string) ([]*APIToken, error)
}

// MemoryAPITokenStore is an in-memory API token store for testing.
type MemoryAPITokenStore struct {
	tokens map[string]*APIToken
	mu     sync.RWMutex
}

// NewMemoryAPITokenStore creates a new in-memory API token store.
func NewMemoryAPITokenStore() *MemoryAPITokenStore {
	return &MemoryAPITokenStore{
		tokens: make(map[string]*APIToken),
	}
}

// Create creates a new API token.
func (s *MemoryAPITokenStore) Create(ctx context.Context, token *APIToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

// FindByToken retrieves a token by its value.
func (s *MemoryAPITokenStore) FindByToken(ctx context.Context, token string) (*APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	apiToken, exists := s.tokens[token]
	if !exists {
		return nil, ErrInvalidAPIToken
	}

	if apiToken.IsExpired() {
		return nil, ErrInvalidAPIToken
	}

	return apiToken, nil
}

// Update updates a token.
func (s *MemoryAPITokenStore) Update(ctx context.Context, token *APIToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[token.Token]; !exists {
		return ErrInvalidAPIToken
	}

	s.tokens[token.Token] = token
	return nil
}

// Delete deletes a token.
func (s *MemoryAPITokenStore) Delete(ctx context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, apiToken := range s.tokens {
		if apiToken.ID == tokenID {
			delete(s.tokens, token)
			return nil
		}
	}

	return ErrInvalidAPIToken
}

// DeleteByUserID deletes all tokens for a user.
func (s *MemoryAPITokenStore) DeleteByUserID(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, apiToken := range s.tokens {
		if apiToken.UserID == userID {
			delete(s.tokens, token)
		}
	}

	return nil
}

// FindByUserID finds all tokens for a user.
func (s *MemoryAPITokenStore) FindByUserID(ctx context.Context, userID string) ([]*APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tokens []*APIToken
	for _, apiToken := range s.tokens {
		if apiToken.UserID == userID {
			tokens = append(tokens, apiToken)
		}
	}

	return tokens, nil
}

// APITokenGuard implements Guard using API tokens.
type APITokenGuard struct {
	name         string
	userProvider UserProvider
	tokenStore   APITokenStore
}

// NewAPITokenGuard creates a new API token guard.
func NewAPITokenGuard(name string, provider UserProvider, store APITokenStore) *APITokenGuard {
	return &APITokenGuard{
		name:         name,
		userProvider: provider,
		tokenStore:   store,
	}
}

// Authenticate is not supported for API token guard.
func (g *APITokenGuard) Authenticate(ctx context.Context, credentials interface{}) (User, error) {
	return nil, errors.New("authenticate not supported for API token guard")
}

// Validate validates an API token and returns the associated user.
func (g *APITokenGuard) Validate(ctx context.Context, token string) (User, error) {
	apiToken, err := g.tokenStore.FindByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Update last used
	now := time.Now()
	apiToken.LastUsed = &now
	_ = g.tokenStore.Update(ctx, apiToken)

	// Find user
	user, err := g.userProvider.FindByID(ctx, apiToken.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check if account is locked
	if baseUser, ok := user.(*BaseUser); ok {
		if baseUser.IsLocked() {
			return nil, ErrAccountLocked
		}
	}

	return user, nil
}

// Name returns the name of the guard.
func (g *APITokenGuard) Name() string {
	return g.name
}

// CreateToken creates a new API token for a user.
func (g *APITokenGuard) CreateToken(ctx context.Context, user User, name string, abilities []string, expiresAt *time.Time) (*APIToken, error) {
	token, err := generateAPIToken()
	if err != nil {
		return nil, err
	}

	apiToken := &APIToken{
		ID:        generateAPITokenID(),
		UserID:    user.GetID(),
		Token:     token,
		Name:      name,
		Abilities: abilities,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	err = g.tokenStore.Create(ctx, apiToken)
	if err != nil {
		return nil, err
	}

	return apiToken, nil
}

// RevokeToken revokes a token by its ID.
func (g *APITokenGuard) RevokeToken(ctx context.Context, tokenID string) error {
	return g.tokenStore.Delete(ctx, tokenID)
}

// RevokeAllTokens revokes all tokens for a user.
func (g *APITokenGuard) RevokeAllTokens(ctx context.Context, user User) error {
	return g.tokenStore.DeleteByUserID(ctx, user.GetID())
}

// GetUserTokens retrieves all tokens for a user.
func (g *APITokenGuard) GetUserTokens(ctx context.Context, user User) ([]*APIToken, error) {
	return g.tokenStore.FindByUserID(ctx, user.GetID())
}

// generateAPIToken generates a random API token.
func generateAPIToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateAPITokenID generates a unique token ID.
func generateAPITokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
