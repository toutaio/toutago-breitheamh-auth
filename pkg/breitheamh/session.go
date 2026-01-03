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
	// ErrSessionNotFound indicates that the session was not found
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired indicates that the session has expired
	ErrSessionExpired = errors.New("session has expired")
)

// Session represents a user session.
type Session struct {
	ID        string
	UserID    string
	Data      map[string]interface{}
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionStore defines the interface for session storage.
type SessionStore interface {
	// Create creates a new session
	Create(ctx context.Context, session *Session) error

	// Get retrieves a session by ID
	Get(ctx context.Context, sessionID string) (*Session, error)

	// Update updates a session
	Update(ctx context.Context, session *Session) error

	// Delete deletes a session
	Delete(ctx context.Context, sessionID string) error

	// DeleteByUserID deletes all sessions for a user
	DeleteByUserID(ctx context.Context, userID string) error

	// Cleanup removes expired sessions
	Cleanup(ctx context.Context) error
}

// MemorySessionStore is an in-memory session store for testing.
type MemorySessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create creates a new session.
func (s *MemorySessionStore) Create(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

// Get retrieves a session by ID.
func (s *MemorySessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// Update updates a session.
func (s *MemorySessionStore) Update(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.ID]; !exists {
		return ErrSessionNotFound
	}

	s.sessions[session.ID] = session
	return nil
}

// Delete deletes a session.
func (s *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// DeleteByUserID deletes all sessions for a user.
func (s *MemorySessionStore) DeleteByUserID(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// Cleanup removes expired sessions.
func (s *MemorySessionStore) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	return nil
}

// SessionConfig contains configuration for session management.
type SessionConfig struct {
	SessionTTL time.Duration
	CookieName string
}

// DefaultSessionConfig returns default session configuration.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		SessionTTL: 24 * time.Hour,
		CookieName: "session_id",
	}
}

// SessionGuard implements Guard using sessions.
type SessionGuard struct {
	name         string
	userProvider UserProvider
	sessionStore SessionStore
	hasher       *Hasher
	config       *SessionConfig
}

// NewSessionGuard creates a new session guard.
func NewSessionGuard(
	name string,
	provider UserProvider,
	store SessionStore,
	hasher *Hasher,
	config *SessionConfig,
) *SessionGuard {
	if config == nil {
		config = DefaultSessionConfig()
	}

	return &SessionGuard{
		name:         name,
		userProvider: provider,
		sessionStore: store,
		hasher:       hasher,
		config:       config,
	}
}

// Authenticate attempts to authenticate a user with credentials.
func (g *SessionGuard) Authenticate(ctx context.Context, credentials interface{}) (User, error) {
	creds, ok := credentials.(Credentials)
	if !ok {
		credsMap, ok := credentials.(map[string]interface{})
		if !ok {
			return nil, ErrInvalidCredentials
		}

		email, _ := credsMap["email"].(string)
		password, _ := credsMap["password"].(string)
		creds = Credentials{Email: email, Password: password}
	}

	// Find user by credentials
	user, err := g.userProvider.FindByCredentials(ctx, map[string]interface{}{
		"email": creds.Email,
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check if account is locked
	if baseUser, ok := user.(*BaseUser); ok {
		if baseUser.IsLocked() {
			return nil, ErrAccountLocked
		}
	}

	// Verify password
	err = g.hasher.Verify(creds.Password, user.GetPassword())
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// Validate validates a session ID and returns the associated user.
func (g *SessionGuard) Validate(ctx context.Context, sessionID string) (User, error) {
	session, err := g.sessionStore.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Update last seen
	session.LastSeen = time.Now()
	_ = g.sessionStore.Update(ctx, session)

	// Find user
	user, err := g.userProvider.FindByID(ctx, session.UserID)
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

// Logout logs out a user by deleting their session.
func (g *SessionGuard) Logout(ctx context.Context, user User) error {
	return g.sessionStore.DeleteByUserID(ctx, user.GetID())
}

// Name returns the name of the guard.
func (g *SessionGuard) Name() string {
	return g.name
}

// CreateSession creates a new session for a user.
func (g *SessionGuard) CreateSession(ctx context.Context, user User) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    user.GetID(),
		Data:      make(map[string]interface{}),
		CreatedAt: now,
		ExpiresAt: now.Add(g.config.SessionTTL),
		LastSeen:  now,
	}

	err = g.sessionStore.Create(ctx, session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// Login authenticates a user and creates a session.
func (g *SessionGuard) Login(ctx context.Context, credentials interface{}) (User, *Session, error) {
	user, err := g.Authenticate(ctx, credentials)
	if err != nil {
		return nil, nil, err
	}

	session, err := g.CreateSession(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

// generateSessionID generates a random session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
