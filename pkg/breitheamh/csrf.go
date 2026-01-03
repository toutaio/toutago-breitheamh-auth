package breitheamh

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// ErrInvalidCSRFToken is returned when a CSRF token is invalid
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
	// ErrExpiredCSRFToken is returned when a CSRF token has expired
	ErrExpiredCSRFToken = errors.New("expired CSRF token")
)

// CSRFTokenManager manages CSRF token generation and validation
type CSRFTokenManager struct {
	tokens   map[string]*csrfToken
	mu       sync.RWMutex
	ttl      time.Duration
	tokenLen int
}

type csrfToken struct {
	value     string
	createdAt time.Time
}

// NewCSRFTokenManager creates a new CSRF token manager
func NewCSRFTokenManager(ttl time.Duration, tokenLen int) *CSRFTokenManager {
	if tokenLen <= 0 {
		tokenLen = 32
	}
	
	manager := &CSRFTokenManager{
		tokens:   make(map[string]*csrfToken),
		ttl:      ttl,
		tokenLen: tokenLen,
	}
	
	go manager.cleanup()
	
	return manager
}

// GenerateToken generates a new CSRF token for the given session ID
func (m *CSRFTokenManager) GenerateToken(sessionID string) (string, error) {
	bytes := make([]byte, m.tokenLen)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	token := base64.URLEncoding.EncodeToString(bytes)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.tokens[sessionID] = &csrfToken{
		value:     token,
		createdAt: time.Now(),
	}
	
	return token, nil
}

// ValidateToken validates a CSRF token for the given session ID
func (m *CSRFTokenManager) ValidateToken(sessionID, token string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	stored, exists := m.tokens[sessionID]
	if !exists {
		return ErrInvalidCSRFToken
	}
	
	if time.Since(stored.createdAt) > m.ttl {
		return ErrExpiredCSRFToken
	}
	
	if subtle.ConstantTimeCompare([]byte(stored.value), []byte(token)) != 1 {
		return ErrInvalidCSRFToken
	}
	
	return nil
}

// InvalidateToken removes a CSRF token for the given session ID
func (m *CSRFTokenManager) InvalidateToken(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, sessionID)
}

// RefreshToken generates a new token for an existing session
func (m *CSRFTokenManager) RefreshToken(sessionID string) (string, error) {
	m.InvalidateToken(sessionID)
	return m.GenerateToken(sessionID)
}

func (m *CSRFTokenManager) cleanup() {
	ticker := time.NewTicker(m.ttl)
	defer ticker.Stop()
	
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for key, token := range m.tokens {
			if now.Sub(token.createdAt) > m.ttl {
				delete(m.tokens, key)
			}
		}
		m.mu.Unlock()
	}
}
