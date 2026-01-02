package breitheamh

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

var (
	// ErrInvalidToken indicates that the token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpiredToken indicates that the token has expired
	ErrExpiredToken = errors.New("token has expired")

	// ErrTokenRevoked indicates that the token has been revoked
	ErrTokenRevoked = errors.New("token has been revoked")
)

// TokenClaims represents the claims in a JWT or other token.
type TokenClaims struct {
	UserID    string
	Email     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	TokenID   string
}

// Token represents an authentication token.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

// RefreshToken represents a refresh token for token rotation.
type RefreshToken struct {
	ID          string
	UserID      string
	Token       string
	ParentToken *string
	Revoked     bool
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// TokenManager handles token generation, validation, and revocation.
type TokenManager interface {
	// Generate creates a new access and refresh token pair
	Generate(user User, ttl time.Duration) (*Token, error)

	// Validate validates an access token and returns the claims
	Validate(token string) (*TokenClaims, error)

	// Refresh creates a new token pair using a refresh token
	Refresh(refreshToken string) (*Token, error)

	// Revoke revokes a refresh token
	Revoke(refreshToken string) error

	// IsRevoked checks if a refresh token is revoked
	IsRevoked(refreshToken string) (bool, error)
}

// generateTokenID generates a random token ID.
func generateTokenID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateRefreshToken generates a random refresh token.
func generateRefreshToken() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
