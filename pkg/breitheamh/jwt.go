package breitheamh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// JWTConfig contains configuration for JWT token generation.
type JWTConfig struct {
	SecretKey         []byte
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	Issuer            string
	EnableRefresh     bool
}

// DefaultJWTConfig returns a default JWT configuration.
func DefaultJWTConfig(secretKey string) *JWTConfig {
	return &JWTConfig{
		SecretKey:         []byte(secretKey),
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
		Issuer:            "breitheamh-auth",
		EnableRefresh:     true,
	}
}

// jwtHeader represents the JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// jwtPayload represents the JWT payload.
type jwtPayload struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
	Jti string `json:"jti"`
	Email string `json:"email,omitempty"`
}

// JWTTokenManager implements TokenManager using JWT.
type JWTTokenManager struct {
	config         *JWTConfig
	refreshTokens  map[string]*RefreshToken
	mu             sync.RWMutex
}

// NewJWTTokenManager creates a new JWT token manager.
func NewJWTTokenManager(config *JWTConfig) *JWTTokenManager {
	return &JWTTokenManager{
		config:        config,
		refreshTokens: make(map[string]*RefreshToken),
	}
}

// Generate creates a new access and refresh token pair.
func (tm *JWTTokenManager) Generate(user User, ttl time.Duration) (*Token, error) {
	if ttl == 0 {
		ttl = tm.config.AccessTokenTTL
	}

	// Generate access token
	tokenID, err := generateTokenID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	payload := jwtPayload{
		Sub:   user.GetID(),
		Iat:   now.Unix(),
		Exp:   expiresAt.Unix(),
		Iss:   tm.config.Issuer,
		Jti:   tokenID,
		Email: user.GetAuthIdentifier(),
	}

	accessToken, err := tm.encodeJWT(payload)
	if err != nil {
		return nil, err
	}

	token := &Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ttl.Seconds()),
	}

	// Generate refresh token if enabled
	if tm.config.EnableRefresh {
		refreshTokenStr, err := generateRefreshToken()
		if err != nil {
			return nil, err
		}

		refreshToken := &RefreshToken{
			ID:        tokenID,
			UserID:    user.GetID(),
			Token:     refreshTokenStr,
			Revoked:   false,
			ExpiresAt: now.Add(tm.config.RefreshTokenTTL),
			CreatedAt: now,
		}

		tm.mu.Lock()
		tm.refreshTokens[refreshTokenStr] = refreshToken
		tm.mu.Unlock()

		token.RefreshToken = refreshTokenStr
	}

	return token, nil
}

// Validate validates an access token and returns the claims.
func (tm *JWTTokenManager) Validate(token string) (*TokenClaims, error) {
	payload, err := tm.decodeJWT(token)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().Unix() > payload.Exp {
		return nil, ErrExpiredToken
	}

	claims := &TokenClaims{
		UserID:    payload.Sub,
		Email:     payload.Email,
		IssuedAt:  time.Unix(payload.Iat, 0),
		ExpiresAt: time.Unix(payload.Exp, 0),
		TokenID:   payload.Jti,
	}

	return claims, nil
}

// Refresh creates a new token pair using a refresh token.
func (tm *JWTTokenManager) Refresh(refreshTokenStr string) (*Token, error) {
	tm.mu.RLock()
	refreshToken, exists := tm.refreshTokens[refreshTokenStr]
	tm.mu.RUnlock()

	if !exists {
		return nil, ErrInvalidToken
	}

	if refreshToken.Revoked {
		return nil, ErrTokenRevoked
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	// Create a minimal user object for token generation
	// In a real implementation, this would fetch the full user from storage
	user := &BaseUser{
		ID:    refreshToken.UserID,
		Email: "", // Would be populated from storage
	}

	// Revoke the old refresh token
	tm.mu.Lock()
	refreshToken.Revoked = true
	tm.mu.Unlock()

	// Generate new token pair
	return tm.Generate(user, tm.config.AccessTokenTTL)
}

// Revoke revokes a refresh token.
func (tm *JWTTokenManager) Revoke(refreshTokenStr string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	refreshToken, exists := tm.refreshTokens[refreshTokenStr]
	if !exists {
		return ErrInvalidToken
	}

	refreshToken.Revoked = true
	return nil
}

// IsRevoked checks if a refresh token is revoked.
func (tm *JWTTokenManager) IsRevoked(refreshTokenStr string) (bool, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	refreshToken, exists := tm.refreshTokens[refreshTokenStr]
	if !exists {
		return false, ErrInvalidToken
	}

	return refreshToken.Revoked, nil
}

// encodeJWT encodes a JWT token.
func (tm *JWTTokenManager) encodeJWT(payload jwtPayload) (string, error) {
	header := jwtHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := headerEncoded + "." + payloadEncoded
	signature := tm.sign(message)

	return message + "." + signature, nil
}

// decodeJWT decodes and validates a JWT token.
func (tm *JWTTokenManager) decodeJWT(token string) (*jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerEncoded, payloadEncoded, signature := parts[0], parts[1], parts[2]

	// Verify signature
	message := headerEncoded + "." + payloadEncoded
	expectedSignature := tm.sign(message)
	if signature != expectedSignature {
		return nil, errors.New("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &payload, nil
}

// sign creates an HMAC signature for the message.
func (tm *JWTTokenManager) sign(message string) string {
	h := hmac.New(sha256.New, tm.config.SecretKey)
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
