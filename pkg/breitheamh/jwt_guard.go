package breitheamh

import (
	"context"
	"errors"
)

var (
	// ErrInvalidCredentials indicates that the provided credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrUserNotFound indicates that the user was not found
	ErrUserNotFound = errors.New("user not found")

	// ErrAccountLocked indicates that the user account is locked
	ErrAccountLocked = errors.New("account is locked")
)

// Credentials represents authentication credentials.
type Credentials struct {
	Email    string
	Password string
}

// JWTGuard implements Guard using JWT tokens.
type JWTGuard struct {
	name          string
	userProvider  UserProvider
	tokenManager  TokenManager
	hasher        *Hasher
}

// NewJWTGuard creates a new JWT guard.
func NewJWTGuard(name string, provider UserProvider, tokenManager TokenManager, hasher *Hasher) *JWTGuard {
	return &JWTGuard{
		name:         name,
		userProvider: provider,
		tokenManager: tokenManager,
		hasher:       hasher,
	}
}

// Authenticate attempts to authenticate a user with credentials.
func (g *JWTGuard) Authenticate(ctx context.Context, credentials interface{}) (User, error) {
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

// Validate validates a token and returns the associated user.
func (g *JWTGuard) Validate(ctx context.Context, token string) (User, error) {
	claims, err := g.tokenManager.Validate(token)
	if err != nil {
		return nil, err
	}

	// Find user by ID
	user, err := g.userProvider.FindByID(ctx, claims.UserID)
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

// Logout logs out a user by revoking their tokens.
func (g *JWTGuard) Logout(ctx context.Context, user User) error {
	// In a JWT system, logout is typically handled client-side by discarding the token
	// For refresh token rotation, we would revoke the refresh token here
	// This is a placeholder for future implementation
	return nil
}

// Name returns the name of the guard.
func (g *JWTGuard) Name() string {
	return g.name
}

// Attempt attempts to authenticate and returns a token on success.
func (g *JWTGuard) Attempt(ctx context.Context, credentials interface{}) (User, *Token, error) {
	user, err := g.Authenticate(ctx, credentials)
	if err != nil {
		return nil, nil, err
	}

	token, err := g.tokenManager.Generate(user, 0)
	if err != nil {
		return nil, nil, err
	}

	return user, token, nil
}
