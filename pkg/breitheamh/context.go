package breitheamh

import (
	"context"
	"errors"
)

var (
	// ErrNoAuthenticatedUser indicates no user is authenticated in the context
	ErrNoAuthenticatedUser = errors.New("no authenticated user in context")
)

// AuthContext provides context-based authentication helpers.
type AuthContext struct {
	guard Guard
}

// NewAuthContext creates a new auth context helper.
func NewAuthContext(guard Guard) *AuthContext {
	return &AuthContext{
		guard: guard,
	}
}

// Login authenticates and stores the user in context.
func (ac *AuthContext) Login(ctx context.Context, credentials interface{}) (context.Context, User, error) {
	user, err := ac.guard.Authenticate(ctx, credentials)
	if err != nil {
		return ctx, nil, err
	}

	ctx = context.WithValue(ctx, UserContextKey, user)
	return ctx, user, nil
}

// User retrieves the authenticated user from context.
func (ac *AuthContext) User(ctx context.Context) (User, error) {
	user := GetUser(ctx)
	if user == nil {
		return nil, ErrNoAuthenticatedUser
	}
	return user, nil
}

// Check verifies if a user is authenticated.
func (ac *AuthContext) Check(ctx context.Context) bool {
	return GetUser(ctx) != nil
}

// Guest checks if there is no authenticated user.
func (ac *AuthContext) Guest(ctx context.Context) bool {
	return GetUser(ctx) == nil
}

// ID returns the authenticated user's ID.
func (ac *AuthContext) ID(ctx context.Context) (string, error) {
	user, err := ac.User(ctx)
	if err != nil {
		return "", err
	}
	return user.GetID(), nil
}

// Attempt tries to authenticate but doesn't store in context.
func (ac *AuthContext) Attempt(ctx context.Context, credentials interface{}) (User, error) {
	return ac.guard.Authenticate(ctx, credentials)
}

// LoginUsingID authenticates a user by ID and stores in context.
func (ac *AuthContext) LoginUsingID(
	ctx context.Context,
	provider UserProvider,
	userID string,
) (context.Context, User, error) {
	user, err := provider.FindByID(ctx, userID)
	if err != nil {
		return ctx, nil, err
	}

	ctx = context.WithValue(ctx, UserContextKey, user)
	return ctx, user, nil
}

// Once authenticates without storing in session (for single request).
func (ac *AuthContext) Once(ctx context.Context, credentials interface{}) (context.Context, User, error) {
	user, err := ac.guard.Authenticate(ctx, credentials)
	if err != nil {
		return ctx, nil, err
	}

	ctx = context.WithValue(ctx, UserContextKey, user)
	return ctx, user, nil
}

// SetUser manually sets the authenticated user in context.
func (ac *AuthContext) SetUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, UserContextKey, user)
}

// Logout removes the authenticated user from context.
func (ac *AuthContext) Logout(ctx context.Context) context.Context {
	return context.WithValue(ctx, UserContextKey, nil)
}

// AuthManager provides centralized authentication management.
type AuthManager struct {
	guards       map[string]Guard
	defaultGuard string
}

// NewAuthManager creates a new authentication manager.
func NewAuthManager() *AuthManager {
	return &AuthManager{
		guards: make(map[string]Guard),
	}
}

// Guard returns a specific guard by name.
func (m *AuthManager) Guard(name string) Guard {
	if guard, exists := m.guards[name]; exists {
		return guard
	}
	return nil
}

// RegisterGuard registers a guard.
func (m *AuthManager) RegisterGuard(name string, guard Guard) {
	m.guards[name] = guard
	if m.defaultGuard == "" {
		m.defaultGuard = name
	}
}

// SetDefaultGuard sets the default guard.
func (m *AuthManager) SetDefaultGuard(name string) {
	m.defaultGuard = name
}

// DefaultGuard returns the default guard.
func (m *AuthManager) DefaultGuard() Guard {
	if m.defaultGuard == "" {
		return nil
	}
	return m.guards[m.defaultGuard]
}

// Login authenticates using the default guard.
func (m *AuthManager) Login(ctx context.Context, credentials interface{}) (context.Context, User, error) {
	guard := m.DefaultGuard()
	if guard == nil {
		return ctx, nil, errors.New("no default guard configured")
	}

	authCtx := NewAuthContext(guard)
	return authCtx.Login(ctx, credentials)
}

// Attempt tries authentication without storing in context.
func (m *AuthManager) Attempt(ctx context.Context, credentials interface{}) (User, error) {
	guard := m.DefaultGuard()
	if guard == nil {
		return nil, errors.New("no default guard configured")
	}

	authCtx := NewAuthContext(guard)
	return authCtx.Attempt(ctx, credentials)
}

// User retrieves the authenticated user.
func (m *AuthManager) User(ctx context.Context) (User, error) {
	guard := m.DefaultGuard()
	if guard == nil {
		return nil, errors.New("no default guard configured")
	}

	authCtx := NewAuthContext(guard)
	return authCtx.User(ctx)
}

// Check verifies if a user is authenticated.
func (m *AuthManager) Check(ctx context.Context) bool {
	guard := m.DefaultGuard()
	if guard == nil {
		return false
	}

	authCtx := NewAuthContext(guard)
	return authCtx.Check(ctx)
}

// Guest checks if there is no authenticated user.
func (m *AuthManager) Guest(ctx context.Context) bool {
	return !m.Check(ctx)
}

// SetUser manually sets the authenticated user.
func (m *AuthManager) SetUser(ctx context.Context, user User) context.Context {
	guard := m.DefaultGuard()
	if guard == nil {
		return ctx
	}

	authCtx := NewAuthContext(guard)
	return authCtx.SetUser(ctx, user)
}

// Logout removes the authenticated user.
func (m *AuthManager) Logout(ctx context.Context) context.Context {
	guard := m.DefaultGuard()
	if guard == nil {
		return ctx
	}

	authCtx := NewAuthContext(guard)
	return authCtx.Logout(ctx)
}
