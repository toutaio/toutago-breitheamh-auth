package breitheamh

import "context"

// Guard represents an authentication guard responsible for authenticating users.
// Different guards can implement different authentication strategies (JWT, session, API token, etc.).
type Guard interface {
	// Authenticate attempts to authenticate a user with the provided credentials
	Authenticate(ctx context.Context, credentials interface{}) (User, error)

	// Validate validates a token and returns the associated user
	Validate(ctx context.Context, token string) (User, error)

	// Logout logs out a user and invalidates their authentication state
	Logout(ctx context.Context, user User) error

	// Name returns the name of the guard
	Name() string
}

// GuardManager manages multiple authentication guards.
type GuardManager interface {
	// Guard returns a guard by name
	Guard(name string) Guard

	// RegisterGuard registers a new guard
	RegisterGuard(name string, guard Guard)

	// DefaultGuard returns the default guard
	DefaultGuard() Guard

	// SetDefaultGuard sets the default guard
	SetDefaultGuard(name string)
}
