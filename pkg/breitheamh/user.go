package breitheamh

import "context"

// User represents an authenticated user with roles and permissions.
// Implementations should provide access to user identity and authorization data.
type User interface {
	// GetID returns the unique identifier for the user
	GetID() string

	// GetPassword returns the hashed password for the user
	GetPassword() string

	// HasRole checks if the user has the specified role
	HasRole(role string) bool

	// HasPermission checks if the user has the specified permission
	HasPermission(permission string) bool

	// GetRoles returns all roles assigned to the user
	GetRoles() []Role

	// GetPermissions returns all permissions assigned to the user (direct and via roles)
	GetPermissions() []Permission
}

// Authenticatable represents any entity that can be authenticated.
type Authenticatable interface {
	// GetAuthIdentifier returns the unique identifier used for authentication
	GetAuthIdentifier() string

	// GetAuthPassword returns the password used for authentication
	GetAuthPassword() string
}

// UserProvider defines the interface for user storage and retrieval.
// Implementations can use any storage backend (SQL, NoSQL, LDAP, etc.).
type UserProvider interface {
	// FindByID retrieves a user by their unique identifier
	FindByID(ctx context.Context, id string) (User, error)

	// FindByCredentials retrieves a user by their credentials (e.g., email, username)
	FindByCredentials(ctx context.Context, credentials map[string]interface{}) (User, error)

	// UpdateUser updates the user in the storage backend
	UpdateUser(ctx context.Context, user User) error
}
