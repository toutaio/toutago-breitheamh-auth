package breitheamh

import "time"

// Role represents a user role with associated permissions.
type Role struct {
	ID          string
	Name        string
	GuardName   string
	ParentID    *string
	Permissions []Permission
	CreatedAt   time.Time
}

// Permission represents a permission that can be assigned to users or roles.
type Permission struct {
	ID        string
	Name      string
	GuardName string
	GroupName string
	CreatedAt time.Time
}

// HasPermission checks if the role has a specific permission.
func (r *Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if matchesPermission(p.Name, permission) {
			return true
		}
	}
	return false
}

// matchesPermission checks if a permission pattern matches the required permission.
// Supports wildcard matching (e.g., "posts.*" matches "posts.create").
func matchesPermission(pattern, permission string) bool {
	if pattern == permission {
		return true
	}

	// Simple wildcard matching for now (will be enhanced with trie-based matching)
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(permission) >= len(prefix) && permission[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}
