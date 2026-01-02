package breitheamh

import "time"

// BaseUser provides a default implementation of the User interface.
// Applications can embed this struct and extend it with additional fields.
type BaseUser struct {
	ID                string
	Email             string
	Password          string
	RememberToken     string
	EmailVerifiedAt   *time.Time
	LockedUntil       *time.Time
	FailedLoginCount  int
	Roles             []Role
	DirectPermissions []Permission
	CreatedAt         time.Time
	UpdatedAt         time.Time

	// Cached computed permissions (from roles + direct)
	cachedPermissions []Permission
	permissionMatcher *PermissionMatcher
}

// NewBaseUser creates a new base user.
func NewBaseUser(id, email, password string) *BaseUser {
	return &BaseUser{
		ID:                id,
		Email:             email,
		Password:          password,
		Roles:             []Role{},
		DirectPermissions: []Permission{},
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		permissionMatcher: NewPermissionMatcher(),
	}
}

// GetID returns the user's unique identifier.
func (u *BaseUser) GetID() string {
	return u.ID
}

// GetPassword returns the user's hashed password.
func (u *BaseUser) GetPassword() string {
	return u.Password
}

// GetAuthIdentifier returns the identifier used for authentication.
func (u *BaseUser) GetAuthIdentifier() string {
	return u.Email
}

// GetAuthPassword returns the password used for authentication.
func (u *BaseUser) GetAuthPassword() string {
	return u.Password
}

// HasRole checks if the user has the specified role.
func (u *BaseUser) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
		// Check parent roles recursively
		if u.hasRoleRecursive(roleName, role) {
			return true
		}
	}
	return false
}

// hasRoleRecursive checks role hierarchy for the specified role.
func (u *BaseUser) hasRoleRecursive(roleName string, role Role) bool {
	if role.ParentID == nil {
		return false
	}
	// Note: This is a simplified check. Full implementation would need
	// to load parent roles from storage.
	return false
}

// HasPermission checks if the user has the specified permission.
func (u *BaseUser) HasPermission(permission string) bool {
	// Check direct permissions
	for _, p := range u.DirectPermissions {
		if u.permissionMatcher.Match(p.Name, permission) {
			return true
		}
	}

	// Check permissions from roles
	for _, role := range u.Roles {
		if role.HasPermission(permission) {
			return true
		}
	}

	return false
}

// GetRoles returns all roles assigned to the user.
func (u *BaseUser) GetRoles() []Role {
	return u.Roles
}

// GetPermissions returns all permissions (direct and from roles).
func (u *BaseUser) GetPermissions() []Permission {
	if u.cachedPermissions != nil {
		return u.cachedPermissions
	}

	permMap := make(map[string]Permission)

	// Add direct permissions
	for _, p := range u.DirectPermissions {
		permMap[p.ID] = p
	}

	// Add permissions from roles
	for _, role := range u.Roles {
		for _, p := range role.Permissions {
			permMap[p.ID] = p
		}
	}

	// Convert map to slice
	permissions := make([]Permission, 0, len(permMap))
	for _, p := range permMap {
		permissions = append(permissions, p)
	}

	u.cachedPermissions = permissions
	return permissions
}

// AssignRole assigns a role to the user.
func (u *BaseUser) AssignRole(role Role) {
	u.Roles = append(u.Roles, role)
	u.cachedPermissions = nil // Invalidate cache
	u.UpdatedAt = time.Now()
}

// RemoveRole removes a role from the user.
func (u *BaseUser) RemoveRole(roleName string) {
	for i, role := range u.Roles {
		if role.Name == roleName {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			u.cachedPermissions = nil // Invalidate cache
			u.UpdatedAt = time.Now()
			return
		}
	}
}

// GivePermission assigns a permission directly to the user.
func (u *BaseUser) GivePermission(permission Permission) {
	u.DirectPermissions = append(u.DirectPermissions, permission)
	u.cachedPermissions = nil // Invalidate cache
	u.UpdatedAt = time.Now()
}

// RevokePermission removes a direct permission from the user.
func (u *BaseUser) RevokePermission(permissionName string) {
	for i, p := range u.DirectPermissions {
		if p.Name == permissionName {
			u.DirectPermissions = append(u.DirectPermissions[:i], u.DirectPermissions[i+1:]...)
			u.cachedPermissions = nil // Invalidate cache
			u.UpdatedAt = time.Now()
			return
		}
	}
}

// IsLocked checks if the user account is currently locked.
func (u *BaseUser) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// IsEmailVerified checks if the user's email is verified.
func (u *BaseUser) IsEmailVerified() bool {
	return u.EmailVerifiedAt != nil
}
