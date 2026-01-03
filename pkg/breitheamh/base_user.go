package breitheamh

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

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
	SuperAdmin        bool // When true, bypasses all permission and role checks
	CreatedAt         time.Time
	UpdatedAt         time.Time

	// Cached computed permissions (from roles + direct)
	cachedPermissions []Permission
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
	// Super admins bypass all checks
	if u.SuperAdmin {
		return true
	}

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

// HasRoleForGuard checks if the user has the specified role for a specific guard.
func (u *BaseUser) HasRoleForGuard(roleName, guardName string) bool {
	// Super admins bypass all checks
	if u.SuperAdmin {
		return true
	}

	for _, role := range u.Roles {
		if role.Name == roleName && role.GuardName == guardName {
			return true
		}
	}
	return false
}

// hasRoleRecursive checks role hierarchy for the specified role.
func (u *BaseUser) hasRoleRecursive(_ string, role Role) bool {
	if role.ParentID == nil {
		return false
	}
	// Note: This is a simplified check. Full implementation would need
	// to load parent roles from storage.
	return false
}

// HasPermission checks if the user has the specified permission.
func (u *BaseUser) HasPermission(permission string) bool {
	// Super admins bypass all checks
	if u.SuperAdmin {
		return true
	}

	// Check direct permissions
	for _, p := range u.DirectPermissions {
		if matchesPermissionSimple(p.Name, permission) {
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

// HasPermissionForGuard checks if the user has the specified permission for a specific guard.
func (u *BaseUser) HasPermissionForGuard(permission, guardName string) bool {
	// Super admins bypass all checks
	if u.SuperAdmin {
		return true
	}

	// Check direct permissions
	for _, p := range u.DirectPermissions {
		if p.GuardName == guardName && matchesPermissionSimple(p.Name, permission) {
			return true
		}
	}

	// Check permissions from roles matching the guard
	for _, role := range u.Roles {
		if role.GuardName == guardName && role.HasPermission(permission) {
			return true
		}
	}

	return false
}

// GetRoles returns all roles assigned to the user.
func (u *BaseUser) GetRoles() []Role {
	return u.Roles
}

// GetRolesForGuard returns all roles assigned to the user for a specific guard.
func (u *BaseUser) GetRolesForGuard(guardName string) []Role {
	var filtered []Role
	for _, role := range u.Roles {
		if role.GuardName == guardName {
			filtered = append(filtered, role)
		}
	}
	return filtered
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

// GetPermissionsForGuard returns all permissions for a specific guard (direct and from roles).
func (u *BaseUser) GetPermissionsForGuard(guardName string) []Permission {
	permMap := make(map[string]Permission)

	// Add direct permissions matching the guard
	for _, p := range u.DirectPermissions {
		if p.GuardName == guardName {
			permMap[p.ID] = p
		}
	}

	// Add permissions from roles matching the guard
	for _, role := range u.Roles {
		if role.GuardName == guardName {
			for _, p := range role.Permissions {
				permMap[p.ID] = p
			}
		}
	}

	// Convert map to slice
	permissions := make([]Permission, 0, len(permMap))
	for _, p := range permMap {
		permissions = append(permissions, p)
	}

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

// IsSuperAdmin checks if the user has super admin privileges.
// Super admins bypass all permission and role checks.
func (u *BaseUser) IsSuperAdmin() bool {
	return u.SuperAdmin
}

// SetSuperAdmin sets the super admin status for the user.
func (u *BaseUser) SetSuperAdmin(isSuperAdmin bool) {
	u.SuperAdmin = isSuperAdmin
	u.UpdatedAt = time.Now()
}

// RecordFailedLogin increments the failed login counter.
func (u *BaseUser) RecordFailedLogin() {
	u.FailedLoginCount++
	// Lock account after 5 failed attempts for 15 minutes
	if u.FailedLoginCount >= 5 {
		lockUntil := time.Now().Add(15 * time.Minute)
		u.LockedUntil = &lockUntil
	}
	u.UpdatedAt = time.Now()
}

// ResetFailedLogins resets the failed login counter.
func (u *BaseUser) ResetFailedLogins() {
	u.FailedLoginCount = 0
	u.UpdatedAt = time.Now()
}

// Unlock unlocks the user account and resets failed login attempts.
func (u *BaseUser) Unlock() {
	u.LockedUntil = nil
	u.FailedLoginCount = 0
	u.UpdatedAt = time.Now()
}

// GenerateEmailVerificationToken generates a unique token for email verification.
func (u *BaseUser) GenerateEmailVerificationToken() string {
	// Generate a secure random token (simplified version)
	token := generateSecureToken(32)
	u.RememberToken = token
	u.UpdatedAt = time.Now()
	return token
}

// VerifyEmailWithToken verifies the email using the provided token.
func (u *BaseUser) VerifyEmailWithToken(token string) bool {
	if u.RememberToken == "" || u.RememberToken != token {
		return false
	}
	now := time.Now()
	u.EmailVerifiedAt = &now
	u.RememberToken = "" // Clear token after use
	u.UpdatedAt = time.Now()
	return true
}

// GrantPermission is an alias for GivePermission for consistency.
func (u *BaseUser) GrantPermission(permission Permission) {
	u.GivePermission(permission)
}

// generateSecureToken generates a cryptographically secure random token.
func generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}
