package breitheamh

import "time"

// RoleProvider defines the interface for role storage and retrieval.
type RoleProvider interface {
	FindRoleByID(id string) *Role
	FindRoleByName(name string) *Role
	GetAllRoles() []Role
}

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
		if matchesPermissionSimple(p.Name, permission) {
			return true
		}
	}
	return false
}

// HasPermissionWithInheritance checks if the role has a permission including inherited permissions.
func (r *Role) HasPermissionWithInheritance(permission string, roleProvider RoleProvider) bool {
	// Check own permissions
	if r.HasPermission(permission) {
		return true
	}

	// Check parent role permissions
	if r.ParentID != nil && roleProvider != nil {
		parent := roleProvider.FindRoleByID(*r.ParentID)
		if parent != nil {
			return parent.HasPermissionWithInheritance(permission, roleProvider)
		}
	}

	return false
}

// GetAllPermissions returns all permissions including inherited from parent roles.
func (r *Role) GetAllPermissions(roleProvider RoleProvider) []Permission {
	permMap := make(map[string]Permission)

	// Add own permissions
	for _, p := range r.Permissions {
		permMap[p.ID] = p
	}

	// Add parent permissions
	if r.ParentID != nil && roleProvider != nil {
		parent := roleProvider.FindRoleByID(*r.ParentID)
		if parent != nil {
			parentPerms := parent.GetAllPermissions(roleProvider)
			for _, p := range parentPerms {
				if _, exists := permMap[p.ID]; !exists {
					permMap[p.ID] = p
				}
			}
		}
	}

	// Convert map to slice
	perms := make([]Permission, 0, len(permMap))
	for _, p := range permMap {
		perms = append(perms, p)
	}

	return perms
}
