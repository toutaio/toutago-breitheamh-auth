package breitheamh

import (
	"context"
	"testing"
	"time"
)

func TestBaseUser(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "hashed-password")

	if user.GetID() != "user-1" {
		t.Errorf("GetID() = %q, expected %q", user.GetID(), "user-1")
	}

	if user.GetAuthIdentifier() != "test@example.com" {
		t.Errorf("GetAuthIdentifier() = %q, expected %q", user.GetAuthIdentifier(), "test@example.com")
	}

	if user.GetPassword() != "hashed-password" {
		t.Errorf("GetPassword() = %q, expected %q", user.GetPassword(), "hashed-password")
	}
}

func TestBaseUserRoles(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	// Create a role
	editorRole := Role{
		ID:   "role-1",
		Name: "editor",
	}

	user.AssignRole(editorRole)

	if !user.HasRole("editor") {
		t.Error("User should have editor role")
	}

	if user.HasRole("admin") {
		t.Error("User should not have admin role")
	}

	roles := user.GetRoles()
	if len(roles) != 1 {
		t.Errorf("User should have 1 role, got %d", len(roles))
	}

	user.RemoveRole("editor")

	if user.HasRole("editor") {
		t.Error("User should not have editor role after removal")
	}
}

func TestBaseUserPermissions(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	// Give direct permission
	createPerm := Permission{
		ID:   "perm-1",
		Name: "posts.create",
	}
	user.GivePermission(createPerm)

	if !user.HasPermission("posts.create") {
		t.Error("User should have posts.create permission")
	}

	if user.HasPermission("posts.delete") {
		t.Error("User should not have posts.delete permission")
	}

	// Test wildcard permission
	wildcardPerm := Permission{
		ID:   "perm-2",
		Name: "users.*",
	}
	user.GivePermission(wildcardPerm)

	if !user.HasPermission("users.edit") {
		t.Error("User should have users.edit permission via wildcard")
	}

	// Revoke permission
	user.RevokePermission("posts.create")

	if user.HasPermission("posts.create") {
		t.Error("User should not have posts.create permission after revocation")
	}
}

func TestBaseUserPermissionsFromRole(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	// Create permissions
	createPerm := Permission{
		ID:   "perm-1",
		Name: "posts.create",
	}
	editPerm := Permission{
		ID:   "perm-2",
		Name: "posts.edit",
	}

	// Create role with permissions
	editorRole := Role{
		ID:          "role-1",
		Name:        "editor",
		Permissions: []Permission{createPerm, editPerm},
	}

	user.AssignRole(editorRole)

	if !user.HasPermission("posts.create") {
		t.Error("User should have posts.create permission from role")
	}

	if !user.HasPermission("posts.edit") {
		t.Error("User should have posts.edit permission from role")
	}

	allPerms := user.GetPermissions()
	if len(allPerms) != 2 {
		t.Errorf("User should have 2 permissions, got %d", len(allPerms))
	}
}

func TestBaseUserLocked(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	if user.IsLocked() {
		t.Error("User should not be locked initially")
	}

	// Lock user for 1 hour
	lockUntil := time.Now().Add(1 * time.Hour)
	user.LockedUntil = &lockUntil

	if !user.IsLocked() {
		t.Error("User should be locked")
	}

	// Set lock in the past
	pastLock := time.Now().Add(-1 * time.Hour)
	user.LockedUntil = &pastLock

	if user.IsLocked() {
		t.Error("User should not be locked when lock is in the past")
	}
}

func TestBaseUserEmailVerified(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	if user.IsEmailVerified() {
		t.Error("User email should not be verified initially")
	}

	// Verify email
	now := time.Now()
	user.EmailVerifiedAt = &now

	if !user.IsEmailVerified() {
		t.Error("User email should be verified")
	}
}

func TestSuperAdmin(t *testing.T) {
t.Run("Super admin bypasses permission checks", func(t *testing.T) {
user := NewBaseUser("admin-1", "admin@example.com", "password")
user.SetSuperAdmin(true)

// Should have any permission without assignment
if !user.HasPermission("posts.create") {
t.Error("Super admin should have all permissions")
}

if !user.HasPermission("users.delete") {
t.Error("Super admin should have all permissions")
}

if !user.HasPermission("anything.at.all") {
t.Error("Super admin should have all permissions")
}
})

t.Run("Super admin bypasses role checks", func(t *testing.T) {
user := NewBaseUser("admin-1", "admin@example.com", "password")
user.SetSuperAdmin(true)

// Should have any role without assignment
if !user.HasRole("admin") {
t.Error("Super admin should have all roles")
}

if !user.HasRole("editor") {
t.Error("Super admin should have all roles")
}
})

t.Run("Regular user without super admin", func(t *testing.T) {
user := NewBaseUser("user-1", "user@example.com", "password")

// Should not have permissions
if user.HasPermission("posts.create") {
t.Error("Regular user should not have unassigned permission")
}

// Assign permission
user.GivePermission(Permission{Name: "posts.create"})

// Now should have it
if !user.HasPermission("posts.create") {
t.Error("User should have assigned permission")
}

// Should not have other permissions
if user.HasPermission("posts.delete") {
t.Error("User should not have unassigned permission")
}
})

t.Run("IsSuperAdmin returns correct status", func(t *testing.T) {
user := NewBaseUser("user-1", "user@example.com", "password")

if user.IsSuperAdmin() {
t.Error("New user should not be super admin")
}

user.SetSuperAdmin(true)

if !user.IsSuperAdmin() {
t.Error("User should be super admin after setting")
}

user.SetSuperAdmin(false)

if user.IsSuperAdmin() {
t.Error("User should not be super admin after unsetting")
}
})

t.Run("Super admin in authorization flow", func(t *testing.T) {
superAdmin := NewBaseUser("admin-1", "admin@example.com", "password")
superAdmin.SetSuperAdmin(true)

regularUser := NewBaseUser("user-1", "user@example.com", "password")

authorizer := NewAuthorizer()

// Super admin should pass any check
if !authorizer.Can(context.Background(), superAdmin, "posts.create", nil) {
t.Error("Super admin should pass any authorization check")
}

// Regular user should fail without permission
if authorizer.Can(context.Background(), regularUser, "posts.create", nil) {
t.Error("Regular user should fail without permission")
}
})
}

func TestGuardBasedRoleScoping(t *testing.T) {
user := NewBaseUser("user-1", "test@example.com", "password")

// Create roles for different guards
webRole := Role{
ID:        "role-1",
Name:      "editor",
GuardName: "web",
}

apiRole := Role{
ID:        "role-2",
Name:      "admin",
GuardName: "api",
}

user.AssignRole(webRole)
user.AssignRole(apiRole)

// Test guard-specific role checks
if !user.HasRoleForGuard("editor", "web") {
t.Error("User should have editor role for web guard")
}

if user.HasRoleForGuard("editor", "api") {
t.Error("User should not have editor role for api guard")
}

if !user.HasRoleForGuard("admin", "api") {
t.Error("User should have admin role for api guard")
}

if user.HasRoleForGuard("admin", "web") {
t.Error("User should not have admin role for web guard")
}

// Test GetRolesForGuard
webRoles := user.GetRolesForGuard("web")
if len(webRoles) != 1 || webRoles[0].Name != "editor" {
t.Error("Should get only web guard roles")
}

apiRoles := user.GetRolesForGuard("api")
if len(apiRoles) != 1 || apiRoles[0].Name != "admin" {
t.Error("Should get only api guard roles")
}
}

func TestGuardBasedPermissionScoping(t *testing.T) {
user := NewBaseUser("user-1", "test@example.com", "password")

// Add direct permissions for different guards
webPerm := Permission{
ID:        "perm-1",
Name:      "posts.create",
GuardName: "web",
}

apiPerm := Permission{
ID:        "perm-2",
Name:      "users.delete",
GuardName: "api",
}

user.GivePermission(webPerm)
user.GivePermission(apiPerm)

// Test guard-specific permission checks
if !user.HasPermissionForGuard("posts.create", "web") {
t.Error("User should have posts.create permission for web guard")
}

if user.HasPermissionForGuard("posts.create", "api") {
t.Error("User should not have posts.create permission for api guard")
}

if !user.HasPermissionForGuard("users.delete", "api") {
t.Error("User should have users.delete permission for api guard")
}

if user.HasPermissionForGuard("users.delete", "web") {
t.Error("User should not have users.delete permission for web guard")
}

// Test GetPermissionsForGuard
webPerms := user.GetPermissionsForGuard("web")
if len(webPerms) != 1 || webPerms[0].Name != "posts.create" {
t.Error("Should get only web guard permissions")
}

apiPerms := user.GetPermissionsForGuard("api")
if len(apiPerms) != 1 || apiPerms[0].Name != "users.delete" {
t.Error("Should get only api guard permissions")
}
}

func TestGuardBasedPermissionFromRoles(t *testing.T) {
user := NewBaseUser("user-1", "test@example.com", "password")

// Create role with permissions for web guard
webRole := Role{
ID:        "role-1",
Name:      "editor",
GuardName: "web",
Permissions: []Permission{
{ID: "perm-1", Name: "posts.create", GuardName: "web"},
{ID: "perm-2", Name: "posts.edit", GuardName: "web"},
},
}

// Create role with permissions for api guard
apiRole := Role{
ID:        "role-2",
Name:      "manager",
GuardName: "api",
Permissions: []Permission{
{ID: "perm-3", Name: "users.manage", GuardName: "api"},
},
}

user.AssignRole(webRole)
user.AssignRole(apiRole)

// Test permissions from roles are guard-scoped
if !user.HasPermissionForGuard("posts.create", "web") {
t.Error("User should have posts.create from web role")
}

if user.HasPermissionForGuard("posts.create", "api") {
t.Error("User should not have posts.create for api guard")
}

if !user.HasPermissionForGuard("users.manage", "api") {
t.Error("User should have users.manage from api role")
}

if user.HasPermissionForGuard("users.manage", "web") {
t.Error("User should not have users.manage for web guard")
}

// Test GetPermissionsForGuard includes role permissions
webPerms := user.GetPermissionsForGuard("web")
if len(webPerms) != 2 {
t.Errorf("Should get 2 web permissions, got %d", len(webPerms))
}

apiPerms := user.GetPermissionsForGuard("api")
if len(apiPerms) != 1 {
t.Errorf("Should get 1 api permission, got %d", len(apiPerms))
}
}
