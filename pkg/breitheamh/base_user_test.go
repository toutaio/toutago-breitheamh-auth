package breitheamh

import (
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
