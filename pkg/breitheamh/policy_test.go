package breitheamh

import (
	"context"
	"testing"
)

// MockPost is a test resource for policy testing.
type MockPost struct {
	ID        string
	Title     string
	AuthorID  string
	Published bool
}

// MockPostPolicy is a test policy for posts.
type MockPostPolicy struct{}

func (p *MockPostPolicy) Before(ctx context.Context, user User, ability string) *bool {
	// Super admins can do anything
	if user.HasPermission("admin.*") {
		allow := true
		return &allow
	}
	return nil
}

func (p *MockPostPolicy) View(user User, post *MockPost) bool {
	return post.Published || post.AuthorID == user.GetID()
}

func (p *MockPostPolicy) Update(user User, post *MockPost) bool {
	return post.AuthorID == user.GetID() || user.HasPermission("posts.edit.any")
}

func (p *MockPostPolicy) Delete(user User, post *MockPost) bool {
	return user.HasPermission("posts.delete")
}

func TestAuthorizer(t *testing.T) {
	authorizer := NewAuthorizer()

	user := NewBaseUser("user-1", "test@example.com", "password")
	user.GivePermission(Permission{ID: "1", Name: "posts.create"})

	t.Run("Can with permission", func(t *testing.T) {
		if !authorizer.Can(context.Background(), user, "posts.create", nil) {
			t.Error("User should be able to create posts")
		}
	})

	t.Run("Cannot without permission", func(t *testing.T) {
		if authorizer.Can(context.Background(), user, "posts.delete", nil) {
			t.Error("User should not be able to delete posts")
		}
	})

	t.Run("Cannot checks", func(t *testing.T) {
		if !authorizer.Cannot(context.Background(), user, "posts.delete", nil) {
			t.Error("Cannot should return true for missing permission")
		}
	})
}

func TestPolicyRegistry(t *testing.T) {
	registry := NewPolicyRegistry()
	policy := &MockPostPolicy{}

	t.Run("Register and get policy", func(t *testing.T) {
		registry.Register("post", policy)

		retrieved, exists := registry.Get("post")
		if !exists {
			t.Error("Policy should exist")
		}

		if retrieved == nil {
			t.Error("Retrieved policy should not be nil")
		}
	})

	t.Run("Get non-existent policy", func(t *testing.T) {
		_, exists := registry.Get("nonexistent")
		if exists {
			t.Error("Non-existent policy should not exist")
		}
	})
}

func TestAuthorizerWithPolicy(t *testing.T) {
	authorizer := NewAuthorizer()
	policy := &MockPostPolicy{}
	authorizer.RegisterPolicy("post", policy)

	post := &MockPost{
		ID:        "post-1",
		Title:     "Test Post",
		AuthorID:  "user-1",
		Published: false,
	}

	t.Run("Policy before hook for admin", func(t *testing.T) {
		admin := NewBaseUser("admin-1", "admin@example.com", "password")
		admin.GivePermission(Permission{ID: "1", Name: "admin.*"})

		// Admin with admin.* permission should pass via fallback permission check
		if !authorizer.Can(context.Background(), admin, "admin.anything", post) {
			t.Error("Admin should be able to use admin permissions")
		}
	})
}
