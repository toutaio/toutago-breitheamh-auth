package breitheamh

import (
	"context"
	"testing"
	"time"
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

func TestPolicyResolver(t *testing.T) {
	authorizer := NewAuthorizer()
	policy := &MockPostPolicy{}
	authorizer.RegisterPolicy("MockPost", policy)

	user := NewBaseUser("user-1", "test@example.com", "password")
	otherUser := NewBaseUser("user-2", "other@example.com", "password")

	post := &MockPost{
		ID:        "post-1",
		Title:     "Test Post",
		AuthorID:  "user-1",
		Published: true,
	}

	t.Run("Policy method View is called for view ability", func(t *testing.T) {
		if !authorizer.Can(context.Background(), user, "view", post) {
			t.Error("Author should be able to view their own post")
		}
	})

	t.Run("Policy method Update is called for update ability", func(t *testing.T) {
		if !authorizer.Can(context.Background(), user, "update", post) {
			t.Error("Author should be able to update their own post")
		}

		if authorizer.Can(context.Background(), otherUser, "update", post) {
			t.Error("Other user should not be able to update post")
		}
	})

	t.Run("Policy method Delete is called for delete ability", func(t *testing.T) {
		if authorizer.Can(context.Background(), user, "delete", post) {
			t.Error("User without permission should not be able to delete")
		}

		user.GivePermission(Permission{ID: "1", Name: "posts.delete"})
		if !authorizer.Can(context.Background(), user, "delete", post) {
			t.Error("User with permission should be able to delete")
		}
	})

	t.Run("Unpublished post visibility", func(t *testing.T) {
		unpublishedPost := &MockPost{
			ID:        "post-2",
			Title:     "Draft",
			AuthorID:  "user-1",
			Published: false,
		}

		if !authorizer.Can(context.Background(), user, "view", unpublishedPost) {
			t.Error("Author should be able to view their unpublished post")
		}

		if authorizer.Can(context.Background(), otherUser, "view", unpublishedPost) {
			t.Error("Other user should not be able to view unpublished post")
		}
	})
}

func TestPolicyResolverWithPermission(t *testing.T) {
	authorizer := NewAuthorizer()
	policy := &MockPostPolicy{}
	authorizer.RegisterPolicy("MockPost", policy)

	user := NewBaseUser("user-1", "test@example.com", "password")
	user.GivePermission(Permission{ID: "1", Name: "posts.edit.any"})

	post := &MockPost{
		ID:        "post-1",
		AuthorID:  "other-user",
		Published: true,
	}

	t.Run("Permission overrides policy", func(t *testing.T) {
		if !authorizer.Can(context.Background(), user, "update", post) {
			t.Error("User with posts.edit.any should be able to update any post")
		}
	})
}

func TestToPascalCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"view", "View"},
		{"create", "Create"},
		{"update", "Update"},
		{"delete", "Delete"},
		{"view-post", "ViewPost"},
		{"create_user", "CreateUser"},
		{"edit.profile", "EditProfile"},
		{"manage-admin-users", "ManageAdminUsers"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toPascalCase(tt.input)
			if result != tt.expected {
				t.Errorf("toPascalCase(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetResourceType(t *testing.T) {
	post := &MockPost{ID: "1"}

	t.Run("Get type name from pointer", func(t *testing.T) {
		typeName := getResourceType(post)
		if typeName != "MockPost" {
			t.Errorf("getResourceType(post) = %q, want %q", typeName, "MockPost")
		}
	})

	t.Run("Get type name from value", func(t *testing.T) {
		typeName := getResourceType(*post)
		if typeName != "MockPost" {
			t.Errorf("getResourceType(*post) = %q, want %q", typeName, "MockPost")
		}
	})
}

func TestPolicyBeforeHook(t *testing.T) {
	authorizer := NewAuthorizer()
	policy := &MockPostPolicy{}
	authorizer.RegisterPolicy("MockPost", policy)

	admin := NewBaseUser("admin-1", "admin@example.com", "password")
	admin.GivePermission(Permission{ID: "1", Name: "admin.all"})

	regularUser := NewBaseUser("user-1", "user@example.com", "password")

	post := &MockPost{
		ID:        "post-1",
		AuthorID:  "other-user",
		Published: false,
	}

	t.Run("Before hook allows admin", func(t *testing.T) {
		// Admin has admin.* permission (matched by admin.all with wildcard)
		// But the Before hook checks for admin.* exactly, so this won't match
		// unless we give exact permission
		admin.GivePermission(Permission{ID: "2", Name: "admin.*"})

		if !authorizer.Can(context.Background(), admin, "update", post) {
			t.Error("Admin with admin.* should be allowed via before hook")
		}
	})

	t.Run("Before hook returns nil for regular user", func(t *testing.T) {
		// Regular user without author access should be denied
		if authorizer.Can(context.Background(), regularUser, "update", post) {
			t.Error("Regular user should not be able to update other's post")
		}
	})
}

func TestAuthorizerWithCache(t *testing.T) {
	authorizer := NewAuthorizer()
	authorizer.EnableCache(1 * time.Minute)

	policy := &MockPostPolicy{}
	authorizer.RegisterPolicy("MockPost", policy)

	user := NewBaseUser("user-1", "test@example.com", "password")
	post := &MockPost{
		ID:        "post-1",
		Title:     "Test Post",
		AuthorID:  "user-1",
		Published: true,
	}

	t.Run("Cache stores and retrieves results", func(t *testing.T) {
		// First call - should compute and cache
		result1 := authorizer.Can(context.Background(), user, "view", post)
		if !result1 {
			t.Error("User should be able to view post")
		}

		// Second call - should come from cache
		result2 := authorizer.Can(context.Background(), user, "view", post)
		if !result2 {
			t.Error("Cached result should be true")
		}
	})

	t.Run("Cache invalidation for user", func(t *testing.T) {
		// Make a call to cache it
		authorizer.Can(context.Background(), user, "update", post)

		// Invalidate user cache
		authorizer.InvalidateCacheForUser(user.GetID())

		// Next call should recompute (we can't directly verify, but it shouldn't error)
		result := authorizer.Can(context.Background(), user, "update", post)
		if !result {
			t.Error("User should still be able to update after cache invalidation")
		}
	})

	t.Run("Cache invalidation for resource", func(t *testing.T) {
		// Make a call to cache it
		authorizer.Can(context.Background(), user, "view", post)

		// Invalidate resource cache
		authorizer.InvalidateCacheForResource("MockPost", "post-1")

		// Next call should recompute
		result := authorizer.Can(context.Background(), user, "view", post)
		if !result {
			t.Error("User should still be able to view after cache invalidation")
		}
	})

	t.Run("Clear cache", func(t *testing.T) {
		// Make some calls to cache them
		authorizer.Can(context.Background(), user, "view", post)
		authorizer.Can(context.Background(), user, "update", post)

		// Clear all cache
		authorizer.ClearCache()

		// Calls should still work (recomputing)
		result := authorizer.Can(context.Background(), user, "view", post)
		if !result {
			t.Error("User should still be able to view after cache clear")
		}
	})

	t.Run("Disable cache", func(t *testing.T) {
		authorizer.DisableCache()

		// Calls should work without caching
		result := authorizer.Can(context.Background(), user, "view", post)
		if !result {
			t.Error("User should be able to view with cache disabled")
		}
	})
}
