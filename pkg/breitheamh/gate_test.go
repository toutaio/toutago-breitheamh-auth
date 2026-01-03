package breitheamh

import (
	"context"
	"testing"
)

func TestCallbackGate(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	t.Run("Gate allows access", func(t *testing.T) {
		gate := NewCallbackGate("test-gate", func(ctx context.Context, u User, args ...interface{}) bool {
			return u.GetID() == "user-1"
		})

		if !gate.Allows(context.Background(), user) {
			t.Error("Gate should allow access")
		}

		if gate.Denies(context.Background(), user) {
			t.Error("Gate should not deny access")
		}
	})

	t.Run("Gate denies access", func(t *testing.T) {
		gate := NewCallbackGate("test-gate", func(ctx context.Context, u User, args ...interface{}) bool {
			return u.GetID() == "other-user"
		})

		if gate.Allows(context.Background(), user) {
			t.Error("Gate should not allow access")
		}

		if !gate.Denies(context.Background(), user) {
			t.Error("Gate should deny access")
		}
	})

	t.Run("Gate with arguments", func(t *testing.T) {
		gate := NewCallbackGate("owns-resource", func(ctx context.Context, u User, args ...interface{}) bool {
			if len(args) == 0 {
				return false
			}
			resourceOwner, ok := args[0].(string)
			if !ok {
				return false
			}
			return u.GetID() == resourceOwner
		})

		if !gate.Allows(context.Background(), user, "user-1") {
			t.Error("Gate should allow access when user owns resource")
		}

		if gate.Allows(context.Background(), user, "other-user") {
			t.Error("Gate should not allow access when user doesn't own resource")
		}
	})

	t.Run("Gate name", func(t *testing.T) {
		gate := NewCallbackGate("my-gate", func(ctx context.Context, u User, args ...interface{}) bool {
			return true
		})

		if gate.Name() != "my-gate" {
			t.Errorf("Gate name = %q, expected %q", gate.Name(), "my-gate")
		}
	})
}

func TestPermissionGate(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")
	user.GivePermission(Permission{ID: "1", Name: "posts.create"})

	t.Run("Allows with permission", func(t *testing.T) {
		gate := NewPermissionGate("create-post", "posts.create")

		if !gate.Allows(context.Background(), user) {
			t.Error("Gate should allow access with permission")
		}
	})

	t.Run("Denies without permission", func(t *testing.T) {
		gate := NewPermissionGate("delete-post", "posts.delete")

		if gate.Allows(context.Background(), user) {
			t.Error("Gate should not allow access without permission")
		}

		if !gate.Denies(context.Background(), user) {
			t.Error("Gate should deny access without permission")
		}
	})

	t.Run("Gate name", func(t *testing.T) {
		gate := NewPermissionGate("create-post", "posts.create")

		if gate.Name() != "create-post" {
			t.Errorf("Gate name = %q, expected %q", gate.Name(), "create-post")
		}
	})
}

func TestRoleGate(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")
	editorRole := Role{ID: "1", Name: "editor"}
	user.AssignRole(editorRole)

	t.Run("Allows with role", func(t *testing.T) {
		gate := NewRoleGate("editor-only", "editor")

		if !gate.Allows(context.Background(), user) {
			t.Error("Gate should allow access with role")
		}
	})

	t.Run("Denies without role", func(t *testing.T) {
		gate := NewRoleGate("admin-only", "admin")

		if gate.Allows(context.Background(), user) {
			t.Error("Gate should not allow access without role")
		}

		if !gate.Denies(context.Background(), user) {
			t.Error("Gate should deny access without role")
		}
	})

	t.Run("Gate name", func(t *testing.T) {
		gate := NewRoleGate("editor-only", "editor")

		if gate.Name() != "editor-only" {
			t.Errorf("Gate name = %q, expected %q", gate.Name(), "editor-only")
		}
	})
}

func TestAuthorizerGates(t *testing.T) {
	authorizer := NewAuthorizer()
	user := NewBaseUser("user-1", "test@example.com", "password")

	t.Run("Define and use gate", func(t *testing.T) {
		authorizer.DefineGate("is-admin", func(ctx context.Context, u User, args ...interface{}) bool {
			return u.HasPermission("admin.*")
		})

		if authorizer.Allows(context.Background(), "is-admin", user) {
			t.Error("Gate should deny access without admin permission")
		}

		user.GivePermission(Permission{ID: "1", Name: "admin.*"})

		if !authorizer.Allows(context.Background(), "is-admin", user) {
			t.Error("Gate should allow access with admin permission")
		}
	})

	t.Run("Denies method", func(t *testing.T) {
		authorizer.DefineGate("is-banned", func(ctx context.Context, u User, args ...interface{}) bool {
			return false
		})

		if !authorizer.Denies(context.Background(), "is-banned", user) {
			t.Error("Denies should return true when gate returns false")
		}
	})

	t.Run("Non-existent gate", func(t *testing.T) {
		if authorizer.Allows(context.Background(), "non-existent", user) {
			t.Error("Non-existent gate should deny access")
		}
	})
}

func TestGateInterceptors(t *testing.T) {
user := NewBaseUser("user-1", "test@example.com", "password")

t.Run("Before interceptor can allow", func(t *testing.T) {
gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
return false // Gate would deny
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
// Before interceptor allows
allow := true
return &allow
})

if !gate.Allows(context.Background(), user) {
t.Error("Before interceptor should allow access")
}
})

t.Run("Before interceptor can deny", func(t *testing.T) {
gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
return true // Gate would allow
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
// Before interceptor denies
deny := false
return &deny
})

if gate.Allows(context.Background(), user) {
t.Error("Before interceptor should deny access")
}
})

t.Run("Before interceptor returns nil continues to gate", func(t *testing.T) {
gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
return true
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
// Interceptor returns nil, so gate logic should run
return nil
})

if !gate.Allows(context.Background(), user) {
t.Error("Gate should allow when before interceptor returns nil")
}
})

t.Run("After interceptor can override result", func(t *testing.T) {
gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
return true // Gate allows
})

gate.After(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
// After interceptor denies
deny := false
return &deny
})

if gate.Allows(context.Background(), user) {
t.Error("After interceptor should override and deny")
}
})

t.Run("Multiple before interceptors", func(t *testing.T) {
var callOrder []string

gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
callOrder = append(callOrder, "gate")
return true
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
callOrder = append(callOrder, "before1")
return nil // Continue
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
callOrder = append(callOrder, "before2")
return nil // Continue
})

gate.Allows(context.Background(), user)

if len(callOrder) != 3 || callOrder[0] != "before1" || callOrder[1] != "before2" || callOrder[2] != "gate" {
t.Errorf("Call order incorrect: %v", callOrder)
}
})

t.Run("Multiple after interceptors", func(t *testing.T) {
var callOrder []string

gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
callOrder = append(callOrder, "gate")
return true
})

gate.After(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
callOrder = append(callOrder, "after1")
return nil // Continue
})

gate.After(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
callOrder = append(callOrder, "after2")
return nil // Continue
})

gate.Allows(context.Background(), user)

if len(callOrder) != 3 || callOrder[0] != "gate" || callOrder[1] != "after1" || callOrder[2] != "after2" {
t.Errorf("Call order incorrect: %v", callOrder)
}
})

t.Run("Before interceptor short-circuits", func(t *testing.T) {
gateExecuted := false

gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
gateExecuted = true
return true
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
// Return early, gate shouldn't execute
allow := true
return &allow
})

gate.Allows(context.Background(), user)

if gateExecuted {
t.Error("Gate should not execute when before interceptor short-circuits")
}
})

t.Run("Interceptor receives gate name", func(t *testing.T) {
var receivedName string

gate := NewCallbackGate("my-gate", func(ctx context.Context, u User, args ...interface{}) bool {
return true
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
receivedName = gateName
return nil
})

gate.Allows(context.Background(), user)

if receivedName != "my-gate" {
t.Errorf("Interceptor should receive gate name 'my-gate', got '%s'", receivedName)
}
})

t.Run("Interceptor receives arguments", func(t *testing.T) {
var receivedArgs []interface{}

gate := NewCallbackGate("test", func(ctx context.Context, u User, args ...interface{}) bool {
return true
})

gate.Before(func(ctx context.Context, u User, gateName string, args ...interface{}) *bool {
receivedArgs = args
return nil
})

gate.Allows(context.Background(), user, "arg1", 123, true)

if len(receivedArgs) != 3 {
t.Errorf("Expected 3 args, got %d", len(receivedArgs))
}
if receivedArgs[0] != "arg1" || receivedArgs[1] != 123 || receivedArgs[2] != true {
t.Errorf("Args not passed correctly: %v", receivedArgs)
}
})
}
