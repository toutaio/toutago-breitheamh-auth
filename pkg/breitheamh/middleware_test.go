package breitheamh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)

	provider := newMockUserProvider()
	provider.AddUser(user)

	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)
	guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	middleware := NewAuthMiddleware(guard)

	t.Run("Valid token allows access", func(t *testing.T) {
		token, _ := tokenManager.Generate(user, 0)

		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUser(r.Context())
			if user == nil {
				t.Error("User should be in context")
			}
			if user.GetID() != "user-1" {
				t.Errorf("User ID = %q, expected %q", user.GetID(), "user-1")
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("Missing token returns 401", func(t *testing.T) {
		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/protected", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("Invalid token returns 401", func(t *testing.T) {
		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestPermissionMiddleware(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")
	user.GivePermission(Permission{ID: "1", Name: "posts.create"})

	middleware := RequirePermission("posts.create")

	t.Run("User with permission can access", func(t *testing.T) {
		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/posts/create", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, user)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("User without permission gets 403", func(t *testing.T) {
		middleware := RequirePermission("posts.delete")

		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/posts/delete", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, user)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("No user returns 401", func(t *testing.T) {
		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/posts/create", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestRoleMiddleware(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")
	editorRole := Role{ID: "1", Name: "editor"}
	user.AssignRole(editorRole)

	middleware := RequireRole("editor")

	t.Run("User with role can access", func(t *testing.T) {
		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/editor-panel", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, user)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("User without role gets 403", func(t *testing.T) {
		middleware := RequireRole("admin")

		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/admin-panel", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, user)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("No user returns 401", func(t *testing.T) {
		handler := middleware.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/editor-panel", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestGetUser(t *testing.T) {
	user := NewBaseUser("user-1", "test@example.com", "password")

	t.Run("Get user from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserContextKey, user)
		retrieved := GetUser(ctx)

		if retrieved == nil {
			t.Error("User should not be nil")
		}

		if retrieved.GetID() != user.GetID() {
			t.Errorf("User ID = %q, expected %q", retrieved.GetID(), user.GetID())
		}
	})

	t.Run("Get user from empty context", func(t *testing.T) {
		ctx := context.Background()
		retrieved := GetUser(ctx)

		if retrieved != nil {
			t.Error("User should be nil")
		}
	})
}

func TestExtractToken(t *testing.T) {
	t.Run("Valid Bearer token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer my-token-123")

		token := extractToken(req)
		if token != "my-token-123" {
			t.Errorf("Token = %q, expected %q", token, "my-token-123")
		}
	})

	t.Run("Missing Authorization header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		token := extractToken(req)
		if token != "" {
			t.Errorf("Token = %q, expected empty", token)
		}
	})

	t.Run("Invalid format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "InvalidFormat")

		token := extractToken(req)
		if token != "" {
			t.Errorf("Token = %q, expected empty", token)
		}
	})

	t.Run("Wrong scheme", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		token := extractToken(req)
		if token != "" {
			t.Errorf("Token = %q, expected empty", token)
		}
	})
}

func TestMiddlewareChaining(t *testing.T) {
	user := NewBaseUser("user-1", "admin@example.com", "password")
	adminRole := Role{ID: "1", Name: "admin"}
	user.AssignRole(adminRole)
	user.GivePermission(Permission{ID: "1", Name: "posts.delete"})

	t.Run("Chain role and permission middleware", func(t *testing.T) {
		roleMiddleware := RequireRole("admin")
		permMiddleware := RequirePermission("posts.delete")

		handler := roleMiddleware.Handle(
			permMiddleware.Handle(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			),
		)

		req := httptest.NewRequest("DELETE", "/posts/1", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, user)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("Chain fails if missing role", func(t *testing.T) {
		userNoRole := NewBaseUser("user-2", "user@example.com", "password")
		userNoRole.GivePermission(Permission{ID: "1", Name: "posts.delete"})

		roleMiddleware := RequireRole("admin")
		permMiddleware := RequirePermission("posts.delete")

		handler := roleMiddleware.Handle(
			permMiddleware.Handle(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("Handler should not be called")
				}),
			),
		)

		req := httptest.NewRequest("DELETE", "/posts/1", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, userNoRole)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Status = %d, expected %d", rec.Code, http.StatusForbidden)
		}
	})
}

func TestCustomErrorHandler(t *testing.T) {
hasher := NewHasher(AlgorithmBcrypt)
provider := newMockUserProvider()
config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
tokenManager := NewJWTTokenManager(config)
guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

t.Run("Default error handler", func(t *testing.T) {
middleware := NewAuthMiddleware(guard)

req := httptest.NewRequest("GET", "/protected", nil)
rr := httptest.NewRecorder()

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
})

middleware.Handle(handler).ServeHTTP(rr, req)

if rr.Code != http.StatusUnauthorized {
t.Errorf("Status = %d, expected %d", rr.Code, http.StatusUnauthorized)
}

if !strings.Contains(rr.Body.String(), "Unauthorized") {
t.Error("Expected default error message")
}
})

t.Run("Custom error handler", func(t *testing.T) {
customHandler := func(w http.ResponseWriter, r *http.Request, err error) {
w.WriteHeader(http.StatusUnauthorized)
w.Write([]byte("Custom auth error"))
}

middleware := NewAuthMiddleware(guard).WithErrorHandler(customHandler)

req := httptest.NewRequest("GET", "/protected", nil)
rr := httptest.NewRecorder()

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
})

middleware.Handle(handler).ServeHTTP(rr, req)

if rr.Code != http.StatusUnauthorized {
t.Errorf("Status = %d, expected %d", rr.Code, http.StatusUnauthorized)
}

if !strings.Contains(rr.Body.String(), "Custom auth error") {
t.Errorf("Expected custom error message, got: %s", rr.Body.String())
}
})

t.Run("JSON error handler", func(t *testing.T) {
middleware := NewAuthMiddleware(guard).WithErrorHandler(JSONErrorHandler)

req := httptest.NewRequest("GET", "/protected", nil)
rr := httptest.NewRecorder()

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
})

middleware.Handle(handler).ServeHTTP(rr, req)

if rr.Code != http.StatusUnauthorized {
t.Errorf("Status = %d, expected %d", rr.Code, http.StatusUnauthorized)
}

contentType := rr.Header().Get("Content-Type")
if contentType != "application/json" {
t.Errorf("Content-Type = %s, expected application/json", contentType)
}
})
}
