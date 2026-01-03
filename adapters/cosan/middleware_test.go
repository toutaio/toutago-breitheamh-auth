package cosan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func setupTestGuardManager() (breitheamh.GuardManager, *breitheamh.BaseUser, string) {
	provider := memory.NewProvider()
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret")
	
	user := breitheamh.NewBaseUser("1", "test@example.com", hashedPassword)
	
	// Add roles and permissions
	adminRole := breitheamh.Role{ID: "role-1", Name: "admin"}
	user.AssignRole(adminRole)
	
	createPerm := breitheamh.Permission{ID: "perm-1", Name: "posts.create"}
	editPerm := breitheamh.Permission{ID: "perm-2", Name: "posts.edit"}
	user.GivePermission(createPerm)
	user.GivePermission(editPerm)
	
	provider.AddUser(user)

	guardManager := breitheamh.NewGuardManager()
	tokenManager := breitheamh.NewJWTTokenManager(breitheamh.DefaultJWTConfig("testsecret"))
	jwtGuard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)
	guardManager.RegisterGuard("jwt", jwtGuard)

	// Generate token
	ctx := context.Background()
	_, token, _ := jwtGuard.Attempt(ctx, breitheamh.Credentials{
		Email:    "test@example.com",
		Password: "secret",
	})

	return guardManager, user, token.AccessToken
}

func TestAuthMiddleware(t *testing.T) {
	guardManager, _, token := setupTestGuardManager()

	handler := AuthMiddleware(guardManager, "jwt")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	t.Run("NoToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("ValidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestPermissionMiddleware(t *testing.T) {
	guardManager, _, token := setupTestGuardManager()

	authHandler := AuthMiddleware(guardManager, "jwt")
	permHandler := PermissionMiddleware("posts.create")

	handler := authHandler(permHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})))

	t.Run("HasPermission", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestRoleMiddleware(t *testing.T) {
	guardManager, _, token := setupTestGuardManager()

	authHandler := AuthMiddleware(guardManager, "jwt")
	roleHandler := RoleMiddleware("admin")

	handler := authHandler(roleHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})))

	t.Run("HasRole", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestGetUser(t *testing.T) {
	guardManager, baseUser, token := setupTestGuardManager()

	handler := AuthMiddleware(guardManager, "jwt")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := GetUser(r.Context())
		if !ok || user == nil {
			t.Error("Expected user to be in context")
			return
		}
		if user.GetAuthIdentifier() != baseUser.GetAuthIdentifier() {
			t.Errorf("Expected user ID %s, got %s", baseUser.GetAuthIdentifier(), user.GetAuthIdentifier())
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

