package breitheamh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test models for policy testing
type Post struct {
	ID       string
	Title    string
	AuthorID string
}

type PostPolicy struct{}

func (p *PostPolicy) Update(ctx context.Context, user User, post interface{}) bool {
	if post, ok := post.(*Post); ok {
		return user.GetID() == post.AuthorID
	}
	return false
}

func (p *PostPolicy) View(ctx context.Context, user User, post interface{}) bool {
	return true // Anyone can view
}

func (p *PostPolicy) Before(ctx context.Context, user User, ability string) *bool {
	return nil // No special pre-checks
}

// TestFullAuthenticationFlow tests the complete authentication flow
func TestFullAuthenticationFlow(t *testing.T) {
	// Setup
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("password123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)
	user.GivePermission(Permission{Name: "posts.create"})
	user.AssignRole(Role{Name: "editor"})

	provider := newMockUserProvider()
	provider.users["user-1"] = user

	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)
	guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	// Step 1: User login
	loggedUser, tokenObj, err := guard.Attempt(context.Background(), map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	})

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if loggedUser == nil {
		t.Fatal("Expected user to be returned")
	}

	token := tokenObj.AccessToken

	// Step 2: Validate token
	validatedUser, err := guard.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Token validation failed: %v", err)
	}

	if validatedUser.GetID() != "user-1" {
		t.Errorf("User ID = %s, expected user-1", validatedUser.GetID())
	}

	// Step 3: Check permissions
	authorizer := NewAuthorizer()
	if !authorizer.Can(context.Background(), validatedUser, "posts.create", nil) {
		t.Error("User should have posts.create permission")
	}

	// Step 4: Check roles
	if !validatedUser.HasRole("editor") {
		t.Error("User should have editor role")
	}

	// Step 5: Logout
	err = guard.Logout(context.Background(), validatedUser)
	if err != nil {
		t.Errorf("Logout failed: %v", err)
	}
}

// TestFullAuthorizationFlow tests the complete authorization flow
func TestFullAuthorizationFlow(t *testing.T) {
	// Setup users with different permissions
	admin := NewBaseUser("admin-1", "admin@example.com", "hash")
	admin.SetSuperAdmin(true)

	editor := NewBaseUser("editor-1", "editor@example.com", "hash")
	editor.AssignRole(Role{Name: "editor", Permissions: []Permission{
		{Name: "posts.create"},
		{Name: "posts.edit"},
	}})

	viewer := NewBaseUser("viewer-1", "viewer@example.com", "hash")
	viewer.GivePermission(Permission{Name: "posts.view"})

	authorizer := NewAuthorizer()
	ctx := context.Background()

	// Test admin access (should pass all)
	t.Run("Admin has all access", func(t *testing.T) {
		if !authorizer.Can(ctx, admin, "posts.create", nil) {
			t.Error("Admin should have posts.create")
		}
		if !authorizer.Can(ctx, admin, "posts.delete", nil) {
			t.Error("Admin should have posts.delete")
		}
		if !authorizer.Can(ctx, admin, "anything.at.all", nil) {
			t.Error("Admin should have all permissions")
		}
	})

	// Test editor access
	t.Run("Editor has limited access", func(t *testing.T) {
		if !authorizer.Can(ctx, editor, "posts.create", nil) {
			t.Error("Editor should have posts.create")
		}
		if !authorizer.Can(ctx, editor, "posts.edit", nil) {
			t.Error("Editor should have posts.edit")
		}
		if authorizer.Can(ctx, editor, "posts.delete", nil) {
			t.Error("Editor should not have posts.delete")
		}
	})

	// Test viewer access
	t.Run("Viewer has minimal access", func(t *testing.T) {
		if !authorizer.Can(ctx, viewer, "posts.view", nil) {
			t.Error("Viewer should have posts.view")
		}
		if authorizer.Can(ctx, viewer, "posts.create", nil) {
			t.Error("Viewer should not have posts.create")
		}
		if authorizer.Can(ctx, viewer, "posts.edit", nil) {
			t.Error("Viewer should not have posts.edit")
		}
	})
}

// TestHTTPMiddlewareFlow tests the complete HTTP middleware flow
func TestHTTPMiddlewareFlow(t *testing.T) {
	// Setup
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("password123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)
	user.GivePermission(Permission{Name: "posts.create"})

	provider := newMockUserProvider()
	provider.users["user-1"] = user

	config := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	tokenManager := NewJWTTokenManager(config)
	guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	// Generate token
	_, tokenObj, _ := guard.Attempt(context.Background(), map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	})
	token := tokenObj.AccessToken

	// Create middleware stack
	authMiddleware := NewAuthMiddleware(guard)
	permMiddleware := RequirePermission("posts.create")

	// Protected handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(UserContextKey)
		if u == nil {
			t.Error("User should be in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	})

	// Apply middleware chain
	protected := authMiddleware.Handle(permMiddleware.Handle(handler))

	t.Run("Authenticated request with permission", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/posts", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		protected.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, expected %d", rr.Code, http.StatusOK)
		}

		if rr.Body.String() != "Success" {
			t.Error("Expected success response")
		}
	})

	t.Run("Unauthenticated request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/posts", nil)
		rr := httptest.NewRecorder()

		protected.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, expected %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("Invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/posts", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rr := httptest.NewRecorder()

		protected.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, expected %d", rr.Code, http.StatusUnauthorized)
		}
	})
}

// TestSessionBasedFlow tests session-based authentication flow
func TestSessionBasedFlow(t *testing.T) {
	// Setup
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("password123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)
	user.GivePermission(Permission{Name: "dashboard.view"})

	provider := newMockUserProvider()
	provider.users["user-1"] = user

	store := NewMemorySessionStore()
	guard := NewSessionGuard("session", provider, store, hasher, nil)

	ctx := context.Background()

	// Step 1: Login and create session
	loggedUser, session, err := guard.Login(ctx, map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	})

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if loggedUser == nil {
		t.Fatal("User should be returned")
	}

	sessionID := session.ID

	// Step 2: Validate session
	validatedUser, err := guard.Validate(ctx, sessionID)
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if validatedUser.GetID() != "user-1" {
		t.Errorf("User ID = %s, expected user-1", validatedUser.GetID())
	}

	// Step 3: Use session in HTTP request
	authMiddleware := NewAuthMiddleware(guard)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(UserContextKey).(User)
		if u.GetID() != "user-1" {
			t.Error("Wrong user in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rr := httptest.NewRecorder()

	authMiddleware.Handle(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, expected %d", rr.Code, http.StatusOK)
	}

	// Step 4: Logout
	err = guard.Logout(ctx, validatedUser)
	if err != nil {
		t.Errorf("Logout failed: %v", err)
	}

	// Step 5: Verify session is destroyed
	_, err = guard.Validate(ctx, sessionID)
	if err == nil {
		t.Error("Session should be invalid after logout")
	}
}

// TestPolicyBasedFlow tests policy-based authorization flow
func TestPolicyBasedFlow(t *testing.T) {
	user := NewBaseUser("user-1", "user@example.com", "hash")
	user.GivePermission(Permission{Name: "posts.view"})
	user.GivePermission(Permission{Name: "posts.create"})

	admin := NewBaseUser("admin-1", "admin@example.com", "hash")
	admin.GivePermission(Permission{Name: "posts.view"})

	authorizer := NewAuthorizer()
	ctx := context.Background()

	t.Run("User with permission can access", func(t *testing.T) {
		if !authorizer.Can(ctx, user, "posts.view", nil) {
			t.Error("User should have posts.view permission")
		}
		if !authorizer.Can(ctx, user, "posts.create", nil) {
			t.Error("User should have posts.create permission")
		}
	})

	t.Run("User without permission cannot access", func(t *testing.T) {
		if authorizer.Can(ctx, admin, "posts.create", nil) {
			t.Error("Admin should not have posts.create permission")
		}
	})

	t.Run("Both can view", func(t *testing.T) {
		if !authorizer.Can(ctx, user, "posts.view", nil) {
			t.Error("User should be able to view")
		}
		if !authorizer.Can(ctx, admin, "posts.view", nil) {
			t.Error("Admin should be able to view")
		}
	})
}

// TestTokenRefreshFlow tests token refresh flow
func TestTokenRefreshFlow(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("password123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)

	provider := newMockUserProvider()
	provider.users["user-1"] = user

	// Create config with short expiry
	config := &JWTConfig{
		SecretKey:       []byte("test-secret-key-min-32-chars-long"),
		AccessTokenTTL:  2 * time.Second,
		RefreshTokenTTL: 10 * time.Second,
		Issuer:          "test",
		EnableRefresh:   true,
	}

	tokenManager := NewJWTTokenManager(config)
	guard := NewJWTGuard("jwt", provider, tokenManager, hasher)

	ctx := context.Background()

	// Step 1: Login
	_, tokenObj, err := guard.Attempt(ctx, map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	})

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	token := tokenObj.AccessToken

	// Step 2: Token should work immediately
	_, err = guard.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Initial validation failed: %v", err)
	}

	// Step 3: Get refresh token if available
	if tokenObj.RefreshToken != "" {
		newTokenObj, err := tokenManager.Refresh(tokenObj.RefreshToken)
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		if newTokenObj.AccessToken == "" {
			t.Error("Refresh token should be generated")
		}

		// Step 4: New token should work
		_, err = guard.Validate(ctx, newTokenObj.AccessToken)
		if err != nil {
			t.Errorf("Refreshed token validation failed: %v", err)
		}
	}
}

// TestMultiGuardFlow tests using multiple guards together
func TestMultiGuardFlow(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("password123")

	user := NewBaseUser("user-1", "test@example.com", hashedPassword)
	user.GivePermission(Permission{Name: "api.access"})

	provider := newMockUserProvider()
	provider.users["user-1"] = user

	// Setup JWT guard
	jwtConfig := DefaultJWTConfig("test-secret-key-min-32-chars-long")
	jwtTokenManager := NewJWTTokenManager(jwtConfig)
	jwtGuard := NewJWTGuard("jwt", provider, jwtTokenManager, hasher)

	// Setup API token guard
	apiTokenStore := NewMemoryAPITokenStore()
	apiGuard := NewAPITokenGuard("api", provider, apiTokenStore)

	ctx := context.Background()

	// Create JWT token
	_, jwtTokenObj, _ := jwtGuard.Attempt(ctx, map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	})
	jwtToken := jwtTokenObj.AccessToken

	// Create API token
	apiTokenObj, _ := apiGuard.CreateToken(ctx, user, "Test API Token", nil, nil)
	apiToken := apiTokenObj.Token

	// Both tokens should work
	t.Run("JWT token validates", func(t *testing.T) {
		validatedUser, err := jwtGuard.Validate(ctx, jwtToken)
		if err != nil {
			t.Errorf("JWT validation failed: %v", err)
		}
		if validatedUser.GetID() != "user-1" {
			t.Error("Wrong user from JWT")
		}
	})

	t.Run("API token validates", func(t *testing.T) {
		validatedUser, err := apiGuard.Validate(ctx, apiToken)
		if err != nil {
			t.Errorf("API token validation failed: %v", err)
		}
		if validatedUser.GetID() != "user-1" {
			t.Error("Wrong user from API token")
		}
	})

	// Both should work with same authorizer
	t.Run("Authorization works with both tokens", func(t *testing.T) {
		authorizer := NewAuthorizer()

		jwtUser, _ := jwtGuard.Validate(ctx, jwtToken)
		apiUser, _ := apiGuard.Validate(ctx, apiToken)

		if !authorizer.Can(ctx, jwtUser, "api.access", nil) {
			t.Error("JWT user should have api.access")
		}

		if !authorizer.Can(ctx, apiUser, "api.access", nil) {
			t.Error("API user should have api.access")
		}
	})
}
