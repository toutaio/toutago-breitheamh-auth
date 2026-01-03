package cosan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

type mockGuard struct {
	authenticateFunc func(ctx context.Context, credentials interface{}) (breitheamh.User, error)
}

func (m *mockGuard) Authenticate(ctx context.Context, credentials interface{}) (breitheamh.User, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, credentials)
	}
	return &breitheamh.BaseUser{ID: "123", Email: "test@example.com"}, nil
}

func (m *mockGuard) Validate(ctx context.Context, token string) (breitheamh.User, error) {
	return nil, nil
}

func (m *mockGuard) Logout(ctx context.Context, user breitheamh.User) error {
	return nil
}

func (m *mockGuard) Name() string {
	return "mock"
}

func TestAuthMiddleware_Handle_Success(t *testing.T) {
	guard := &mockGuard{}
	middleware := NewAuthMiddleware(AuthMiddlewareConfig{
		Guard: guard,
	})

	handlerCalled := false
	handler := middleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		user := GetUser(r.Context())
		if user == nil {
			t.Error("expected user in context")
		}
		if user.GetAuthIdentifier() != "test@example.com" {
			t.Errorf("expected email test@example.com, got %s", user.GetAuthIdentifier())
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_Handle_AuthenticationFailure(t *testing.T) {
	guard := &mockGuard{
		authenticateFunc: func(ctx context.Context, credentials interface{}) (breitheamh.User, error) {
			return nil, breitheamh.ErrInvalidToken
		},
	}
	middleware := NewAuthMiddleware(AuthMiddlewareConfig{
		Guard: guard,
	})

	handlerCalled := false
	handler := middleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if handlerCalled {
		t.Error("handler should not have been called")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_Handle_ExcludedPath(t *testing.T) {
	authCalled := false
	guard := &mockGuard{
		authenticateFunc: func(ctx context.Context, credentials interface{}) (breitheamh.User, error) {
			authCalled = true
			return nil, errors.New("should not be called")
		},
	}
	middleware := NewAuthMiddleware(AuthMiddlewareConfig{
		Guard:        guard,
		ExcludePaths: []string{"/public"},
	})

	handlerCalled := false
	handler := middleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if authCalled {
		t.Error("authentication should not have been called for excluded path")
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRequirePermission_Success(t *testing.T) {
	user := &breitheamh.BaseUser{
		ID:    "123",
		Email: "test@example.com",
		DirectPermissions: []breitheamh.Permission{
			{Name: "posts.create"},
		},
	}

	handlerCalled := false
	handler := RequirePermission("posts.create")(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/posts", nil)
	ctx := context.WithValue(req.Context(), userContextKey, user)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler(w, req)

	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRequirePermission_Forbidden(t *testing.T) {
	user := &breitheamh.BaseUser{
		ID:                "123",
		Email:             "test@example.com",
		DirectPermissions: []breitheamh.Permission{},
	}

	handlerCalled := false
	handler := RequirePermission("posts.delete")(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("DELETE", "/posts/1", nil)
	ctx := context.WithValue(req.Context(), userContextKey, user)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler(w, req)

	if handlerCalled {
		t.Error("handler should not have been called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestRequireRole_Success(t *testing.T) {
	user := &breitheamh.BaseUser{
		ID:    "123",
		Email: "test@example.com",
		Roles: []breitheamh.Role{
			{Name: "admin"},
		},
	}

	handlerCalled := false
	handler := RequireRole("admin")(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	ctx := context.WithValue(req.Context(), userContextKey, user)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler(w, req)

	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRequireAnyRole_Success(t *testing.T) {
	user := &breitheamh.BaseUser{
		ID:    "123",
		Email: "test@example.com",
		Roles: []breitheamh.Role{
			{Name: "editor"},
		},
	}

	handlerCalled := false
	handler := RequireAnyRole("admin", "editor", "moderator")(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	ctx := context.WithValue(req.Context(), userContextKey, user)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler(w, req)

	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGetUser_NoUser(t *testing.T) {
	ctx := context.Background()
	user := GetUser(ctx)
	if user != nil {
		t.Error("expected nil user")
	}
}

func TestGetGuard(t *testing.T) {
	guard := &mockGuard{}
	ctx := context.WithValue(context.Background(), guardContextKey, guard)
	
	retrieved := GetGuard(ctx)
	if retrieved == nil {
		t.Error("expected guard in context")
	}
}
