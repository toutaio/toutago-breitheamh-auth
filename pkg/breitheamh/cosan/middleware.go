package cosan

import (
	"context"
	"net/http"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// contextKey is used for storing auth data in context
type contextKey string

const (
	userContextKey  contextKey = "breitheamh_user"
	guardContextKey contextKey = "breitheamh_guard"
)

// AuthMiddleware creates authentication middleware for Cosan router
type AuthMiddleware struct {
	guard        breitheamh.Guard
	errorHandler func(http.ResponseWriter, *http.Request, error)
	excludePaths map[string]bool
}

// AuthMiddlewareConfig configures authentication middleware
type AuthMiddlewareConfig struct {
	Guard        breitheamh.Guard
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
	ExcludePaths []string
}

// NewAuthMiddleware creates new authentication middleware for Cosan router
func NewAuthMiddleware(config AuthMiddlewareConfig) *AuthMiddleware {
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}

	excludePaths := make(map[string]bool)
	for _, path := range config.ExcludePaths {
		excludePaths[path] = true
	}

	return &AuthMiddleware{
		guard:        config.Guard,
		errorHandler: config.ErrorHandler,
		excludePaths: excludePaths,
	}
}

// Handle returns the middleware handler function
func (m *AuthMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for excluded paths
		if m.excludePaths[r.URL.Path] {
			next(w, r)
			return
		}

		// Authenticate the request - pass the *http.Request as credentials
		user, err := m.guard.Authenticate(r.Context(), r)
		if err != nil {
			m.errorHandler(w, r, err)
			return
		}

		// Store user and guard in context
		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, guardContextKey, m.guard)

		// Continue with authenticated request
		next(w, r.WithContext(ctx))
	}
}

// RequirePermission creates middleware that requires a specific permission
func RequirePermission(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := GetUser(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !user.HasPermission(permission) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

// RequireRole creates middleware that requires a specific role
func RequireRole(role string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := GetUser(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !user.HasRole(role) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

// RequireAnyRole creates middleware that requires any of the specified roles
func RequireAnyRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := GetUser(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required roles
			for _, role := range roles {
				if user.HasRole(role) {
					next(w, r)
					return
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}

// GetUser retrieves the authenticated user from request context
func GetUser(ctx context.Context) breitheamh.User {
	if user, ok := ctx.Value(userContextKey).(breitheamh.User); ok {
		return user
	}
	return nil
}

// GetGuard retrieves the guard from request context
func GetGuard(ctx context.Context) breitheamh.Guard {
	if guard, ok := ctx.Value(guardContextKey).(breitheamh.Guard); ok {
		return guard
	}
	return nil
}

// defaultErrorHandler is the default error handler for authentication failures
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err == breitheamh.ErrInvalidToken || err == breitheamh.ErrExpiredToken {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}
	http.Error(w, "Authentication failed", http.StatusUnauthorized)
}
