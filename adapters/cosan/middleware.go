package cosan

import (
	"context"
	"net/http"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// contextKey is the key for storing user in context
type contextKey string

const userContextKey contextKey = "breitheamh_user"

// AuthMiddleware creates authentication middleware for Cosan router
// It validates the token from Authorization header and stores the user in context
func AuthMiddleware(guardManager breitheamh.GuardManager, guardName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			guard := guardManager.Guard(guardName)

			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthenticated", http.StatusUnauthorized)
				return
			}

			// Remove "Bearer " prefix
			token := authHeader
			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}

			// Validate token
			user, err := guard.Validate(r.Context(), token)
			if err != nil || user == nil {
				http.Error(w, "Unauthenticated", http.StatusUnauthorized)
				return
			}

			// Store user in context
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// checkMiddleware creates middleware that checks a user authorization condition
func checkMiddleware(checkFn func(breitheamh.User) bool, errorMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(userContextKey).(breitheamh.User)
			if !ok || user == nil {
				http.Error(w, "Unauthenticated", http.StatusUnauthorized)
				return
			}

			if !checkFn(user) {
				http.Error(w, errorMsg, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PermissionMiddleware checks if user has required permission
func PermissionMiddleware(permission string) func(http.Handler) http.Handler {
	return checkMiddleware(func(u breitheamh.User) bool {
		return u.HasPermission(permission)
	}, "Forbidden")
}

// RoleMiddleware checks if user has required role
func RoleMiddleware(role string) func(http.Handler) http.Handler {
	return checkMiddleware(func(u breitheamh.User) bool {
		return u.HasRole(role)
	}, "Forbidden")
}

// GetUser retrieves the authenticated user from request context
func GetUser(ctx context.Context) (breitheamh.User, bool) {
	user, ok := ctx.Value(userContextKey).(breitheamh.User)
	return user, ok
}
