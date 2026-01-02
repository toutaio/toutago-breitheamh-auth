package breitheamh

import (
"context"
"net/http"
"strings"
)

// ContextKey is the type for context keys used in middleware.
type ContextKey string

const (
// UserContextKey is the context key for the authenticated user
UserContextKey ContextKey = "breitheamh_user"
)

// AuthMiddleware creates HTTP middleware for authentication.
type AuthMiddleware struct {
guard Guard
}

// NewAuthMiddleware creates a new authentication middleware.
func NewAuthMiddleware(guard Guard) *AuthMiddleware {
return &AuthMiddleware{
guard: guard,
}
}

// Handle authenticates the request and adds user to context.
func (m *AuthMiddleware) Handle(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
token := extractToken(r)
if token == "" {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

user, err := m.guard.Validate(r.Context(), token)
if err != nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

ctx := context.WithValue(r.Context(), UserContextKey, user)
next.ServeHTTP(w, r.WithContext(ctx))
})
}

// HandleFunc wraps a handler function with authentication.
func (m *AuthMiddleware) HandleFunc(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
m.Handle(next).ServeHTTP(w, r)
}
}

// PermissionMiddleware creates HTTP middleware for permission checking.
type PermissionMiddleware struct {
permission string
}

// RequirePermission creates middleware that requires a specific permission.
func RequirePermission(permission string) *PermissionMiddleware {
return &PermissionMiddleware{
permission: permission,
}
}

// Handle checks if the user has the required permission.
func (m *PermissionMiddleware) Handle(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
user := GetUser(r.Context())
if user == nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

if !user.HasPermission(m.permission) {
http.Error(w, "Forbidden", http.StatusForbidden)
return
}

next.ServeHTTP(w, r)
})
}

// HandleFunc wraps a handler function with permission checking.
func (m *PermissionMiddleware) HandleFunc(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
m.Handle(next).ServeHTTP(w, r)
}
}

// RoleMiddleware creates HTTP middleware for role checking.
type RoleMiddleware struct {
role string
}

// RequireRole creates middleware that requires a specific role.
func RequireRole(role string) *RoleMiddleware {
return &RoleMiddleware{
role: role,
}
}

// Handle checks if the user has the required role.
func (m *RoleMiddleware) Handle(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
user := GetUser(r.Context())
if user == nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

if !user.HasRole(m.role) {
http.Error(w, "Forbidden", http.StatusForbidden)
return
}

next.ServeHTTP(w, r)
})
}

// HandleFunc wraps a handler function with role checking.
func (m *RoleMiddleware) HandleFunc(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
m.Handle(next).ServeHTTP(w, r)
}
}

// GateMiddleware creates HTTP middleware for gate checking.
type GateMiddleware struct {
authorizer *Authorizer
gateName   string
}

// RequireGate creates middleware that requires passing a gate.
func RequireGate(authorizer *Authorizer, gateName string) *GateMiddleware {
return &GateMiddleware{
authorizer: authorizer,
gateName:   gateName,
}
}

// Handle checks if the user passes the gate.
func (m *GateMiddleware) Handle(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
user := GetUser(r.Context())
if user == nil {
http.Error(w, "Unauthorized", http.StatusUnauthorized)
return
}

if !m.authorizer.Allows(r.Context(), m.gateName, user) {
http.Error(w, "Forbidden", http.StatusForbidden)
return
}

next.ServeHTTP(w, r)
})
}

// HandleFunc wraps a handler function with gate checking.
func (m *GateMiddleware) HandleFunc(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
m.Handle(next).ServeHTTP(w, r)
}
}

// GetUser retrieves the authenticated user from the request context.
func GetUser(ctx context.Context) User {
user, ok := ctx.Value(UserContextKey).(User)
if !ok {
return nil
}
return user
}

// extractToken extracts the bearer token from the Authorization header.
func extractToken(r *http.Request) string {
auth := r.Header.Get("Authorization")
if auth == "" {
return ""
}

parts := strings.SplitN(auth, " ", 2)
if len(parts) != 2 || parts[0] != "Bearer" {
return ""
}

return parts[1]
}
