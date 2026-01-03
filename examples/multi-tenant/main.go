package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/providers"
)

// Tenant represents an organization/tenant
type Tenant struct {
	ID   string
	Name string
}

// TenantUser extends base user with tenant information
type TenantUser struct {
	*breitheamh.BaseUser
	TenantID string
}

var (
	// Tenant-specific user providers
	tenantProviders = make(map[string]*providers.MemoryProvider)

	// Tenant-specific JWT guards
	tenantGuards = make(map[string]*breitheamh.JWTGuard)

	// Tenant database
	tenants = map[string]*Tenant{
		"acme-corp": {ID: "acme-corp", Name: "Acme Corporation"},
		"tech-inc":  {ID: "tech-inc", Name: "Tech Inc"},
	}
)

func main() {
	setupTenants()
	setupRoutes()

	log.Println("Multi-tenant application starting on :8080")
	log.Println("\nTenants:")
	log.Println("  - acme-corp (Acme Corporation)")
	log.Println("  - tech-inc (Tech Inc)")
	log.Println("\nAccess tenant endpoints with subdomain header:")
	log.Println("  X-Tenant-ID: acme-corp")
	log.Println("  X-Tenant-ID: tech-inc")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupTenants() {
	// Setup Acme Corp tenant
	acmeProvider := providers.NewMemoryProvider()
	acmeGuard := breitheamh.NewJWTGuard("acme-secret-key", acmeProvider, 24*time.Hour)

	// Create users for Acme Corp
	acmeAdmin := breitheamh.NewBaseUser(1, "admin@acme.com", "Acme Admin")
	acmeAdminHash, _ := breitheamh.HashPasswordBcrypt("acme123", 10)
	acmeAdmin.SetPassword(acmeAdminHash)
	adminRole := breitheamh.NewRole("admin", "Administrator")
	adminRole.GrantPermission(breitheamh.NewPermission("*", "All permissions"))
	acmeAdmin.AssignRole(adminRole)
	acmeProvider.AddUser(acmeAdmin)

	acmeUser := breitheamh.NewBaseUser(2, "user@acme.com", "Acme User")
	acmeUserHash, _ := breitheamh.HashPasswordBcrypt("user123", 10)
	acmeUser.SetPassword(acmeUserHash)
	userRole := breitheamh.NewRole("user", "Regular User")
	userRole.GrantPermission(breitheamh.NewPermission("posts.view", "View posts"))
	acmeUser.AssignRole(userRole)
	acmeProvider.AddUser(acmeUser)

	tenantProviders["acme-corp"] = acmeProvider
	tenantGuards["acme-corp"] = acmeGuard

	// Setup Tech Inc tenant
	techProvider := providers.NewMemoryProvider()
	techGuard := breitheamh.NewJWTGuard("tech-secret-key", techProvider, 24*time.Hour)

	// Create users for Tech Inc
	techAdmin := breitheamh.NewBaseUser(1, "admin@tech.com", "Tech Admin")
	techAdminHash, _ := breitheamh.HashPasswordBcrypt("tech123", 10)
	techAdmin.SetPassword(techAdminHash)
	techAdmin.AssignRole(adminRole)
	techProvider.AddUser(techAdmin)

	techUser := breitheamh.NewBaseUser(2, "user@tech.com", "Tech User")
	techUserHash, _ := breitheamh.HashPasswordBcrypt("user123", 10)
	techUser.SetPassword(techUserHash)
	techUser.AssignRole(userRole)
	techProvider.AddUser(techUser)

	tenantProviders["tech-inc"] = techProvider
	tenantGuards["tech-inc"] = techGuard

	log.Println("Tenants configured:")
	log.Println("  Acme Corp: admin@acme.com / acme123, user@acme.com / user123")
	log.Println("  Tech Inc: admin@tech.com / tech123, user@tech.com / user123")
}

func setupRoutes() {
	http.HandleFunc("/login", tenantMiddleware(handleLogin))
	http.HandleFunc("/dashboard", tenantMiddleware(requireAuth(handleDashboard)))
	http.HandleFunc("/users", tenantMiddleware(requireAuth(requirePermission("users.view", handleUsers))))
	http.HandleFunc("/admin", tenantMiddleware(requireAuth(requireRole("admin", handleAdmin))))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := getTenantID(r)
	guard, ok := tenantGuards[tenantID]
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid tenant"})
		return
	}

	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	creds := map[string]interface{}{
		"email":    credentials.Email,
		"password": credentials.Password,
	}

	token, err := guard.Attempt(creds)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	user, _ := guard.User()
	tenant := tenants[tenantID]

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"tenant": map[string]string{
			"id":   tenant.ID,
			"name": tenant.Name,
		},
		"user": map[string]interface{}{
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"name":  user.GetName(),
			"roles": getRoleNames(user),
		},
	})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r)
	tenantID := getTenantID(r)
	tenant := tenants[tenantID]

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Dashboard",
		"tenant": map[string]string{
			"id":   tenant.ID,
			"name": tenant.Name,
		},
		"user": map[string]interface{}{
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"name":  user.GetName(),
			"roles": getRoleNames(user),
		},
		"stats": map[string]int{
			"total_users": len(tenantProviders[tenantID].GetAllUsers()),
			"total_posts": 5, // Example data
		},
	})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantID(r)
	provider := tenantProviders[tenantID]
	users := provider.GetAllUsers()

	userList := make([]map[string]interface{}, len(users))
	for i, u := range users {
		userList[i] = map[string]interface{}{
			"id":    u.GetID(),
			"email": u.GetEmail(),
			"name":  u.GetName(),
			"roles": getRoleNames(u),
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"tenant": tenantID,
		"users":  userList,
	})
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r)
	tenantID := getTenantID(r)
	tenant := tenants[tenantID]

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Admin Panel (Tenant Isolated)",
		"tenant": map[string]string{
			"id":   tenant.ID,
			"name": tenant.Name,
		},
		"admin": map[string]interface{}{
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"name":  user.GetName(),
		},
		"note": "This admin can only manage users/data within their tenant",
	})
}

// Middleware
func tenantMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing X-Tenant-ID header"})
			return
		}

		if _, ok := tenants[tenantID]; !ok {
			respondJSON(w, http.StatusNotFound, map[string]string{"error": "Tenant not found"})
			return
		}

		// Store tenant ID in context
		ctx := r.Context()
		ctx = setTenantID(ctx, tenantID)
		next(w, r.WithContext(ctx))
	}
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing authorization token"})
			return
		}

		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		tenantID := getTenantID(r)
		guard := tenantGuards[tenantID]

		user, err := guard.ValidateToken(token)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}

		ctx := breitheamh.WithUser(r.Context(), user)
		next(w, r.WithContext(ctx))
	}
}

func requirePermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getAuthUser(r)
		if !user.HasPermission(permission) {
			respondJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("Permission denied: %s required", permission),
			})
			return
		}
		next(w, r)
	}
}

func requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getAuthUser(r)
		if !user.HasRole(role) {
			respondJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("Role denied: %s required", role),
			})
			return
		}
		next(w, r)
	}
}

// Context helpers
type contextKey string

const tenantIDKey contextKey = "tenant_id"

func setTenantID(ctx *http.Request, tenantID string) {
	ctx.Header.Set("X-Tenant-ID-Context", tenantID)
}

func getTenantID(r *http.Request) string {
	// Try context first
	if id := r.Header.Get("X-Tenant-ID-Context"); id != "" {
		return id
	}
	// Fall back to header
	return r.Header.Get("X-Tenant-ID")
}

func getAuthUser(r *http.Request) breitheamh.User {
	return breitheamh.UserFromContext(r.Context())
}

func getRoleNames(user breitheamh.User) []string {
	roles := user.GetRoles()
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = role.GetName()
	}
	return names
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Example requests:
//
// 1. Login to Acme Corp:
//    curl -X POST http://localhost:8080/login \
//      -H "X-Tenant-ID: acme-corp" \
//      -H "Content-Type: application/json" \
//      -d '{"email":"admin@acme.com","password":"acme123"}'
//
// 2. Access Acme Corp dashboard:
//    curl http://localhost:8080/dashboard \
//      -H "X-Tenant-ID: acme-corp" \
//      -H "Authorization: Bearer YOUR_ACME_TOKEN"
//
// 3. Login to Tech Inc:
//    curl -X POST http://localhost:8080/login \
//      -H "X-Tenant-ID: tech-inc" \
//      -H "Content-Type: application/json" \
//      -d '{"email":"admin@tech.com","password":"tech123"}'
//
// 4. Try to use Acme token with Tech Inc (should fail):
//    curl http://localhost:8080/dashboard \
//      -H "X-Tenant-ID: tech-inc" \
//      -H "Authorization: Bearer YOUR_ACME_TOKEN"
//
// Note: Each tenant has isolated:
// - User database
// - JWT secret key
// - Roles and permissions
// - Authentication state
