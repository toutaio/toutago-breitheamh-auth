package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/providers"
)

var (
	userProvider *providers.MemoryProvider
	jwtGuard     *breitheamh.JWTGuard
	authManager  *breitheamh.GuardManager
)

func main() {
	setupAuth()
	setupRoutes()

	log.Println("RBAC Admin Panel starting on :8080")
	log.Println("Login with: admin@example.com / admin123")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupAuth() {
	userProvider = providers.NewMemoryProvider()
	jwtGuard = breitheamh.NewJWTGuard("secret-key-change-in-production", userProvider, 24*time.Hour)
	authManager = breitheamh.NewGuardManager(jwtGuard)

	// Create roles
	adminRole := breitheamh.NewRole("admin", "Administrator")
	adminRole.GrantPermission(breitheamh.NewPermission("*", "All permissions"))

	editorRole := breitheamh.NewRole("editor", "Editor")
	editorRole.GrantPermission(breitheamh.NewPermission("posts.*", "All post operations"))
	editorRole.GrantPermission(breitheamh.NewPermission("users.view", "View users"))

	viewerRole := breitheamh.NewRole("viewer", "Viewer")
	viewerRole.GrantPermission(breitheamh.NewPermission("posts.view", "View posts"))
	viewerRole.GrantPermission(breitheamh.NewPermission("users.view", "View users"))

	// Create admin user
	admin := breitheamh.NewBaseUser(1, "admin@example.com", "Admin User")
	adminHash, _ := breitheamh.HashPasswordBcrypt("admin123", 10)
	admin.SetPassword(adminHash)
	admin.AssignRole(adminRole)
	userProvider.AddUser(admin)

	// Create editor user
	editor := breitheamh.NewBaseUser(2, "editor@example.com", "Editor User")
	editorHash, _ := breitheamh.HashPasswordBcrypt("editor123", 10)
	editor.SetPassword(editorHash)
	editor.AssignRole(editorRole)
	userProvider.AddUser(editor)

	// Create viewer user
	viewer := breitheamh.NewBaseUser(3, "viewer@example.com", "Viewer User")
	viewerHash, _ := breitheamh.HashPasswordBcrypt("viewer123", 10)
	viewer.SetPassword(viewerHash)
	viewer.AssignRole(viewerRole)
	userProvider.AddUser(viewer)

	log.Println("Users created:")
	log.Println("  admin@example.com / admin123 (admin role)")
	log.Println("  editor@example.com / editor123 (editor role)")
	log.Println("  viewer@example.com / viewer123 (viewer role)")
}

func setupRoutes() {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/users", requireAuth(handleUsers))
	http.HandleFunc("/users/create", requireAuth(requirePermission("users.create", handleUserCreate)))
	http.HandleFunc("/users/delete", requireAuth(requirePermission("users.delete", handleUserDelete)))
	http.HandleFunc("/posts", requireAuth(handlePosts))
	http.HandleFunc("/posts/create", requireAuth(requirePermission("posts.create", handlePostCreate)))
	http.HandleFunc("/posts/delete", requireAuth(requirePermission("posts.delete", handlePostDelete)))
	http.HandleFunc("/admin", requireAuth(requireRole("admin", handleAdmin)))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	token, err := jwtGuard.Attempt(creds)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	user, _ := jwtGuard.User()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user": map[string]interface{}{
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"name":  user.GetName(),
			"roles": getRoleNames(user),
		},
	})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Users list",
		"can_create": user.HasPermission("users.create"),
		"can_delete": user.HasPermission("users.delete"),
		"users": []map[string]interface{}{
			{"id": 1, "email": "admin@example.com", "name": "Admin User"},
			{"id": 2, "email": "editor@example.com", "name": "Editor User"},
			{"id": 3, "email": "viewer@example.com", "name": "Viewer User"},
		},
	})
}

func handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{
		"message": "User created successfully",
	})
}

func handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "User deleted successfully",
	})
}

func handlePosts(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Posts list",
		"can_create": user.HasPermission("posts.create"),
		"can_delete": user.HasPermission("posts.delete"),
		"posts": []map[string]interface{}{
			{"id": 1, "title": "First Post", "author": "Admin"},
			{"id": 2, "title": "Second Post", "author": "Editor"},
		},
	})
}

func handlePostCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{
		"message": "Post created successfully",
	})
}

func handlePostDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Post deleted successfully",
	})
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Admin panel",
		"user": map[string]interface{}{
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"name":  user.GetName(),
			"roles": getRoleNames(user),
		},
		"stats": map[string]int{
			"total_users": 3,
			"total_posts": 2,
		},
	})
}

// Middleware
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing authorization token"})
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		user, err := jwtGuard.ValidateToken(token)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}

		// Store user in context
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

// Helpers
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
// 1. Login as admin:
//    curl -X POST http://localhost:8080/login \
//      -H "Content-Type: application/json" \
//      -d '{"email":"admin@example.com","password":"admin123"}'
//
// 2. Get users (with token):
//    curl http://localhost:8080/users \
//      -H "Authorization: Bearer YOUR_TOKEN"
//
// 3. Create user (admin only):
//    curl -X POST http://localhost:8080/users/create \
//      -H "Authorization: Bearer YOUR_TOKEN"
//
// 4. Access admin panel (admin role only):
//    curl http://localhost:8080/admin \
//      -H "Authorization: Bearer YOUR_TOKEN"
//
// 5. Login as editor (cannot access admin panel):
//    curl -X POST http://localhost:8080/login \
//      -H "Content-Type: application/json" \
//      -d '{"email":"editor@example.com","password":"editor123"}'
