package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// This example demonstrates how to integrate Breitheamh authentication
// with any HTTP router using http.HandlerFunc

func main() {
	// 1. Set up user provider (in-memory for example)
	provider := memory.NewProvider()

	// Add a test user with roles and permissions
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("password123")

	user := breitheamh.NewBaseUser("1", "admin@example.com", hashedPassword)
	user.AssignRole(breitheamh.Role{
		ID:   "role-1",
		Name: "admin",
	})
	user.AssignRole(breitheamh.Role{
		ID:   "role-2",
		Name: "editor",
	})
	user.GivePermission(breitheamh.Permission{
		ID:   "perm-1",
		Name: "posts.create",
	})
	user.GivePermission(breitheamh.Permission{
		ID:   "perm-2",
		Name: "posts.edit",
	})
	user.GivePermission(breitheamh.Permission{
		ID:   "perm-3",
		Name: "posts.delete",
	})
	user.GivePermission(breitheamh.Permission{
		ID:   "perm-4",
		Name: "users.manage",
	})
	provider.AddUser(user)

	// 2. Set up JWT guard
	jwtConfig := breitheamh.DefaultJWTConfig("your-secret-key-change-in-production-min-32!!")
	tokenManager := breitheamh.NewJWTTokenManager(jwtConfig)
	jwtGuard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)

	// 3. Create authentication middleware
	authMiddleware := breitheamh.NewAuthMiddleware(jwtGuard)

	// 4. Set up routes
	mux := http.NewServeMux()

	// Public routes (no authentication required)
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/login", handleLogin(jwtGuard))

	// Protected routes (authentication required)
	mux.Handle("/profile", authMiddleware.Handle(http.HandlerFunc(handleProfile)))
	mux.Handle("/dashboard", authMiddleware.Handle(http.HandlerFunc(handleDashboard)))

	// Routes with role requirements
	mux.Handle("/admin",
		authMiddleware.Handle(
			requireRole("admin")(http.HandlerFunc(handleAdmin)),
		),
	)

	// Routes with permission requirements
	mux.Handle("/posts",
		authMiddleware.Handle(
			requirePermission("posts.create")(http.HandlerFunc(handleCreatePost)),
		),
	)

	// Routes with multiple role options
	mux.Handle("/content",
		authMiddleware.Handle(
			requireAnyRole("admin", "editor", "moderator")(http.HandlerFunc(handleContent)),
		),
	)

	// 5. Start server
	log.Println("Server starting on :8080")
	log.Println("Try: curl -X POST http://localhost:8080/login -d '{\"email\":\"admin@example.com\",\"password\":\"password123\"}'")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// Helper middleware functions
func requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Context().Value(breitheamh.UserContextKey)
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			authUser := user.(breitheamh.User)
			if !authUser.HasRole(role) {
				http.Error(w, "Forbidden: missing required role", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Context().Value(breitheamh.UserContextKey)
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			authUser := user.(breitheamh.User)
			if !authUser.HasPermission(permission) {
				http.Error(w, "Forbidden: missing required permission", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Context().Value(breitheamh.UserContextKey)
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			authUser := user.(breitheamh.User)
			for _, role := range roles {
				if authUser.HasRole(role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "Forbidden: missing required role", http.StatusForbidden)
		})
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to Breitheamh + Cosan Example\n")
	fmt.Fprintf(w, "\nAvailable endpoints:\n")
	fmt.Fprintf(w, "  POST /login - Login and get JWT token\n")
	fmt.Fprintf(w, "  GET  /profile - View profile (requires auth)\n")
	fmt.Fprintf(w, "  GET  /dashboard - Dashboard (requires auth)\n")
	fmt.Fprintf(w, "  GET  /admin - Admin panel (requires admin role)\n")
	fmt.Fprintf(w, "  POST /posts - Create post (requires posts.create permission)\n")
	fmt.Fprintf(w, "  GET  /content - Content management (requires admin, editor, or moderator role)\n")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy"}`)
}

func handleLogin(guard *breitheamh.JWTGuard) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		credentials := map[string]interface{}{
			"email":    "admin@example.com",
			"password": "password123",
		}

		// Authenticate with JWT guard
		user, token, err := guard.Attempt(r.Context(), credentials)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s","user":"%s"}`, token.AccessToken, user.GetAuthIdentifier())
	}
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(breitheamh.UserContextKey)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	authUser := user.(breitheamh.User)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":"%v","email":"%s"}`, authUser.GetID(), authUser.GetAuthIdentifier())
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(breitheamh.UserContextKey).(breitheamh.User)
	fmt.Fprintf(w, "Welcome to dashboard, %s!\n", user.GetAuthIdentifier())
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(breitheamh.UserContextKey).(breitheamh.User)
	fmt.Fprintf(w, "Admin panel - Hello %s (admin)\n", user.GetAuthIdentifier())
}

func handleCreatePost(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(breitheamh.UserContextKey).(breitheamh.User)
	fmt.Fprintf(w, "Post created by %s\n", user.GetAuthIdentifier())
}

func handleContent(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(breitheamh.UserContextKey).(breitheamh.User)
	fmt.Fprintf(w, "Content management - Hello %s\n", user.GetAuthIdentifier())
}
