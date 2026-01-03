package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/cosan"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/providers"
)

// This example demonstrates how to integrate Breitheamh authentication
// with Cosan router (or any HTTP router using http.HandlerFunc)

func main() {
	// 1. Set up user provider (in-memory for example)
	config := providers.MemoryProviderConfig{}
	provider := providers.NewMemoryProvider(config)

	// Add a test user with roles and permissions
	hasher := breitheamh.NewBcryptHasher(10)
	hashedPassword, _ := hasher.Hash("password123")
	
	user := &breitheamh.BaseUser{
		ID:       "1",
		Email:    "admin@example.com",
		Password: hashedPassword,
		Roles: []breitheamh.Role{
			{Name: "admin", GuardName: "jwt"},
			{Name: "editor", GuardName: "jwt"},
		},
		DirectPermissions: []breitheamh.Permission{
			{Name: "posts.create", GuardName: "jwt"},
			{Name: "posts.edit", GuardName: "jwt"},
			{Name: "posts.delete", GuardName: "jwt"},
			{Name: "users.manage", GuardName: "jwt"},
		},
	}
	provider.AddUser(user)

	// 2. Set up JWT guard
	jwtGuard := breitheamh.NewJWTGuard(breitheamh.JWTConfig{
		Provider:   provider,
		SigningKey: []byte("your-secret-key-change-in-production"),
		Issuer:     "breitheamh-example",
		Audience:   []string{"api"},
		TTL:        15 * time.Minute,
	})

	// 3. Create authentication middleware
	authMiddleware := cosan.NewAuthMiddleware(cosan.AuthMiddlewareConfig{
		Guard:        jwtGuard,
		ExcludePaths: []string{"/", "/login", "/health"},
	})

	// 4. Set up routes
	mux := http.NewServeMux()

	// Public routes (no authentication required)
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/login", handleLogin(jwtGuard))

	// Protected routes (authentication required)
	mux.HandleFunc("/profile", authMiddleware.Handle(handleProfile))
	mux.HandleFunc("/dashboard", authMiddleware.Handle(handleDashboard))

	// Routes with role requirements
	mux.HandleFunc("/admin", 
		authMiddleware.Handle(
			cosan.RequireRole("admin")(handleAdmin),
		),
	)

	// Routes with permission requirements
	mux.HandleFunc("/posts", 
		authMiddleware.Handle(
			cosan.RequirePermission("posts.create")(handleCreatePost),
		),
	)

	// Routes with multiple role options
	mux.HandleFunc("/content", 
		authMiddleware.Handle(
			cosan.RequireAnyRole("admin", "editor", "moderator")(handleContent),
		),
	)

	// 5. Start server
	log.Println("Server starting on :8080")
	log.Println("Try: curl -X POST http://localhost:8080/login -d '{\"email\":\"admin@example.com\",\"password\":\"password123\"}'")
	log.Fatal(http.ListenAndServe(":8080", mux))
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

func handleLogin(guard breitheamh.Guard) http.HandlerFunc {
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
		user, err := guard.Authenticate(r.Context(), credentials)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Generate token
		jwtGuard, ok := guard.(*breitheamh.JWTGuard)
		if !ok {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		token, err := jwtGuard.GenerateToken(user)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":"%s","user":"%s"}`, token, user.GetAuthIdentifier())
	}
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	user := cosan.GetUser(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":"%v","email":"%s"}`, user.GetAuthIdentifier(), user.GetAuthIdentifier())
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := cosan.GetUser(r.Context())
	fmt.Fprintf(w, "Welcome to dashboard, %s!\n", user.GetAuthIdentifier())
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	user := cosan.GetUser(r.Context())
	fmt.Fprintf(w, "Admin panel - Hello %s (admin)\n", user.GetAuthIdentifier())
}

func handleCreatePost(w http.ResponseWriter, r *http.Request) {
	user := cosan.GetUser(r.Context())
	fmt.Fprintf(w, "Post created by %s\n", user.GetAuthIdentifier())
}

func handleContent(w http.ResponseWriter, r *http.Request) {
	user := cosan.GetUser(r.Context())
	fmt.Fprintf(w, "Content management - Hello %s\n", user.GetAuthIdentifier())
}
