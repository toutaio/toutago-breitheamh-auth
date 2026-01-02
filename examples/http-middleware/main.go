package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
	fmt.Println("HTTP Middleware Example")
	fmt.Println("========================")
	fmt.Println()

	// Setup authentication
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash("secret123")

	// Create users with different permissions
	alice := breitheamh.NewBaseUser("user-1", "alice@example.com", hashedPassword)
	alice.GivePermission(breitheamh.Permission{ID: "1", Name: "posts.create"})
	alice.GivePermission(breitheamh.Permission{ID: "2", Name: "posts.read"})

	bob := breitheamh.NewBaseUser("user-2", "bob@example.com", hashedPassword)
	adminRole := breitheamh.Role{
		ID:   "admin",
		Name: "admin",
		Permissions: []breitheamh.Permission{
			{ID: "3", Name: "posts.*"},
			{ID: "4", Name: "users.*"},
		},
	}
	bob.AssignRole(adminRole)

	// Setup provider and guard
	provider := memory.NewProvider()
	provider.AddUser(alice)
	provider.AddUser(bob)

	jwtConfig := breitheamh.DefaultJWTConfig("your-secret-key-min-32-chars-long-here")
	tokenManager := breitheamh.NewJWTTokenManager(jwtConfig)
	guard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)

	// Create middleware
	authMiddleware := breitheamh.NewAuthMiddleware(guard)

	// Setup HTTP server
	mux := http.NewServeMux()

	// Public endpoint - no authentication required
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Welcome! This is a public endpoint.")
	})

	// Login endpoint
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		password := r.URL.Query().Get("password")

		user, token, err := guard.Attempt(r.Context(), breitheamh.Credentials{
			Email:    email,
			Password: password,
		})
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Login successful!\n")
		fmt.Fprintf(w, "User: %s\n", user.GetAuthIdentifier())
		fmt.Fprintf(w, "Token: %s\n", token.AccessToken)
	})

	// Protected endpoint - requires authentication
	mux.Handle("/protected", authMiddleware.Handle(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := breitheamh.GetUser(r.Context())
			fmt.Fprintf(w, "Hello, %s! You are authenticated.\n", user.GetAuthIdentifier())
		}),
	))

	// Posts endpoint - requires posts.read permission
	postsReadMiddleware := breitheamh.RequirePermission("posts.read")
	mux.Handle("/posts", authMiddleware.Handle(
		postsReadMiddleware.Handle(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Posts: [Post 1, Post 2, Post 3]")
			}),
		),
	))

	// Create post endpoint - requires posts.create permission
	postsCreateMiddleware := breitheamh.RequirePermission("posts.create")
	mux.Handle("/posts/create", authMiddleware.Handle(
		postsCreateMiddleware.Handle(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Post created successfully!")
			}),
		),
	))

	// Admin endpoint - requires admin role
	adminRoleMiddleware := breitheamh.RequireRole("admin")
	mux.Handle("/admin", authMiddleware.Handle(
		adminRoleMiddleware.Handle(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user := breitheamh.GetUser(r.Context())
				fmt.Fprintf(w, "Admin Panel - Welcome %s!\n", user.GetAuthIdentifier())
			}),
		),
	))

	// Print instructions
	fmt.Println("Server starting on :8080")
	fmt.Println()
	fmt.Println("Example requests:")
	fmt.Println("1. Login as Alice:")
	fmt.Println("   curl http://localhost:8080/login?email=alice@example.com&password=secret123")
	fmt.Println()
	fmt.Println("2. Access protected endpoint (use token from step 1):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/protected")
	fmt.Println()
	fmt.Println("3. Read posts (Alice has permission):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/posts")
	fmt.Println()
	fmt.Println("4. Create post (Alice has permission):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/posts/create")
	fmt.Println()
	fmt.Println("5. Access admin (Alice will be forbidden, login as Bob):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/admin")
	fmt.Println()

	log.Fatal(http.ListenAndServe(":8080", mux))
}
