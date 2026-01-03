package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// UserRepository simulates a database
type UserRepository struct {
	provider *memory.Provider
	hasher   *breitheamh.Hasher
}

func NewUserRepository() *UserRepository {
	return &UserRepository{
		provider: memory.NewProvider(),
		hasher:   breitheamh.NewHasher(breitheamh.AlgorithmBcrypt),
	}
}

func (r *UserRepository) CreateUser(email, password string) (*breitheamh.BaseUser, error) {
	hash, err := r.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user := breitheamh.NewBaseUser(email, email, hash)
	user.GivePermission(breitheamh.Permission{Name: "api.access"})
	user.GivePermission(breitheamh.Permission{Name: "posts.read"})

	r.provider.AddUser(user)
	return user, nil
}

func (r *UserRepository) FindByEmail(email string) (breitheamh.User, error) {
	return r.provider.FindByCredentials(context.TODO(), map[string]interface{}{
		"email": email,
	})
}

// API Response types
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// API Server
type APIServer struct {
	repo           *UserRepository
	guard          *breitheamh.JWTGuard
	tokenManager   *breitheamh.JWTTokenManager
	authMiddleware *breitheamh.AuthMiddleware
}

func NewAPIServer() *APIServer {
	repo := NewUserRepository()

	// Create JWT guard
	config := breitheamh.DefaultJWTConfig("your-super-secret-key-change-in-production-min-32-chars")
	tokenManager := breitheamh.NewJWTTokenManager(config)
	guard := breitheamh.NewJWTGuard("api", repo.provider, tokenManager, repo.hasher)

	// Create auth middleware with JSON error handler
	authMiddleware := breitheamh.NewAuthMiddleware(guard).WithErrorHandler(breitheamh.JSONErrorHandler)

	return &APIServer{
		repo:           repo,
		guard:          guard,
		tokenManager:   tokenManager,
		authMiddleware: authMiddleware,
	}
}

// Handlers
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Attempt login
	user, token, err := s.guard.Attempt(r.Context(), map[string]interface{}{
		"email":    req.Email,
		"password": req.Password,
	})

	if err != nil {
		s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	log.Printf("User %s logged in successfully", user.GetID())

	// Return token response
	response := LoginResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(token.ExpiresIn),
	}

	s.jsonResponse(w, response, http.StatusOK)
}

func (s *APIServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create user
	user, err := s.repo.CreateUser(req.Email, req.Password)
	if err != nil {
		s.jsonError(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	log.Printf("User %s registered successfully", user.GetID())

	s.jsonResponse(w, UserResponse{
		ID:    user.GetID(),
		Email: user.GetAuthIdentifier(),
	}, http.StatusCreated)
}

func (s *APIServer) handleMe(w http.ResponseWriter, r *http.Request) {
	// User is already authenticated by middleware
	user := r.Context().Value(breitheamh.UserContextKey).(breitheamh.User)

	s.jsonResponse(w, UserResponse{
		ID:    user.GetID(),
		Email: user.GetAuthIdentifier(),
	}, http.StatusOK)
}

func (s *APIServer) handlePosts(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(breitheamh.UserContextKey).(breitheamh.User)

	// Check permission
	authorizer := breitheamh.NewAuthorizer()
	if !authorizer.Can(r.Context(), user, "posts.read", nil) {
		s.jsonError(w, "Forbidden: insufficient permissions", http.StatusForbidden)
		return
	}

	// Return mock posts
	posts := []map[string]interface{}{
		{"id": "1", "title": "First Post", "author": user.GetAuthIdentifier()},
		{"id": "2", "title": "Second Post", "author": user.GetAuthIdentifier()},
	}

	s.jsonResponse(w, posts, http.StatusOK)
}

func (s *APIServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Extract refresh token from header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.jsonError(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Refresh token
	newToken, err := s.tokenManager.Refresh(refreshToken)
	if err != nil {
		s.jsonError(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	response := LoginResponse{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(newToken.ExpiresIn),
	}

	s.jsonResponse(w, response, http.StatusOK)
}

// Helper methods
func (s *APIServer) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *APIServer) jsonError(w http.ResponseWriter, message string, status int) {
	s.jsonResponse(w, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	}, status)
}

func main() {
	server := NewAPIServer()

	// Create a test user
	server.repo.CreateUser("test@example.com", "password123")

	// Routes
	http.HandleFunc("/api/register", server.handleRegister)
	http.HandleFunc("/api/login", server.handleLogin)
	http.HandleFunc("/api/refresh", server.handleRefresh)

	// Protected routes
	http.Handle("/api/me", server.authMiddleware.Handle(http.HandlerFunc(server.handleMe)))
	http.Handle("/api/posts", server.authMiddleware.Handle(http.HandlerFunc(server.handlePosts)))

	fmt.Println("🔐 JWT API Server running on http://localhost:8080")
	fmt.Println("")
	fmt.Println("Try these commands:")
	fmt.Println("")
	fmt.Println("# Login")
	fmt.Println(`curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'`)
	fmt.Println("")
	fmt.Println("# Get user info (use token from login)")
	fmt.Println(`curl http://localhost:8080/api/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"`)
	fmt.Println("")
	fmt.Println("# Get posts (requires posts.read permission)")
	fmt.Println(`curl http://localhost:8080/api/posts \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"`)
	fmt.Println("")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
