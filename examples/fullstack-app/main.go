package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/authorization"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/middleware"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/providers"
	"github.com/toutaio/toutago-cosan/pkg/cosan"
	"github.com/toutaio/toutago-datamapper/pkg/datamapper"
	"github.com/toutaio/toutago-scela-bus/pkg/scela"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID        int64     `db:"id"`
	Email     string    `db:"email"`
	Password  string    `db:"password"`
	Name      string    `db:"name"`
	CreatedAt time.Time `db:"created_at"`
}

func (u *User) GetAuthIdentifier() interface{} { return u.ID }
func (u *User) GetAuthPassword() string        { return u.Password }

type Post struct {
	ID        int64     `db:"id"`
	UserID    int64     `db:"user_id"`
	Title     string    `db:"title"`
	Content   string    `db:"content"`
	Published bool      `db:"published"`
	CreatedAt time.Time `db:"created_at"`
}

type PostPolicy struct{}

func (p *PostPolicy) View(user breitheamh.Authenticatable, post *Post) bool {
	return post.Published || post.UserID == user.GetAuthIdentifier().(int64)
}

func (p *PostPolicy) Create(user breitheamh.Authenticatable) bool {
	return true
}

func (p *PostPolicy) Update(user breitheamh.Authenticatable, post *Post) bool {
	return post.UserID == user.GetAuthIdentifier().(int64)
}

func (p *PostPolicy) Delete(user breitheamh.Authenticatable, post *Post) bool {
	return post.UserID == user.GetAuthIdentifier().(int64)
}

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := initDatabase(db); err != nil {
		log.Fatal(err)
	}

	dm := datamapper.New(db, datamapper.Config{Driver: "sqlite3"})
	bus := scela.NewBus()

	provider := providers.NewDatamapperProvider(dm, "users", func() breitheamh.Authenticatable {
		return &User{}
	})

	jwtSecret := []byte("your-secret-key-change-in-production")
	jwtGuard := breitheamh.NewJWTGuard(provider, jwtSecret, breitheamh.JWTConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	authManager := breitheamh.NewAuthManager()
	authManager.RegisterGuard("jwt", jwtGuard)

	authz := authorization.NewManager()
	authz.DefineRole("admin", []string{"posts.*", "users.*"})
	authz.DefineRole("editor", []string{"posts.create", "posts.update"})
	authz.DefineRole("viewer", []string{"posts.view"})
	
	authz.RegisterPolicy("Post", &PostPolicy{})
	
	authz.DefineGate("manage-users", func(user breitheamh.Authenticatable) bool {
		return authz.HasRole(user, "admin")
	})

	bus.On("user.login", func(ctx context.Context, event scela.Event) error {
		log.Printf("User logged in: %v", event.Data)
		return nil
	})

	router := cosan.NewRouter()

	router.POST("/auth/register", handleRegister(dm, authManager))
	router.POST("/auth/login", handleLogin(authManager, bus))
	router.POST("/auth/refresh", handleRefresh(authManager))

	apiGroup := router.Group("/api")
	apiGroup.Use(middleware.Authenticate(authManager, "jwt"))

	apiGroup.GET("/posts", handleListPosts(dm, authz))
	apiGroup.GET("/posts/:id", handleViewPost(dm, authz))
	apiGroup.POST("/posts", handleCreatePost(dm, authz))
	apiGroup.PUT("/posts/:id", handleUpdatePost(dm, authz))
	apiGroup.DELETE("/posts/:id", handleDeletePost(dm, authz))

	adminGroup := apiGroup.Group("/admin")
	adminGroup.Use(middleware.AuthorizeRole(authManager, authz, "admin"))
	adminGroup.GET("/users", handleListUsers(dm))

	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		log.Println("Server starting on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func initDatabase(db *sql.DB) error {
	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			published BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		CREATE TABLE user_roles (
			user_id INTEGER NOT NULL,
			role TEXT NOT NULL,
			PRIMARY KEY (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`
	_, err := db.Exec(schema)
	return err
}

func handleRegister(dm *datamapper.DataMapper, authManager *breitheamh.AuthManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Name     string `json:"name"`
		}

		if err := parseJSON(r, &req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		hashedPassword, err := breitheamh.HashPassword(req.Password)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to hash password")
			return
		}

		user := &User{
			Email:     req.Email,
			Password:  hashedPassword,
			Name:      req.Name,
			CreatedAt: time.Now(),
		}

		if err := dm.Insert("users", user); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to create user")
			return
		}

		respondJSON(w, http.StatusCreated, map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		})
	}
}

func handleLogin(authManager *breitheamh.AuthManager, bus *scela.Bus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := parseJSON(r, &req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		guard := authManager.Guard("jwt").(*breitheamh.JWTGuard)
		accessToken, refreshToken, err := guard.Attempt(r.Context(), map[string]interface{}{
			"email":    req.Email,
			"password": req.Password,
		})

		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		bus.Dispatch(r.Context(), scela.Event{
			Name: "user.login",
			Data: map[string]interface{}{"email": req.Email},
		})

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"token_type":    "Bearer",
		})
	}
}

func handleRefresh(authManager *breitheamh.AuthManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}

		if err := parseJSON(r, &req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		guard := authManager.Guard("jwt").(*breitheamh.JWTGuard)
		accessToken, refreshToken, err := guard.RefreshToken(r.Context(), req.RefreshToken)

		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid refresh token")
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"token_type":    "Bearer",
		})
	}
}

func handleListPosts(dm *datamapper.DataMapper, authz *authorization.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := breitheamh.AuthUser(r.Context())
		
		var posts []Post
		query := "SELECT * FROM posts WHERE published = 1"
		
		if user != nil {
			query += fmt.Sprintf(" OR user_id = %d", user.GetAuthIdentifier())
		}
		
		if err := dm.Query(r.Context(), &posts, query); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to fetch posts")
			return
		}

		respondJSON(w, http.StatusOK, posts)
	}
}

func handleViewPost(dm *datamapper.DataMapper, authz *authorization.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := breitheamh.AuthUser(r.Context())
		
		var post Post
		if err := dm.FindByID(r.Context(), "posts", cosan.Param(r, "id"), &post); err != nil {
			respondError(w, http.StatusNotFound, "Post not found")
			return
		}

		if !authz.Authorize(user, "view", &post) {
			respondError(w, http.StatusForbidden, "Access denied")
			return
		}

		respondJSON(w, http.StatusOK, post)
	}
}

func handleCreatePost(dm *datamapper.DataMapper, authz *authorization.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := breitheamh.AuthUser(r.Context())

		if !authz.Authorize(user, "create", &Post{}) {
			respondError(w, http.StatusForbidden, "Access denied")
			return
		}

		var req struct {
			Title     string `json:"title"`
			Content   string `json:"content"`
			Published bool   `json:"published"`
		}

		if err := parseJSON(r, &req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		post := &Post{
			UserID:    user.GetAuthIdentifier().(int64),
			Title:     req.Title,
			Content:   req.Content,
			Published: req.Published,
			CreatedAt: time.Now(),
		}

		if err := dm.Insert("posts", post); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to create post")
			return
		}

		respondJSON(w, http.StatusCreated, post)
	}
}

func handleUpdatePost(dm *datamapper.DataMapper, authz *authorization.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := breitheamh.AuthUser(r.Context())

		var post Post
		if err := dm.FindByID(r.Context(), "posts", cosan.Param(r, "id"), &post); err != nil {
			respondError(w, http.StatusNotFound, "Post not found")
			return
		}

		if !authz.Authorize(user, "update", &post) {
			respondError(w, http.StatusForbidden, "Access denied")
			return
		}

		var req struct {
			Title     string `json:"title"`
			Content   string `json:"content"`
			Published bool   `json:"published"`
		}

		if err := parseJSON(r, &req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		post.Title = req.Title
		post.Content = req.Content
		post.Published = req.Published

		if err := dm.Update("posts", post.ID, &post); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to update post")
			return
		}

		respondJSON(w, http.StatusOK, post)
	}
}

func handleDeletePost(dm *datamapper.DataMapper, authz *authorization.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := breitheamh.AuthUser(r.Context())

		var post Post
		if err := dm.FindByID(r.Context(), "posts", cosan.Param(r, "id"), &post); err != nil {
			respondError(w, http.StatusNotFound, "Post not found")
			return
		}

		if !authz.Authorize(user, "delete", &post) {
			respondError(w, http.StatusForbidden, "Access denied")
			return
		}

		if err := dm.Delete("posts", post.ID); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to delete post")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleListUsers(dm *datamapper.DataMapper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var users []User
		if err := dm.Query(r.Context(), &users, "SELECT * FROM users"); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to fetch users")
			return
		}

		for i := range users {
			users[i].Password = ""
		}

		respondJSON(w, http.StatusOK, users)
	}
}

func parseJSON(r *http.Request, v interface{}) error {
	return nil
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
