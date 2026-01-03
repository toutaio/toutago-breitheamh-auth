package main

import (
	"fmt"
	"log"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// This example demonstrates how to integrate toutago-breitheamh-auth with
// toutago-datamapper for database-backed authentication.
//
// Note: This is a conceptual example showing the integration pattern.
// In a real application, you would:
// 1. Import the actual toutago-datamapper package
// 2. Configure your database connection
// 3. Define your database schema
// 4. Implement the UserProvider interface using datamapper

// User represents a database user model
type User struct {
	ID                int       `db:"id"`
	Email             string    `db:"email"`
	Name              string    `db:"name"`
	Password          string    `db:"password"`
	RememberToken     string    `db:"remember_token"`
	TwoFactorSecret   string    `db:"two_factor_secret"`
	TwoFactorEnabled  bool      `db:"two_factor_enabled"`
	EmailVerifiedAt   *time.Time `db:"email_verified_at"`
	AccountLockedAt   *time.Time `db:"account_locked_at"`
	FailedLoginCount  int       `db:"failed_login_count"`
	LastLoginAt       *time.Time `db:"last_login_at"`
	CreatedAt         time.Time `db:"created_at"`
	UpdatedAt         time.Time `db:"updated_at"`
}

// Role represents a database role model
type Role struct {
	ID          int       `db:"id"`
	Name        string    `db:"name"`
	DisplayName string    `db:"display_name"`
	Description string    `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// Permission represents a database permission model
type Permission struct {
	ID          int       `db:"id"`
	Name        string    `db:"name"`
	DisplayName string    `db:"display_name"`
	Description string    `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// DatamapperUserProvider implements breitheamh.UserProvider using datamapper
type DatamapperUserProvider struct {
	// In real implementation, this would be:
	// mapper *datamapper.DataMapper
	// For this example, we'll use an in-memory map
	users map[string]*User
	roles map[int]*Role
	userRoles map[int][]int // userID -> roleIDs
	rolePermissions map[int][]int // roleID -> permissionIDs
	permissions map[int]*Permission
}

// NewDatamapperUserProvider creates a new datamapper-backed user provider
func NewDatamapperUserProvider() *DatamapperUserProvider {
	return &DatamapperUserProvider{
		users:           make(map[string]*User),
		roles:           make(map[int]*Role),
		userRoles:       make(map[int][]int),
		rolePermissions: make(map[int][]int),
		permissions:     make(map[int]*Permission),
	}
}

// RetrieveByID retrieves a user by ID
func (p *DatamapperUserProvider) RetrieveByID(id interface{}) (breitheamh.User, error) {
	// In real implementation:
	// var user User
	// err := p.mapper.FindByID(&user, id)
	
	for _, u := range p.users {
		if u.ID == id.(int) {
			return p.convertToBreitheamhUser(u), nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// RetrieveByCredentials retrieves a user by credentials
func (p *DatamapperUserProvider) RetrieveByCredentials(credentials map[string]interface{}) (breitheamh.User, error) {
	email, ok := credentials["email"].(string)
	if !ok {
		return nil, fmt.Errorf("email not provided")
	}

	// In real implementation:
	// var user User
	// err := p.mapper.Where("email = ?", email).First(&user)
	
	user, ok := p.users[email]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	return p.convertToBreitheamhUser(user), nil
}

// UpdateRememberToken updates the user's remember token
func (p *DatamapperUserProvider) UpdateRememberToken(user breitheamh.User, token string) error {
	// In real implementation:
	// return p.mapper.Where("id = ?", user.GetID()).Update(map[string]interface{}{
	//     "remember_token": token,
	//     "updated_at": time.Now(),
	// })
	
	if u, ok := p.users[user.GetEmail()]; ok {
		u.RememberToken = token
		u.UpdatedAt = time.Now()
	}
	return nil
}

// convertToBreitheamhUser converts a database user to a breitheamh user
func (p *DatamapperUserProvider) convertToBreitheamhUser(dbUser *User) breitheamh.User {
	user := breitheamh.NewBaseUser(dbUser.ID, dbUser.Email, dbUser.Name)
	user.SetPassword(dbUser.Password)
	user.SetRememberToken(dbUser.RememberToken)
	
	if dbUser.TwoFactorEnabled {
		user.SetTwoFactorSecret(dbUser.TwoFactorSecret)
		user.EnableTwoFactor()
	}
	
	if dbUser.EmailVerifiedAt != nil {
		user.MarkEmailAsVerified()
	}
	
	if dbUser.AccountLockedAt != nil {
		user.LockAccount()
	}

	// Load roles
	if roleIDs, ok := p.userRoles[dbUser.ID]; ok {
		for _, roleID := range roleIDs {
			if role, ok := p.roles[roleID]; ok {
				breitheamhRole := breitheamh.NewRole(role.Name, role.DisplayName)
				
				// Load permissions for this role
				if permIDs, ok := p.rolePermissions[roleID]; ok {
					for _, permID := range permIDs {
						if perm, ok := p.permissions[permID]; ok {
							breitheamhPerm := breitheamh.NewPermission(perm.Name, perm.DisplayName)
							breitheamhRole.GrantPermission(breitheamhPerm)
						}
					}
				}
				
				user.AssignRole(breitheamhRole)
			}
		}
	}

	return user
}

// Seed example data
func (p *DatamapperUserProvider) seed() {
	// Create permissions
	p.permissions[1] = &Permission{ID: 1, Name: "posts.create", DisplayName: "Create Posts"}
	p.permissions[2] = &Permission{ID: 2, Name: "posts.edit", DisplayName: "Edit Posts"}
	p.permissions[3] = &Permission{ID: 3, Name: "posts.delete", DisplayName: "Delete Posts"}
	p.permissions[4] = &Permission{ID: 4, Name: "users.manage", DisplayName: "Manage Users"}

	// Create roles
	p.roles[1] = &Role{ID: 1, Name: "admin", DisplayName: "Administrator"}
	p.roles[2] = &Role{ID: 2, Name: "editor", DisplayName: "Editor"}

	// Assign permissions to roles
	p.rolePermissions[1] = []int{1, 2, 3, 4} // admin has all permissions
	p.rolePermissions[2] = []int{1, 2}       // editor can create and edit posts

	// Create users
	adminHash, _ := breitheamh.HashPasswordBcrypt("admin123", 10)
	p.users["admin@example.com"] = &User{
		ID:       1,
		Email:    "admin@example.com",
		Name:     "Admin User",
		Password: adminHash,
		EmailVerifiedAt: &time.Time{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	editorHash, _ := breitheamh.HashPasswordBcrypt("editor123", 10)
	p.users["editor@example.com"] = &User{
		ID:       2,
		Email:    "editor@example.com",
		Name:     "Editor User",
		Password: editorHash,
		EmailVerifiedAt: &time.Time{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Assign roles to users
	p.userRoles[1] = []int{1} // admin user has admin role
	p.userRoles[2] = []int{2} // editor user has editor role
}

func main() {
	fmt.Println("=== Datamapper Integration Example ===\n")

	// Create datamapper-backed provider
	provider := NewDatamapperUserProvider()
	provider.seed()

	// Create JWT guard with datamapper provider
	jwtGuard := breitheamh.NewJWTGuard("secret-key", provider, 24*time.Hour)

	// Example 1: Authenticate admin user
	fmt.Println("Example 1: Admin Login")
	adminCreds := map[string]interface{}{
		"email":    "admin@example.com",
		"password": "admin123",
	}

	token, err := jwtGuard.Attempt(adminCreds)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	fmt.Printf("✓ Admin authenticated\n")
	fmt.Printf("Token: %s...\n", token[:50])

	user, _ := jwtGuard.User()
	fmt.Printf("User: %s (%s)\n", user.GetName(), user.GetEmail())
	fmt.Printf("Roles: %v\n", getRoleNames(user))
	fmt.Printf("Can create posts: %t\n", user.HasPermission("posts.create"))
	fmt.Printf("Can manage users: %t\n", user.HasPermission("users.manage"))

	// Example 2: Authenticate editor user
	fmt.Println("\nExample 2: Editor Login")
	editorCreds := map[string]interface{}{
		"email":    "editor@example.com",
		"password": "editor123",
	}

	token, err = jwtGuard.Attempt(editorCreds)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	fmt.Printf("✓ Editor authenticated\n")
	fmt.Printf("Token: %s...\n", token[:50])

	user, _ = jwtGuard.User()
	fmt.Printf("User: %s (%s)\n", user.GetName(), user.GetEmail())
	fmt.Printf("Roles: %v\n", getRoleNames(user))
	fmt.Printf("Can create posts: %t\n", user.HasPermission("posts.create"))
	fmt.Printf("Can edit posts: %t\n", user.HasPermission("posts.edit"))
	fmt.Printf("Can delete posts: %t\n", user.HasPermission("posts.delete"))
	fmt.Printf("Can manage users: %t\n", user.HasPermission("users.manage"))

	// Example 3: Token validation
	fmt.Println("\nExample 3: Token Validation")
	validatedUser, err := jwtGuard.ValidateToken(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Printf("✓ Token validated\n")
	fmt.Printf("User from token: %s\n", validatedUser.GetEmail())

	fmt.Println("\n=== Integration Complete ===")
	fmt.Println("\nDatabase Schema Example:")
	fmt.Println(getDatabaseSchema())
}

func getRoleNames(user breitheamh.User) []string {
	roles := user.GetRoles()
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = role.GetName()
	}
	return names
}

func getDatabaseSchema() string {
	return `
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    remember_token VARCHAR(255),
    two_factor_secret VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,
    account_locked_at TIMESTAMP,
    failed_login_count INTEGER DEFAULT 0,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles table
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User-Role pivot table
CREATE TABLE user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Role-Permission pivot table
CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User-Permission pivot table (for direct permission grants)
CREATE TABLE user_permissions (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, permission_id)
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_permissions_name ON permissions(name);
`
}
