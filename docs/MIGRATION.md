# Migration Guide: From Custom Auth to Breitheamh

This guide helps you migrate from a custom authentication system to toutago-breitheamh-auth.

## Table of Contents

1. [Overview](#overview)
2. [Database Migration](#database-migration)
3. [Code Migration](#code-migration)
4. [Common Scenarios](#common-scenarios)
5. [Testing Your Migration](#testing-your-migration)

## Overview

Breitheamh provides a complete authentication and authorization system. This guide covers:

- Migrating your user database schema
- Replacing custom authentication code
- Migrating from session-based to JWT authentication
- Implementing role-based access control (RBAC)

## Database Migration

### User Table Schema

If you have an existing users table, you may need to add columns for Breitheamh features:

```sql
-- Add remember token column for persistent sessions
ALTER TABLE users ADD COLUMN remember_token VARCHAR(255);

-- Add password column if not present
ALTER TABLE users ADD COLUMN password VARCHAR(255);

-- Add timestamps if needed
ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
```

### Roles and Permissions Tables

Create the roles and permissions tables:

```sql
-- Roles table
CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    parent_id BIGINT REFERENCES roles(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table
CREATE TABLE permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User-Role pivot table
CREATE TABLE user_roles (
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- User-Permission pivot table
CREATE TABLE user_permissions (
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    permission_id BIGINT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, permission_id)
);

-- Role-Permission pivot table
CREATE TABLE role_permissions (
    role_id BIGINT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
```

### Password Migration

If you're migrating from a different password hashing algorithm:

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func migratePasswords(db *sql.DB) error {
    // Get all users
    rows, err := db.Query("SELECT id, old_password_hash FROM users")
    if err != nil {
        return err
    }
    defer rows.Close()

    hasher := breitheamh.NewBcryptHasher(12)
    
    for rows.Next() {
        var userID int64
        var oldHash string
        if err := rows.Scan(&userID, &oldHash); err != nil {
            return err
        }

        // You'll need to prompt users to reset passwords
        // or migrate if you have access to plaintext (not recommended)
        
        // Option 1: Set a flag requiring password reset
        _, err = db.Exec(
            "UPDATE users SET requires_password_reset = true WHERE id = $1",
            userID,
        )
        if err != nil {
            return err
        }
    }
    
    return nil
}
```

## Code Migration

### Step 1: Replace User Model

**Before:**
```go
type User struct {
    ID       int64
    Email    string
    Password string
}

func (u *User) CheckPassword(password string) bool {
    // Custom password checking
}
```

**After:**
```go
import "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"

type User struct {
    breitheamh.BaseUser
    // Add custom fields here
}

// BaseUser already provides:
// - ID, Email, Username, Password
// - GetAuthIdentifier(), GetAuthPassword()
// - HasRole(), HasPermission(), Can()
```

### Step 2: Replace Authentication Logic

**Before:**
```go
func login(email, password string) (*User, error) {
    user, err := db.GetUserByEmail(email)
    if err != nil {
        return nil, err
    }
    
    if !user.CheckPassword(password) {
        return nil, errors.New("invalid credentials")
    }
    
    // Create session
    sessionID := generateSessionID()
    saveSession(sessionID, user.ID)
    
    return user, nil
}
```

**After:**
```go
import (
    "context"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/providers"
)

func setupAuth(db *sql.DB) *breitheamh.GuardManager {
    // Create provider
    provider := providers.NewSQLProvider(db, &providers.SQLConfig{
        UserTable: "users",
    })
    
    // Create JWT guard
    jwtGuard := breitheamh.NewJWTGuard(provider, &breitheamh.JWTConfig{
        Secret:     []byte("your-secret-key"),
        Issuer:     "your-app",
        ExpireTime: 15 * time.Minute,
    })
    
    // Create guard manager
    manager := breitheamh.NewGuardManager()
    manager.AddGuard("jwt", jwtGuard)
    manager.SetDefaultGuard("jwt")
    
    return manager
}

func login(ctx context.Context, manager *breitheamh.GuardManager, email, password string) (string, error) {
    credentials := map[string]interface{}{
        "email":    email,
        "password": password,
    }
    
    guard := manager.Guard("jwt").(*breitheamh.JWTGuard)
    user, token, err := guard.Attempt(ctx, credentials)
    if err != nil {
        return "", err
    }
    
    // user is authenticated, token is the JWT
    return token, nil
}
```

### Step 3: Replace Authorization Logic

**Before:**
```go
func canEditPost(user *User, post *Post) bool {
    return user.ID == post.AuthorID || user.IsAdmin
}
```

**After:**
```go
import "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"

// Define a policy
type PostPolicy struct{}

func (p *PostPolicy) Update(user breitheamh.Authenticatable, post *Post) bool {
    return user.GetAuthIdentifier() == post.AuthorID || 
           user.HasRole("admin")
}

// Register the policy
registry := breitheamh.NewPolicyRegistry()
registry.Register(&Post{}, &PostPolicy{})

// Use the policy
func canEditPost(user breitheamh.Authenticatable, post *Post) bool {
    authorized, _ := registry.Authorize(user, "update", post)
    return authorized
}
```

### Step 4: Replace Middleware

**Before:**
```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        sessionID := getSessionID(r)
        userID := getSessionUserID(sessionID)
        if userID == 0 {
            http.Error(w, "Unauthorized", 401)
            return
        }
        
        user := getUserByID(userID)
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**After:**
```go
import "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"

func setupMiddleware(manager *breitheamh.GuardManager) func(http.Handler) http.Handler {
    return breitheamh.Authenticate(manager, "jwt", &breitheamh.AuthOptions{
        ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
            http.Error(w, "Unauthorized", 401)
        },
    })
}

// Use it
http.Handle("/api/", setupMiddleware(manager)(apiHandler))
```

## Common Scenarios

### Scenario 1: Migrating from Session-Based to JWT

```go
// Old session-based auth
func oldLogin(w http.ResponseWriter, r *http.Request) {
    // ... authenticate user ...
    
    session, _ := store.Get(r, "session-name")
    session.Values["user_id"] = user.ID
    session.Save(r, w)
}

// New JWT-based auth
func newLogin(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&creds)
    
    credentials := map[string]interface{}{
        "email":    creds.Email,
        "password": creds.Password,
    }
    
    guard := manager.Guard("jwt").(*breitheamh.JWTGuard)
    user, token, err := guard.Attempt(r.Context(), credentials)
    if err != nil {
        http.Error(w, "Invalid credentials", 401)
        return
    }
    
    json.NewEncoder(w).Encode(map[string]string{
        "token": token,
        "user_id": fmt.Sprint(user.GetAuthIdentifier()),
    })
}
```

### Scenario 2: Adding Roles to Existing Users

```go
func assignDefaultRoles(db *sql.DB) error {
    // Create default roles
    adminRole := &breitheamh.Role{
        Name: "Administrator",
        Slug: "admin",
    }
    userRole := &breitheamh.Role{
        Name: "User",
        Slug: "user",
    }
    
    // Insert roles
    db.Exec("INSERT INTO roles (name, slug) VALUES ($1, $2)", 
        adminRole.Name, adminRole.Slug)
    db.Exec("INSERT INTO roles (name, slug) VALUES ($1, $2)", 
        userRole.Name, userRole.Slug)
    
    // Assign all existing users to 'user' role
    db.Exec(`
        INSERT INTO user_roles (user_id, role_id)
        SELECT u.id, r.id FROM users u
        CROSS JOIN roles r
        WHERE r.slug = 'user'
    `)
    
    return nil
}
```

### Scenario 3: Custom User Fields

```go
// Extend BaseUser with custom fields
type AppUser struct {
    breitheamh.BaseUser
    
    // Custom fields
    CompanyID      int64
    IsActive       bool
    LastLoginAt    time.Time
    ProfilePicture string
}

// Implement custom provider if needed
type AppUserProvider struct {
    *providers.SQLProvider
}

func (p *AppUserProvider) RetrieveByID(ctx context.Context, id interface{}) (breitheamh.Authenticatable, error) {
    user := &AppUser{}
    query := `
        SELECT id, email, username, password, remember_token,
               company_id, is_active, last_login_at, profile_picture
        FROM users WHERE id = $1
    `
    
    err := p.DB.QueryRowContext(ctx, query, id).Scan(
        &user.ID, &user.Email, &user.Username, &user.Password,
        &user.RememberToken, &user.CompanyID, &user.IsActive,
        &user.LastLoginAt, &user.ProfilePicture,
    )
    
    if err != nil {
        return nil, err
    }
    
    // Load roles and permissions
    // ...
    
    return user, nil
}
```

## Testing Your Migration

### 1. Test Authentication Flow

```go
func TestMigratedAuth(t *testing.T) {
    // Setup
    db := setupTestDB()
    manager := setupAuth(db)
    
    // Create test user with old password hash
    // (if migrating passwords)
    
    // Test login
    ctx := context.Background()
    token, err := login(ctx, manager, "test@example.com", "password")
    if err != nil {
        t.Fatalf("Login failed: %v", err)
    }
    
    // Verify token
    guard := manager.Guard("jwt").(*breitheamh.JWTGuard)
    user, err := guard.ParseToken(ctx, token)
    if err != nil {
        t.Fatalf("Token parsing failed: %v", err)
    }
    
    if user.GetAuthIdentifier() == nil {
        t.Fatal("User not authenticated")
    }
}
```

### 2. Test Authorization

```go
func TestMigratedAuthz(t *testing.T) {
    user := &breitheamh.BaseUser{
        ID:    1,
        Email: "admin@example.com",
        Roles: []*breitheamh.Role{
            {Slug: "admin"},
        },
    }
    
    if !user.HasRole("admin") {
        t.Fatal("User should have admin role")
    }
    
    // Test permissions
    adminPerm := &breitheamh.Permission{Slug: "manage-users"}
    user.Roles[0].Permissions = []*breitheamh.Permission{adminPerm}
    
    if !user.HasPermission("manage-users") {
        t.Fatal("Admin should have manage-users permission")
    }
}
```

### 3. Test Middleware

```go
func TestMigratedMiddleware(t *testing.T) {
    manager := setupAuth(db)
    
    // Create test handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := breitheamh.AuthUser(r.Context())
        if user == nil {
            t.Fatal("User should be in context")
        }
        w.WriteHeader(200)
    })
    
    // Wrap with auth middleware
    protected := breitheamh.Authenticate(manager, "jwt", nil)(handler)
    
    // Create request with valid token
    token := createTestToken(manager)
    req := httptest.NewRequest("GET", "/protected", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    
    rr := httptest.NewRecorder()
    protected.ServeHTTP(rr, req)
    
    if rr.Code != 200 {
        t.Fatalf("Expected 200, got %d", rr.Code)
    }
}
```

## Checklist

- [ ] Backup your database before migration
- [ ] Update database schema (add columns, create tables)
- [ ] Migrate user data
- [ ] Update user model to embed `BaseUser` or implement `Authenticatable`
- [ ] Replace authentication logic with Breitheamh guards
- [ ] Replace authorization logic with roles/permissions/policies
- [ ] Update middleware to use Breitheamh middleware
- [ ] Test login flow
- [ ] Test authorization checks
- [ ] Test API endpoints with new authentication
- [ ] Update frontend to handle JWT tokens (if applicable)
- [ ] Monitor logs for authentication errors
- [ ] Plan for password reset for users (if changing hash algorithm)

## Need Help?

- Check the [main README](../README.md) for comprehensive documentation
- See [QUICK_START.md](QUICK_START.md) for basic usage
- Review [examples/](../examples/) for complete working examples
- Open an issue on GitHub if you encounter problems
