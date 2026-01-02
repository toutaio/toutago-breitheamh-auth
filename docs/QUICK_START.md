# Quick Start Guide

Get started with Breitheamh Auth in 5 minutes.

## Installation

```bash
go get github.com/toutaio/toutago-breitheamh-auth
```

## Basic Setup

### 1. Password Hashing

```go
import "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"

// Create a hasher
hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)

// Hash a password
hashed, _ := hasher.Hash("secret123")

// Verify a password
err := hasher.Verify("secret123", hashed)
if err != nil {
    // Wrong password
}
```

### 2. User Management

```go
// Create a user
user := breitheamh.NewBaseUser("user-1", "alice@example.com", hashedPassword)

// Assign permissions
user.GivePermission(breitheamh.Permission{
    ID:   "perm-1",
    Name: "posts.create",
})

// Check permissions
if user.HasPermission("posts.create") {
    // User can create posts
}
```

### 3. Wildcard Permissions

```go
// Grant wildcard permission
user.GivePermission(breitheamh.Permission{
    ID:   "perm-2",
    Name: "users.*",
})

// All of these will pass
user.HasPermission("users.create")  // true
user.HasPermission("users.edit")    // true
user.HasPermission("users.delete")  // true
```

### 4. Role-Based Access Control

```go
// Create a role with permissions
editorRole := breitheamh.Role{
    ID:   "role-1",
    Name: "editor",
    Permissions: []breitheamh.Permission{
        {ID: "1", Name: "posts.create"},
        {ID: "2", Name: "posts.edit"},
    },
}

// Assign role to user
user.AssignRole(editorRole)

// Check role
if user.HasRole("editor") {
    // User is an editor
}
```

## JWT Authentication

### 1. Setup

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Create user provider (use memory for testing, SQL for production)
provider := memory.NewProvider()
provider.AddUser(user)

// Configure JWT
jwtConfig := breitheamh.DefaultJWTConfig("your-secret-key-min-32-chars")
tokenManager := breitheamh.NewJWTTokenManager(jwtConfig)

// Create guard
guard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)
```

### 2. Login

```go
ctx := context.Background()

// Authenticate and get token
user, token, err := guard.Attempt(ctx, breitheamh.Credentials{
    Email:    "alice@example.com",
    Password: "secret123",
})

if err != nil {
    // Authentication failed
}

// Use the token
fmt.Println("Access Token:", token.AccessToken)
fmt.Println("Refresh Token:", token.RefreshToken)
fmt.Println("Expires In:", token.ExpiresIn, "seconds")
```

### 3. Validate Token

```go
// Validate token from request
user, err := guard.Validate(ctx, tokenString)
if err != nil {
    // Invalid or expired token
}

// User is authenticated
fmt.Println("Authenticated user:", user.GetID())
```

## Authorization

### Gates

```go
authorizer := breitheamh.NewAuthorizer()

// Define a custom gate
authorizer.DefineGate("view-dashboard", func(ctx context.Context, user breitheamh.User, args ...interface{}) bool {
    return user.HasRole("admin") || user.HasRole("manager")
})

// Check gate
if authorizer.Allows(ctx, "view-dashboard", user) {
    // User can view dashboard
}
```

### Permission Gates

```go
gate := breitheamh.NewPermissionGate("create-posts", "posts.create")

if gate.Allows(ctx, user) {
    // User has posts.create permission
}
```

### Role Gates

```go
gate := breitheamh.NewRoleGate("admin-only", "admin")

if gate.Denies(ctx, user) {
    // User is not an admin
}
```

## Multi-Guard Setup

```go
manager := breitheamh.NewGuardManager()

// Register multiple guards
manager.RegisterGuard("jwt", jwtGuard)
manager.RegisterGuard("session", sessionGuard)

// Use specific guard
guard := manager.Guard("jwt")

// Or use default
defaultGuard := manager.DefaultGuard()
```

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic-auth/` - Password hashing, permissions, JWT
- `examples/policy-authorization/` - Gates and authorization patterns

## Next Steps

- Read the [Authentication Guide](AUTHENTICATION.md) (coming soon)
- Read the [Authorization Guide](AUTHORIZATION.md) (coming soon)
- Explore the [API Reference](https://pkg.go.dev/github.com/toutaio/toutago-breitheamh-auth)
- Check out the [examples](examples/)

## Common Patterns

### API Authentication

```go
// In your HTTP handler
token := extractTokenFromHeader(r)
user, err := guard.Validate(ctx, token)
if err != nil {
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}

// Use authenticated user
// ...
```

### Permission Middleware

```go
func RequirePermission(permission string) middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := getUserFromContext(r.Context())
            
            if !user.HasPermission(permission) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

### Role Middleware

```go
func RequireRole(role string) middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := getUserFromContext(r.Context())
            
            if !user.HasRole(role) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

## Tips

- Always use environment variables for secret keys in production
- Use bcrypt for general use, argon2 for maximum security
- Implement rate limiting on authentication endpoints
- Store refresh tokens securely
- Use HTTPS in production
- Implement account locking after failed attempts
- Log authentication events for audit trails
