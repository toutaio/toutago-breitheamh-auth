# Authentication Guide

This guide covers the authentication capabilities of **Breitheamh** (pronounced "BREH-huv"), the authentication and authorization library for Go.

## Table of Contents

- [Overview](#overview)
- [Guards](#guards)
- [User Provider](#user-provider)
- [JWT Authentication](#jwt-authentication)
- [Session-Based Authentication](#session-based-authentication)
- [API Token Authentication](#api-token-authentication)
- [Multi-Guard Setup](#multi-guard-setup)
- [Context-Based Authentication](#context-based-authentication)

## Overview

Breitheamh provides a flexible authentication system based on **guards**. A guard is responsible for authenticating users and managing their authentication state. Different guards can be used for different parts of your application (web, API, admin, etc.).

## Guards

A guard implements the `Guard` interface:

```go
type Guard interface {
    Attempt(ctx context.Context, credentials map[string]interface{}) (User, error)
    User(ctx context.Context) (User, error)
    Check(ctx context.Context) bool
    Guest(ctx context.Context) bool
    ID(ctx context.Context) (string, error)
    Logout(ctx context.Context) error
}
```

### Available Guards

1. **JWT Guard** - Token-based authentication for APIs
2. **Session Guard** - Cookie-based authentication for web apps
3. **API Token Guard** - Static token authentication

## User Provider

The `UserProvider` interface abstracts user storage:

```go
type UserProvider interface {
    RetrieveByID(id string) (User, error)
    RetrieveByCredentials(credentials map[string]interface{}) (User, error)
    ValidateCredentials(user User, credentials map[string]interface{}) bool
}
```

Implement this interface to connect Breitheamh to your user storage system.

### Memory Provider Example

```go
provider := breitheamh.NewMemoryUserProvider()
provider.AddUser(&breitheamh.BaseUser{
    UserID:       "1",
    UserEmail:    "admin@example.com",
    UserPassword: hashedPassword,
    UserRoles:    []breitheamh.Role{{Name: "admin"}},
})
```

## JWT Authentication

JWT (JSON Web Token) authentication is ideal for stateless APIs.

### Setup

```go
import (
    "time"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Create JWT config
config := &breitheamh.JWTConfig{
    SecretKey:            []byte("your-secret-key"),
    AccessTokenDuration:  15 * time.Minute,
    RefreshTokenDuration: 7 * 24 * time.Hour,
    Issuer:              "your-app",
}

// Create guard
jwtGuard := breitheamh.NewJWTGuard(config, userProvider)
```

### Authenticate User

```go
ctx := context.Background()

// Attempt login
user, err := jwtGuard.Attempt(ctx, map[string]interface{}{
    "email":    "user@example.com",
    "password": "secret",
})
if err != nil {
    // Handle authentication failure
    log.Printf("Login failed: %v", err)
    return
}

// Generate tokens
accessToken, refreshToken, err := jwtGuard.GenerateTokens(user)
if err != nil {
    log.Printf("Token generation failed: %v", err)
    return
}

// Return tokens to client
fmt.Printf("Access Token: %s\n", accessToken)
fmt.Printf("Refresh Token: %s\n", refreshToken)
```

### Validate Token

```go
// Extract token from Authorization header
tokenString := extractBearerToken(r.Header.Get("Authorization"))

// Verify and parse token
claims, err := jwtGuard.VerifyToken(tokenString)
if err != nil {
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}

// Get user ID from claims
userID := claims.Subject

// Store in context for later use
ctx = context.WithValue(r.Context(), "user_id", userID)
```

### Refresh Tokens

```go
// Verify refresh token
claims, err := jwtGuard.VerifyToken(refreshToken)
if err != nil {
    return err
}

// Check if it's a refresh token
if claims.TokenType != "refresh" {
    return errors.New("invalid token type")
}

// Generate new tokens
user, err := userProvider.RetrieveByID(claims.Subject)
if err != nil {
    return err
}

newAccessToken, newRefreshToken, err := jwtGuard.GenerateTokens(user)
```

## Session-Based Authentication

Session-based authentication is ideal for traditional web applications.

### Setup

```go
config := &breitheamh.SessionConfig{
    SessionStore:  sessionStore,  // Your session storage implementation
    CookieName:    "session_id",
    CookiePath:    "/",
    CookieDomain:  "",
    CookieSecure:  true,
    CookieHTTPOnly: true,
    SessionTTL:    24 * time.Hour,
}

sessionGuard := breitheamh.NewSessionGuard(config, userProvider)
```

### Login

```go
// Attempt login
user, err := sessionGuard.Attempt(ctx, map[string]interface{}{
    "email":    "user@example.com",
    "password": "secret",
})
if err != nil {
    http.Error(w, "Invalid credentials", http.StatusUnauthorized)
    return
}

// Session is automatically created and cookie set
http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
```

### Check Authentication

```go
// In your HTTP handler
ctx := r.Context()

if sessionGuard.Check(ctx) {
    user, _ := sessionGuard.User(ctx)
    fmt.Printf("Authenticated user: %s\n", user.GetEmail())
} else {
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}
```

### Logout

```go
err := sessionGuard.Logout(ctx)
if err != nil {
    log.Printf("Logout failed: %v", err)
}
http.Redirect(w, r, "/", http.StatusSeeOther)
```

## API Token Authentication

API token authentication uses long-lived static tokens for API access.

### Setup

```go
tokenStore := breitheamh.NewMemoryTokenStore()
apiGuard := breitheamh.NewAPITokenGuard(tokenStore, userProvider)
```

### Generate Token

```go
token, err := apiGuard.GenerateToken(user, "My API Client", nil)
if err != nil {
    return err
}

fmt.Printf("API Token: %s\n", token.Token)
```

### Authenticate with Token

```go
// Extract token from header
tokenString := r.Header.Get("X-API-Token")

ctx = context.WithValue(r.Context(), "api_token", tokenString)

if apiGuard.Check(ctx) {
    user, _ := apiGuard.User(ctx)
    // Process request
} else {
    http.Error(w, "Invalid API token", http.StatusUnauthorized)
}
```

## Multi-Guard Setup

Use different guards for different parts of your application.

```go
guards := map[string]breitheamh.Guard{
    "web":   sessionGuard,
    "api":   jwtGuard,
    "admin": adminSessionGuard,
}

manager := breitheamh.NewGuardManager(guards, "web")
```

### Use Specific Guard

```go
// Get API guard
apiGuard := manager.Guard("api")

// Authenticate
user, err := apiGuard.Attempt(ctx, credentials)
```

## Context-Based Authentication

Store authentication information in the request context.

```go
// Store user in context after authentication
ctx = context.WithValue(ctx, breitheamh.UserContextKey, user)

// Retrieve user from context
if userVal := ctx.Value(breitheamh.UserContextKey); userVal != nil {
    user := userVal.(breitheamh.User)
    fmt.Printf("Current user: %s\n", user.GetEmail())
}
```

### Custom Context Keys

```go
const (
    UserContextKey  = "breitheamh.user"
    TokenContextKey = "breitheamh.token"
    GuardContextKey = "breitheamh.guard"
)
```

## Best Practices

### 1. Secure Secret Keys

```go
// Use strong, random secret keys
secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))
if len(secretKey) < 32 {
    log.Fatal("JWT secret key must be at least 32 bytes")
}
```

### 2. Token Expiration

```go
// Use short-lived access tokens
AccessTokenDuration: 15 * time.Minute,

// Use longer-lived refresh tokens
RefreshTokenDuration: 7 * 24 * time.Hour,
```

### 3. Password Hashing

```go
// Always use strong password hashing
hasher := breitheamh.NewArgon2Hasher()
hashedPassword, err := hasher.Hash("password123")
```

### 4. HTTPS Only

```go
// Always use secure cookies in production
config := &breitheamh.SessionConfig{
    CookieSecure:   true,  // Requires HTTPS
    CookieHTTPOnly: true,  // Prevents XSS
    CookieSameSite: http.SameSiteStrictMode,
}
```

### 5. Token Revocation

```go
// Implement token blacklist for logout
err := jwtGuard.RevokeToken(tokenString)
```

## Next Steps

- Read the [Authorization Guide](AUTHORIZATION_GUIDE.md) for roles, permissions, and policies
- See [Middleware Integration Guide](MIDDLEWARE_GUIDE.md) for HTTP middleware
- Check [examples/](../examples/) for complete working examples
