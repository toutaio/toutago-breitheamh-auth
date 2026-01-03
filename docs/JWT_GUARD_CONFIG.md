# JWT Guard Configuration

This guide covers configuring and using the JWT (JSON Web Token) authentication guard in Breitheamh Auth.

## Overview

The JWT guard provides stateless authentication using JSON Web Tokens, making it ideal for:
- RESTful APIs
- Microservices
- Single-page applications (SPAs)
- Mobile applications

## Basic Configuration

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Create JWT guard with configuration
guard := breitheamh.NewJWTGuard(breitheamh.JWTConfig{
    SecretKey:          "your-secret-key-min-32-chars",
    AccessTokenExpiry:  15 * time.Minute,
    RefreshTokenExpiry: 7 * 24 * time.Hour,
    Issuer:             "your-app-name",
})
```

## Configuration Options

### SecretKey

The secret key used to sign and verify JWT tokens. **Must be at least 32 characters** for security.

```go
SecretKey: "your-very-secure-secret-key-here-minimum-32-characters"
```

**Security Notes:**
- Store in environment variables, never hardcode
- Use cryptographically random strings
- Rotate regularly in production
- Use different keys for different environments

### Token Expiry Times

Control how long tokens remain valid:

```go
// Short-lived access tokens (recommended: 5-30 minutes)
AccessTokenExpiry: 15 * time.Minute,

// Longer-lived refresh tokens (recommended: 1-7 days)
RefreshTokenExpiry: 7 * 24 * time.Hour,
```

**Best Practices:**
- Keep access tokens short-lived (5-30 minutes)
- Use refresh tokens for extended sessions
- Balance security vs. user experience

### Issuer

Identifies the issuer of the token:

```go
Issuer: "myapp.example.com",
```

This is validated during token verification to prevent token reuse across applications.

## Using the JWT Guard

### 1. User Login

```go
// Authenticate user and get tokens
tokens, err := guard.Login(ctx, map[string]interface{}{
    "email":    "user@example.com",
    "password": "secret",
})
if err != nil {
    // Handle authentication failure
}

// tokens contains:
// - AccessToken: short-lived token for API requests
// - RefreshToken: long-lived token for obtaining new access tokens
```

### 2. Validating Access Tokens

```go
// Extract token from Authorization header
token := extractBearerToken(r.Header.Get("Authorization"))

// Validate and get user
user, err := guard.User(ctx, token)
if err != nil {
    // Handle invalid/expired token
}

// User is authenticated, proceed with request
```

### 3. Refreshing Tokens

When an access token expires, use the refresh token to obtain a new pair:

```go
// Use refresh token to get new tokens
newTokens, err := guard.Refresh(ctx, refreshToken)
if err != nil {
    // Refresh token is invalid or expired
    // User must re-authenticate
}

// Issue new tokens to client
```

### 4. Token Revocation

Logout or revoke tokens:

```go
// Revoke a specific token
err := guard.Revoke(ctx, token)

// Or use the token blacklist
guard.BlacklistToken(token)
```

## Token Structure

JWT tokens contain three parts: header, payload, and signature.

### Access Token Claims

```json
{
  "sub": "user-id",
  "iss": "your-app-name",
  "exp": 1234567890,
  "iat": 1234567000,
  "type": "access"
}
```

### Refresh Token Claims

```json
{
  "sub": "user-id",
  "iss": "your-app-name",
  "exp": 1234567890,
  "iat": 1234567000,
  "type": "refresh"
}
```

## HTTP Integration

### Middleware Example

```go
// Authentication middleware
func AuthMiddleware(guard *breitheamh.JWTGuard) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract token
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            token := strings.TrimPrefix(authHeader, "Bearer ")
            
            // Validate token and get user
            user, err := guard.User(r.Context(), token)
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Add user to context
            ctx := breitheamh.WithUser(r.Context(), user)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Login Endpoint

```go
func LoginHandler(guard *breitheamh.JWTGuard) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var credentials struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }
        
        if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }

        tokens, err := guard.Login(r.Context(), map[string]interface{}{
            "email":    credentials.Email,
            "password": credentials.Password,
        })
        if err != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }

        json.NewEncoder(w).Encode(tokens)
    }
}
```

### Refresh Endpoint

```go
func RefreshHandler(guard *breitheamh.JWTGuard) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var request struct {
            RefreshToken string `json:"refresh_token"`
        }
        
        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }

        tokens, err := guard.Refresh(r.Context(), request.RefreshToken)
        if err != nil {
            http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
            return
        }

        json.NewEncoder(w).Encode(tokens)
    }
}
```

## Advanced Configuration

### Custom User Provider

```go
type CustomUserProvider struct {
    db *sql.DB
}

func (p *CustomUserProvider) RetrieveByID(ctx context.Context, id interface{}) (breitheamh.User, error) {
    // Custom database lookup
}

func (p *CustomUserProvider) RetrieveByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
    // Custom credential verification
}

// Use with guard
guard := breitheamh.NewJWTGuard(breitheamh.JWTConfig{
    SecretKey: os.Getenv("JWT_SECRET"),
    // ... other config
})
guard.SetProvider(&CustomUserProvider{db: db})
```

### Token Blacklist

For logout functionality, implement token blacklisting:

```go
// In-memory blacklist (use Redis in production)
var blacklist = make(map[string]time.Time)
var blacklistMu sync.RWMutex

func BlacklistToken(token string, expiresAt time.Time) {
    blacklistMu.Lock()
    defer blacklistMu.Unlock()
    blacklist[token] = expiresAt
}

func IsBlacklisted(token string) bool {
    blacklistMu.RLock()
    defer blacklistMu.RUnlock()
    
    expiresAt, exists := blacklist[token]
    if !exists {
        return false
    }
    
    // Clean up expired entries
    if time.Now().After(expiresAt) {
        delete(blacklist, token)
        return false
    }
    
    return true
}
```

## Security Considerations

### 1. Token Storage

**Client-side:**
- Use `httpOnly` cookies for web apps (prevents XSS)
- Use secure storage on mobile (Keychain/Keystore)
- Never store in localStorage if possible

### 2. HTTPS Only

Always use HTTPS in production to prevent token interception.

### 3. Token Rotation

Implement refresh token rotation:

```go
// Each refresh generates a new refresh token
// Invalidate the old refresh token
newTokens, err := guard.Refresh(ctx, oldRefreshToken)
// Blacklist oldRefreshToken
```

### 4. Audience and Issuer Validation

```go
// Validate issuer matches expected value
// Prevents cross-application token reuse
```

### 5. Short Expiry Times

Keep access tokens short-lived (5-30 minutes) to limit exposure window.

## Troubleshooting

### "Token has expired"

Access tokens expire quickly by design. Use refresh tokens to obtain new access tokens.

### "Invalid signature"

- Secret key mismatch between issuing and validating servers
- Token was tampered with
- Using wrong secret key for environment

### "Token not yet valid"

Clock skew between servers. Add clock skew tolerance if needed.

## Example: Complete API Server

```go
package main

import (
    "net/http"
    "os"
    "time"
    
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Initialize JWT guard
    guard := breitheamh.NewJWTGuard(breitheamh.JWTConfig{
        SecretKey:          os.Getenv("JWT_SECRET"),
        AccessTokenExpiry:  15 * time.Minute,
        RefreshTokenExpiry: 7 * 24 * time.Hour,
        Issuer:             "myapp",
    })

    // Public endpoints
    http.HandleFunc("/api/login", LoginHandler(guard))
    http.HandleFunc("/api/refresh", RefreshHandler(guard))

    // Protected endpoints
    protected := http.NewServeMux()
    protected.HandleFunc("/api/me", MeHandler)
    protected.HandleFunc("/api/posts", PostsHandler)

    http.Handle("/api/", AuthMiddleware(guard)(protected))

    http.ListenAndServe(":8080", nil)
}
```

## Related Documentation

- [Authentication Guide](AUTHENTICATION_GUIDE.md) - General authentication concepts
- [Middleware Guide](MIDDLEWARE_GUIDE.md) - HTTP middleware integration
- [Security Best Practices](SECURITY_BEST_PRACTICES.md) - Security guidelines
