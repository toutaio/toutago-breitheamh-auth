# Session Guard Usage

This guide covers configuring and using the session-based authentication guard in Breitheamh Auth.

## Overview

The session guard provides traditional session-based authentication using server-side session storage, making it ideal for:
- Traditional web applications
- Server-rendered pages
- Applications requiring immediate session invalidation
- Multi-tab synchronization

## Basic Configuration

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Create session guard with in-memory storage
store := breitheamh.NewMemorySessionStore()
guard := breitheamh.NewSessionGuard(store, breitheamh.SessionConfig{
    SessionName:   "auth_session",
    SessionExpiry: 24 * time.Hour,
    CookiePath:    "/",
    CookieDomain:  "",
    SecureCookie:  true,
    HTTPOnlyCookie: true,
    SameSite:      http.SameSiteStrictMode,
})
```

## Configuration Options

### SessionName

The name of the session cookie:

```go
SessionName: "auth_session",
```

Choose a descriptive name that doesn't conflict with other cookies.

### SessionExpiry

How long sessions remain valid:

```go
SessionExpiry: 24 * time.Hour,  // 1 day
// or
SessionExpiry: 7 * 24 * time.Hour,  // 1 week
```

### Cookie Configuration

Control cookie security and behavior:

```go
CookiePath: "/",              // Cookie available on all paths
CookieDomain: "",             // Current domain only
SecureCookie: true,           // HTTPS only (required in production)
HTTPOnlyCookie: true,         // Not accessible via JavaScript
SameSite: http.SameSiteStrictMode,  // CSRF protection
```

**Security Settings:**
- `SecureCookie`: Always `true` in production (requires HTTPS)
- `HTTPOnlyCookie`: `true` prevents XSS attacks
- `SameSite`: `Strict` for maximum security, `Lax` for usability

## Session Storage Options

### In-Memory Storage

Suitable for development and single-server deployments:

```go
store := breitheamh.NewMemorySessionStore()
```

**Pros:**
- Fast
- Simple
- No external dependencies

**Cons:**
- Not suitable for multi-server deployments
- Sessions lost on server restart
- No built-in cleanup

### Redis Storage

Recommended for production and distributed systems:

```go
import "github.com/go-redis/redis/v8"

redisClient := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})

store := breitheamh.NewRedisSessionStore(redisClient, breitheamh.RedisConfig{
    KeyPrefix: "session:",
    MaxIdle:   10,
    MaxActive: 100,
})
```

**Pros:**
- Scales horizontally
- Persists across restarts
- Automatic expiration
- Fast lookups

### Database Storage

For persistence without Redis:

```go
store := breitheamh.NewDatabaseSessionStore(db, breitheamh.DBSessionConfig{
    TableName: "sessions",
    CleanupInterval: 1 * time.Hour,
})
```

## Using the Session Guard

### 1. User Login

```go
// Authenticate and create session
err := guard.Login(w, r, map[string]interface{}{
    "email":    "user@example.com",
    "password": "secret",
}, true) // true = remember me
if err != nil {
    // Handle authentication failure
}

// Session cookie is automatically set in response
```

### 2. Getting Current User

```go
// Retrieve authenticated user from session
user, err := guard.User(r)
if err != nil {
    // No valid session or session expired
}

// User is authenticated
```

### 3. Logout

```go
// Destroy session and clear cookie
err := guard.Logout(w, r)
if err != nil {
    // Handle error
}

// User is logged out, session deleted
```

### 4. Session Regeneration

For security, regenerate session ID after login:

```go
// Prevent session fixation attacks
err := guard.RegenerateSession(w, r)
```

## HTTP Integration

### Middleware Example

```go
func SessionAuthMiddleware(guard *breitheamh.SessionGuard) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get user from session
            user, err := guard.User(r)
            if err != nil {
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }

            // Add user to context
            ctx := breitheamh.WithUser(r.Context(), user)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Login Handler

```go
func LoginHandler(guard *breitheamh.SessionGuard) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            // Render login form
            renderLoginForm(w)
            return
        }

        email := r.FormValue("email")
        password := r.FormValue("password")
        remember := r.FormValue("remember") == "on"

        err := guard.Login(w, r, map[string]interface{}{
            "email":    email,
            "password": password,
        }, remember)
        
        if err != nil {
            // Show error and login form
            renderLoginForm(w, "Invalid credentials")
            return
        }

        // Regenerate session for security
        guard.RegenerateSession(w, r)

        // Redirect to dashboard
        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    }
}
```

### Logout Handler

```go
func LogoutHandler(guard *breitheamh.SessionGuard) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        guard.Logout(w, r)
        http.Redirect(w, r, "/", http.StatusSeeOther)
    }
}
```

## Remember Me Functionality

### How It Works

When "remember me" is enabled:
1. A remember token is generated and stored with the user
2. A long-lived cookie is set in the browser
3. On subsequent visits, the token is validated
4. If valid, a new session is created automatically

### Implementation

```go
// Login with remember me
err := guard.Login(w, r, credentials, true)

// On subsequent requests, the guard automatically:
// 1. Checks for session cookie (preferred)
// 2. Falls back to remember token cookie
// 3. Creates new session if remember token is valid
```

### Configuration

```go
guard := breitheamh.NewSessionGuard(store, breitheamh.SessionConfig{
    // ... other config
    RememberTokenName:   "remember_token",
    RememberTokenExpiry: 30 * 24 * time.Hour,  // 30 days
})
```

## Session Management

### Check if User is Authenticated

```go
func RequireAuth(guard *breitheamh.SessionGuard) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if !guard.IsAuthenticated(r) {
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

### Update Session Data

```go
// Store custom data in session
err := guard.UpdateSessionData(r, map[string]interface{}{
    "last_activity": time.Now(),
    "ip_address":    r.RemoteAddr,
})
```

### Get Session Data

```go
// Retrieve session data
data, err := guard.GetSessionData(r)
if err != nil {
    // No session
}

lastActivity := data["last_activity"].(time.Time)
```

## Security Best Practices

### 1. Always Use HTTPS

```go
SessionConfig{
    SecureCookie: true,  // Requires HTTPS
}
```

### 2. Regenerate Session After Login

```go
// Prevent session fixation
guard.Login(w, r, credentials, false)
guard.RegenerateSession(w, r)
```

### 3. Implement Session Timeout

```go
// Check last activity
data, _ := guard.GetSessionData(r)
lastActivity := data["last_activity"].(time.Time)

if time.Since(lastActivity) > 30*time.Minute {
    guard.Logout(w, r)
    http.Redirect(w, r, "/login?timeout=1", http.StatusSeeOther)
    return
}

// Update last activity
guard.UpdateSessionData(r, map[string]interface{}{
    "last_activity": time.Now(),
})
```

### 4. Set Appropriate Cookie Flags

```go
SessionConfig{
    HTTPOnlyCookie: true,                    // Prevent XSS
    SecureCookie:   true,                    // HTTPS only
    SameSite:       http.SameSiteStrictMode, // Prevent CSRF
}
```

### 5. Session Cleanup

Implement automatic cleanup of expired sessions:

```go
// Background task
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    for range ticker.C {
        store.Cleanup()
    }
}()
```

## Multi-Tab Synchronization

Sessions are shared across browser tabs by default. To handle logout across tabs:

```go
// Client-side: Listen for storage events
window.addEventListener('storage', function(e) {
    if (e.key === 'logout') {
        window.location.href = '/login';
    }
});

// Server-side: Set flag on logout
guard.Logout(w, r)
// Client can detect this on next request
```

## Flash Messages

Store temporary messages in session:

```go
// Set flash message
guard.SetFlash(w, r, "success", "Login successful!")

// Get and clear flash message
message := guard.GetFlash(r, "success")
// Returns empty string if not set
```

## Example: Complete Web Application

```go
package main

import (
    "net/http"
    "time"
    
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Initialize session store
    store := breitheamh.NewMemorySessionStore()
    
    // Create session guard
    guard := breitheamh.NewSessionGuard(store, breitheamh.SessionConfig{
        SessionName:        "myapp_session",
        SessionExpiry:      24 * time.Hour,
        SecureCookie:       true,
        HTTPOnlyCookie:     true,
        SameSite:           http.SameSiteStrictMode,
        RememberTokenExpiry: 30 * 24 * time.Hour,
    })

    // Public routes
    http.HandleFunc("/", HomeHandler)
    http.HandleFunc("/login", LoginHandler(guard))
    http.HandleFunc("/register", RegisterHandler)

    // Protected routes
    protected := http.NewServeMux()
    protected.HandleFunc("/dashboard", DashboardHandler)
    protected.HandleFunc("/profile", ProfileHandler)
    protected.HandleFunc("/logout", LogoutHandler(guard))

    http.Handle("/app/", http.StripPrefix("/app", 
        SessionAuthMiddleware(guard)(protected)))

    http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
```

## Troubleshooting

### Sessions Not Persisting

- Check `SecureCookie` setting matches HTTPS usage
- Verify cookie domain and path settings
- Check browser cookie settings

### Session Expires Too Quickly

- Increase `SessionExpiry` value
- Implement activity-based expiry refresh
- Check session store cleanup interval

### Remember Me Not Working

- Verify remember token is being generated
- Check cookie expiry settings
- Ensure token storage is working

## Related Documentation

- [Authentication Guide](AUTHENTICATION_GUIDE.md) - General authentication concepts
- [JWT Guard Configuration](JWT_GUARD_CONFIG.md) - Alternative JWT-based auth
- [Middleware Guide](MIDDLEWARE_GUIDE.md) - HTTP middleware integration
- [Security Best Practices](SECURITY_BEST_PRACTICES.md) - Security guidelines
