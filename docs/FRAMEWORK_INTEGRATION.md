# Framework Integration Guide

This guide explains how to integrate Breitheamh Auth with other Toutago components and frameworks.

## Table of Contents

1. [Main Toutago Framework](#main-toutago-framework)
2. [Cosan Router Integration](#cosan-router-integration)
3. [Datamapper Integration](#datamapper-integration)
4. [Scéla Event Bus Integration](#scéla-event-bus-integration)

## Main Toutago Framework

The Toutago adapter provides seamless integration with the main framework.

### Installation

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/adapters/toutago"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)
```

### Setup

```go
// Create manager
config := breitheamh.DefaultConfig()
manager := breitheamh.NewManager(config)

// Create adapter
adapter := toutago.NewAdapter(manager)

// Use in your application
ctx := context.Background()

// Login
user, err := adapter.LoginContext(ctx, "web", map[string]interface{}{
    "email":    "user@example.com",
    "password": "secret",
})

// Check authentication
if adapter.CheckContext(ctx, "web") {
    // User is authenticated
}

// Get current user
user, err := adapter.UserContext(ctx, "web")

// Logout
err = adapter.LogoutContext(ctx, "web")
```

## Cosan Router Integration

Breitheamh provides middleware for the Cosan router.

### Installation

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/adapters/cosan"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)
```

### Authentication Middleware

```go
// Setup manager
config := breitheamh.DefaultConfig()
manager := breitheamh.NewManager(config)

// Create router (pseudo-code, adapt to actual Cosan API)
router := cosan.NewRouter()

// Apply authentication middleware
router.Use(cosan.AuthMiddleware(manager, "web"))

// Protected routes
router.GET("/dashboard", func(w http.ResponseWriter, r *http.Request) {
    // Only authenticated users can access
    guard, _ := manager.Guard("web")
    user, _ := guard.User(r.Context())
    fmt.Fprintf(w, "Welcome %s", user.GetAuthIdentifierName())
})
```

### Guest Middleware

```go
// Ensure user is NOT authenticated
router.Use(cosan.GuestMiddleware(manager, "web"))

router.GET("/login", loginHandler)
router.GET("/register", registerHandler)
```

### Permission-Based Middleware

```go
// Require specific permission
router.Use(cosan.PermissionMiddleware(manager, "web", "posts.create"))

router.POST("/posts", createPostHandler)
```

### Role-Based Middleware

```go
// Require specific role
router.Use(cosan.RoleMiddleware(manager, "web", "admin"))

router.GET("/admin", adminDashboardHandler)
```

### Route Groups

```go
// Protected routes group
protected := router.Group("/api")
protected.Use(cosan.AuthMiddleware(manager, "api"))

protected.GET("/profile", profileHandler)
protected.POST("/posts", createPostHandler)

// Admin routes group
admin := router.Group("/admin")
admin.Use(cosan.AuthMiddleware(manager, "web"))
admin.Use(cosan.RoleMiddleware(manager, "web", "admin"))

admin.GET("/users", listUsersHandler)
admin.DELETE("/users/:id", deleteUserHandler)
```

## Datamapper Integration

The datamapper adapter provides database persistence for authentication.

### Installation

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/adapters/datamapper"
    "github.com/toutaio/toutago-datamapper"
)
```

### Setup

```go
// Initialize datamapper
dm := datamapper.New(db)

// Create provider
provider := datamapper.NewProvider(dm, "users")

// Configure manager
config := breitheamh.DefaultConfig()
config.Providers["users"] = provider

manager := breitheamh.NewManager(config)
```

### User Model

```go
type User struct {
    ID           int64     `db:"id"`
    Email        string    `db:"email"`
    Password     string    `db:"password"`
    RememberToken string   `db:"remember_token"`
    CreatedAt    time.Time `db:"created_at"`
    UpdatedAt    time.Time `db:"updated_at"`
}

// Implement Authenticatable interface
func (u *User) GetAuthIdentifier() string {
    return fmt.Sprintf("%d", u.ID)
}

func (u *User) GetAuthIdentifierName() string {
    return "id"
}

func (u *User) GetAuthPassword() string {
    return u.Password
}

func (u *User) GetRememberToken() string {
    return u.RememberToken
}

func (u *User) SetRememberToken(token string) {
    u.RememberToken = token
}
```

## Scéla Event Bus Integration

Publish authentication events to the Scéla message bus.

### Installation

```go
import (
    "github.com/toutaio/toutago-breitheamh-auth/adapters/scela"
    scelabus "github.com/toutaio/toutago-scela-bus"
)
```

### Setup

```go
// Create Scéla bus
bus := scelabus.New()

// Create event publisher
publisher := scela.NewEventPublisher(bus)

// Publish events
ctx := context.Background()

// Login event
publisher.PublishLoginEvent(ctx, "user123", "web", map[string]interface{}{
    "ip":         "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
})

// Logout event
publisher.PublishLogoutEvent(ctx, "user123", "web", nil)

// Failed login event
publisher.PublishFailedLoginEvent(ctx, "user@example.com", "web", map[string]interface{}{
    "reason": "invalid_password",
    "ip":     "192.168.1.1",
})

// Password reset event
publisher.PublishPasswordResetEvent(ctx, "user123", nil)

// Email verified event
publisher.PublishEmailVerifiedEvent(ctx, "user123", nil)

// Permission granted event
publisher.PublishPermissionGrantedEvent(ctx, "user123", "posts.create", nil)

// Role assigned event
publisher.PublishRoleAssignedEvent(ctx, "user123", "admin", nil)
```

### Subscribe to Events

```go
// Subscribe to login events
bus.Subscribe("auth.login", func(ctx context.Context, event scela.AuthEvent) error {
    log.Printf("User %s logged in via %s guard", event.UserID, event.Guard)
    return nil
})

// Subscribe to failed login events
bus.Subscribe("auth.login.failed", func(ctx context.Context, event scela.AuthEvent) error {
    log.Printf("Failed login attempt for %s", event.UserID)
    // Implement rate limiting, alerting, etc.
    return nil
})

// Subscribe to permission granted events
bus.Subscribe("auth.permission.granted", func(ctx context.Context, event scela.AuthEvent) error {
    permission := event.Metadata["permission"].(string)
    log.Printf("User %s granted permission: %s", event.UserID, permission)
    return nil
})
```

### Integration with Guards

You can integrate the event publisher with guards to automatically publish events:

```go
type EventAwareGuard struct {
    breitheamh.Guard
    publisher *scela.EventPublisher
}

func (g *EventAwareGuard) Attempt(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
    user, err := g.Guard.Attempt(ctx, credentials)
    if err != nil {
        // Publish failed login event
        identifier := credentials["email"].(string)
        g.publisher.PublishFailedLoginEvent(ctx, identifier, "web", map[string]interface{}{
            "error": err.Error(),
        })
        return nil, err
    }

    // Publish successful login event
    g.publisher.PublishLoginEvent(ctx, user.GetAuthIdentifier(), "web", nil)
    return user, nil
}

func (g *EventAwareGuard) Logout(ctx context.Context) error {
    user, _ := g.User(ctx)
    err := g.Guard.Logout(ctx)
    if err == nil && user != nil {
        g.publisher.PublishLogoutEvent(ctx, user.GetAuthIdentifier(), "web", nil)
    }
    return err
}
```

## Complete Example

Here's a complete example integrating all components:

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/toutaio/toutago-breitheamh-auth/adapters/cosan"
    "github.com/toutaio/toutago-breitheamh-auth/adapters/datamapper"
    "github.com/toutaio/toutago-breitheamh-auth/adapters/scela"
    "github.com/toutaio/toutago-breitheamh-auth/adapters/toutago"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Setup database (pseudo-code)
    db := setupDatabase()
    dm := setupDatamapper(db)

    // Setup Scéla bus
    bus := setupScelaBus()
    publisher := scela.NewEventPublisher(bus)

    // Setup auth
    provider := datamapper.NewProvider(dm, "users")
    config := breitheamh.DefaultConfig()
    config.Providers["users"] = provider
    manager := breitheamh.NewManager(config)
    adapter := toutago.NewAdapter(manager)

    // Setup router
    router := setupRouter()

    // Public routes
    router.POST("/login", func(w http.ResponseWriter, r *http.Request) {
        email := r.FormValue("email")
        password := r.FormValue("password")

        user, err := adapter.LoginContext(r.Context(), "web", map[string]interface{}{
            "email":    email,
            "password": password,
        })

        if err != nil {
            publisher.PublishFailedLoginEvent(r.Context(), email, "web", nil)
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }

        publisher.PublishLoginEvent(r.Context(), user.GetAuthIdentifier(), "web", nil)
        w.Write([]byte("Login successful"))
    })

    // Protected routes
    protected := router.Group("/api")
    protected.Use(cosan.AuthMiddleware(manager, "web"))

    protected.GET("/profile", func(w http.ResponseWriter, r *http.Request) {
        user, _ := adapter.UserContext(r.Context(), "web")
        w.Write([]byte("Welcome " + user.GetAuthIdentifierName()))
    })

    // Admin routes
    admin := router.Group("/admin")
    admin.Use(cosan.AuthMiddleware(manager, "web"))
    admin.Use(cosan.RoleMiddleware(manager, "web", "admin"))

    admin.GET("/dashboard", adminDashboardHandler)

    log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Best Practices

1. **Use context properly**: Always pass context through your application for proper request scoping
2. **Event-driven architecture**: Use Scéla events for audit logging, analytics, and side effects
3. **Middleware composition**: Chain middleware for complex authorization requirements
4. **Caching**: Use the built-in caching mechanisms for permissions and roles
5. **Error handling**: Handle authentication errors gracefully and provide useful feedback
6. **Security**: Use HTTPS in production, enable CSRF protection, implement rate limiting

## Additional Resources

- [Breitheamh Documentation](../README.md)
- [Cosan Router Documentation](https://github.com/toutaio/toutago-cosan-router)
- [Datamapper Documentation](https://github.com/toutaio/toutago-datamapper)
- [Scéla Bus Documentation](https://github.com/toutaio/toutago-scela-bus)
