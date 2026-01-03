# Middleware Integration Guide

This guide shows how to integrate **Breitheamh** authentication and authorization into your HTTP applications using middleware.

## Table of Contents

- [Overview](#overview)
- [Authentication Middleware](#authentication-middleware)
- [Permission Middleware](#permission-middleware)
- [Role Middleware](#role-middleware)
- [Policy Middleware](#policy-middleware)
- [Gate Middleware](#gate-middleware)
- [Middleware Chaining](#middleware-chaining)
- [Custom Error Handling](#custom-error-handling)
- [Integration Examples](#integration-examples)

## Overview

Breitheamh provides ready-to-use HTTP middleware for:

- **Authentication** - Verify user identity
- **Permission-based** - Check specific permissions
- **Role-based** - Check user roles
- **Policy-based** - Apply resource-specific rules
- **Gate-based** - Custom authorization logic

## Authentication Middleware

The authentication middleware verifies that the request is from an authenticated user.

### Basic Usage

```go
import (
    "net/http"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Create guard
    guard := breitheamh.NewJWTGuard(jwtConfig, userProvider)
    
    // Create auth middleware
    authMiddleware := breitheamh.NewAuthMiddleware(guard)
    
    // Protect routes
    http.Handle("/dashboard", authMiddleware(dashboardHandler))
    http.Handle("/profile", authMiddleware(profileHandler))
    
    http.ListenAndServe(":8080", nil)
}
```

### Custom Unauthorized Handler

```go
authMiddleware := breitheamh.NewAuthMiddleware(guard,
    breitheamh.WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Authentication required",
            "code":  "AUTH_REQUIRED",
        })
    }),
)
```

### Extracting User in Handler

```go
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Get user from context (set by middleware)
    user := breitheamh.UserFromContext(r.Context())
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    fmt.Fprintf(w, "Welcome, %s!", user.GetEmail())
}
```

## Permission Middleware

Check if the authenticated user has specific permissions.

### Basic Usage

```go
// Require single permission
permMiddleware := breitheamh.NewPermissionMiddleware("posts.create")

http.Handle("/posts/create", 
    authMiddleware(permMiddleware(createPostHandler)))
```

### Multiple Permissions (AND)

```go
// User must have ALL permissions
permMiddleware := breitheamh.NewPermissionMiddleware(
    "posts.create",
    "posts.publish",
)
```

### Multiple Permissions (OR)

```go
// User must have ANY permission
permMiddleware := breitheamh.NewPermissionMiddleware(
    breitheamh.WithAnyPermission("posts.create", "posts.update"),
)
```

### Wildcard Permissions

```go
// Check for wildcard permission
permMiddleware := breitheamh.NewPermissionMiddleware("posts.*")
```

### Custom Forbidden Handler

```go
permMiddleware := breitheamh.NewPermissionMiddleware("posts.delete",
    breitheamh.WithForbiddenHandler(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Insufficient permissions",
            "required": "posts.delete",
        })
    }),
)
```

## Role Middleware

Check if the authenticated user has specific roles.

### Basic Usage

```go
// Require single role
roleMiddleware := breitheamh.NewRoleMiddleware("admin")

http.Handle("/admin", 
    authMiddleware(roleMiddleware(adminHandler)))
```

### Multiple Roles (AND)

```go
// User must have ALL roles
roleMiddleware := breitheamh.NewRoleMiddleware("editor", "reviewer")
```

### Multiple Roles (OR)

```go
// User must have ANY role
roleMiddleware := breitheamh.NewRoleMiddleware(
    breitheamh.WithAnyRole("admin", "moderator"),
)
```

### Role Hierarchy

```go
// Automatically checks parent roles
roleMiddleware := breitheamh.NewRoleMiddleware("editor",
    breitheamh.WithRoleInheritance(roleProvider),
)
```

## Policy Middleware

Apply policy-based authorization for specific resources.

### Basic Usage

```go
policyMiddleware := breitheamh.NewPolicyMiddleware(
    policyRegistry,
    "Post",        // Resource type
    "update",      // Action
    extractPostFromRequest, // Function to extract resource
)

http.Handle("/posts/{id}/edit", 
    authMiddleware(policyMiddleware(editPostHandler)))
```

### Resource Extractor Function

```go
func extractPostFromRequest(r *http.Request) (interface{}, error) {
    // Get post ID from URL
    postID := chi.URLParam(r, "id")
    
    // Load post from database
    post, err := postRepo.FindByID(postID)
    if err != nil {
        return nil, err
    }
    
    return post, nil
}
```

### Multiple Actions

```go
// Check different actions based on request method
policyMiddleware := breitheamh.NewPolicyMiddleware(
    policyRegistry,
    "Post",
    breitheamh.WithActionFromMethod(map[string]string{
        "GET":    "view",
        "POST":   "create",
        "PUT":    "update",
        "DELETE": "delete",
    }),
    extractPostFromRequest,
)
```

## Gate Middleware

Use custom gate logic for authorization.

### Basic Usage

```go
gateMiddleware := breitheamh.NewGateMiddleware(
    gateRegistry,
    "publish-post",
    extractPostFromRequest,
)

http.Handle("/posts/{id}/publish", 
    authMiddleware(gateMiddleware(publishHandler)))
```

### Multiple Arguments

```go
func extractPublishArgs(r *http.Request) ([]interface{}, error) {
    post, err := extractPost(r)
    if err != nil {
        return nil, err
    }
    
    publishDate := r.FormValue("publish_date")
    
    return []interface{}{post, publishDate}, nil
}

gateMiddleware := breitheamh.NewGateMiddleware(
    gateRegistry,
    "schedule-post",
    extractPublishArgs,
)
```

## Middleware Chaining

Combine multiple middleware for layered authorization.

### Standard Library

```go
// Chain middleware
protected := authMiddleware(
    roleMiddleware(
        permMiddleware(handler),
    ),
)

http.Handle("/admin/users", protected)
```

### With Chi Router

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()

// Global middleware
r.Use(authMiddleware)

// Route-specific middleware
r.Route("/admin", func(r chi.Router) {
    r.Use(roleMiddleware("admin"))
    
    r.Get("/users", listUsersHandler)
    r.Post("/users", createUserHandler)
})

r.Route("/posts", func(r chi.Router) {
    r.Get("/", listPostsHandler) // Public
    
    r.Group(func(r chi.Router) {
        r.Use(permMiddleware("posts.create"))
        r.Post("/", createPostHandler)
    })
    
    r.Group(func(r chi.Router) {
        r.Use(policyMiddleware("Post", "update"))
        r.Put("/{id}", updatePostHandler)
    })
})
```

### With Gorilla Mux

```go
import "github.com/gorilla/mux"

r := mux.NewRouter()

// Protected subrouter
admin := r.PathPrefix("/admin").Subrouter()
admin.Use(authMiddleware)
admin.Use(roleMiddleware("admin"))
admin.HandleFunc("/users", listUsersHandler).Methods("GET")
admin.HandleFunc("/users", createUserHandler).Methods("POST")
```

## Custom Error Handling

### JSON Error Responses

```go
type ErrorResponse struct {
    Error   string `json:"error"`
    Code    string `json:"code"`
    Details string `json:"details,omitempty"`
}

func jsonErrorHandler(statusCode int, code, message string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(statusCode)
        json.NewEncoder(w).Encode(ErrorResponse{
            Error: message,
            Code:  code,
        })
    }
}

authMiddleware := breitheamh.NewAuthMiddleware(guard,
    breitheamh.WithUnauthorizedHandler(
        jsonErrorHandler(401, "AUTH_REQUIRED", "Authentication required"),
    ),
)

permMiddleware := breitheamh.NewPermissionMiddleware("posts.create",
    breitheamh.WithForbiddenHandler(
        jsonErrorHandler(403, "INSUFFICIENT_PERMISSIONS", "Insufficient permissions"),
    ),
)
```

### Logging Errors

```go
func loggingErrorHandler(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Authorization failed: %s %s", r.Method, r.URL.Path)
        next(w, r)
    }
}

authMiddleware := breitheamh.NewAuthMiddleware(guard,
    breitheamh.WithUnauthorizedHandler(
        loggingErrorHandler(defaultUnauthorizedHandler),
    ),
)
```

### Redirect to Login

```go
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
    // Save intended URL
    returnURL := r.URL.String()
    
    // Redirect to login with return URL
    loginURL := fmt.Sprintf("/login?return=%s", url.QueryEscape(returnURL))
    http.Redirect(w, r, loginURL, http.StatusSeeOther)
}

authMiddleware := breitheamh.NewAuthMiddleware(sessionGuard,
    breitheamh.WithUnauthorizedHandler(redirectToLogin),
)
```

## Integration Examples

### Example 1: Blog API

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Setup guards
    jwtGuard := breitheamh.NewJWTGuard(jwtConfig, userProvider)
    
    // Setup middleware
    auth := breitheamh.NewAuthMiddleware(jwtGuard)
    requirePerm := breitheamh.NewPermissionMiddleware
    requireRole := breitheamh.NewRoleMiddleware
    
    r := chi.NewRouter()
    
    // Public routes
    r.Post("/auth/login", loginHandler)
    r.Post("/auth/register", registerHandler)
    
    // Authenticated routes
    r.Group(func(r chi.Router) {
        r.Use(auth)
        
        // Posts
        r.Get("/posts", listPostsHandler)
        r.Get("/posts/{id}", getPostHandler)
        
        // Protected post operations
        r.With(requirePerm("posts.create")).Post("/posts", createPostHandler)
        r.With(requirePerm("posts.update")).Put("/posts/{id}", updatePostHandler)
        r.With(requirePerm("posts.delete")).Delete("/posts/{id}", deletePostHandler)
        
        // Admin routes
        r.Route("/admin", func(r chi.Router) {
            r.Use(requireRole("admin"))
            r.Get("/users", adminListUsersHandler)
            r.Delete("/users/{id}", adminDeleteUserHandler)
        })
    })
    
    http.ListenAndServe(":8080", r)
}
```

### Example 2: Multi-Guard Web App

```go
package main

import (
    "net/http"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Setup guards
    webGuard := breitheamh.NewSessionGuard(sessionConfig, userProvider)
    apiGuard := breitheamh.NewJWTGuard(jwtConfig, userProvider)
    
    // Setup middleware
    webAuth := breitheamh.NewAuthMiddleware(webGuard)
    apiAuth := breitheamh.NewAuthMiddleware(apiGuard)
    
    // Web routes (session-based)
    http.Handle("/dashboard", webAuth(dashboardHandler))
    http.Handle("/profile", webAuth(profileHandler))
    
    // API routes (token-based)
    http.Handle("/api/users", apiAuth(apiUsersHandler))
    http.Handle("/api/posts", apiAuth(apiPostsHandler))
    
    http.ListenAndServe(":8080", nil)
}
```

### Example 3: Resource-Based Authorization

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Setup
    guard := breitheamh.NewJWTGuard(jwtConfig, userProvider)
    policyRegistry := breitheamh.NewPolicyRegistry()
    policyRegistry.Register("Post", &PostPolicy{})
    
    auth := breitheamh.NewAuthMiddleware(guard)
    
    r := chi.NewRouter()
    r.Use(auth)
    
    // Resource-based routes
    r.Route("/posts/{id}", func(r chi.Router) {
        // Different policies for different actions
        r.With(policyMiddleware(policyRegistry, "Post", "view")).Get("/", viewPostHandler)
        r.With(policyMiddleware(policyRegistry, "Post", "update")).Put("/", updatePostHandler)
        r.With(policyMiddleware(policyRegistry, "Post", "delete")).Delete("/", deletePostHandler)
    })
    
    http.ListenAndServe(":8080", r)
}

func policyMiddleware(registry *breitheamh.PolicyRegistry, resource, action string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := breitheamh.UserFromContext(r.Context())
            post := extractPost(r) // Your function to load the post
            
            if !registry.Authorize(user, action, resource, post) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

## Best Practices

### 1. Always Chain Authentication First

```go
// Good
protected := authMiddleware(permMiddleware(handler))

// Bad - permission check without authentication
protected := permMiddleware(handler)
```

### 2. Use Specific Middleware for Specific Routes

```go
// Good - targeted protection
r.Post("/posts", authMiddleware(permMiddleware("posts.create")(handler)))

// Avoid - global permission on everything
r.Use(permMiddleware("posts.create"))
```

### 3. Provide Clear Error Messages

```go
permMiddleware := breitheamh.NewPermissionMiddleware("posts.create",
    breitheamh.WithForbiddenHandler(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "You need the 'posts.create' permission",
            "action": "Contact your administrator",
        })
    }),
)
```

### 4. Use Policy Middleware for Complex Rules

```go
// Good - complex logic in policy
policyMiddleware := breitheamh.NewPolicyMiddleware(registry, "Post", "update")

// Avoid - complex logic in middleware
```

## Next Steps

- Read the [Authentication Guide](AUTHENTICATION_GUIDE.md) for guard setup
- See the [Authorization Guide](AUTHORIZATION_GUIDE.md) for roles and permissions
- Check [examples/](../examples/) for complete working examples
