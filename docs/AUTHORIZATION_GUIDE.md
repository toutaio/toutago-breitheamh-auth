# Authorization Guide

This guide covers the authorization capabilities of **Breitheamh**, including roles, permissions, policies, and gates.

## Table of Contents

- [Overview](#overview)
- [Roles](#roles)
- [Permissions](#permissions)
- [Policies](#policies)
- [Gates](#gates)
- [Checking Authorization](#checking-authorization)
- [Best Practices](#best-practices)

## Overview

Breitheamh provides multiple authorization strategies:

- **Roles** - Group users into categories (admin, editor, viewer)
- **Permissions** - Fine-grained access control (posts.create, users.delete)
- **Policies** - Resource-specific authorization logic
- **Gates** - Simple boolean checks for specific actions

You can use these strategies individually or combine them for sophisticated access control.

## Roles

Roles group users into categories with shared permissions.

### Creating Roles

```go
import (
    "time"
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

adminRole := &breitheamh.Role{
    ID:        "role-1",
    Name:      "admin",
    GuardName: "web",
    Permissions: []breitheamh.Permission{
        {ID: "perm-1", Name: "users.create"},
        {ID: "perm-2", Name: "users.delete"},
        {ID: "perm-3", Name: "posts.*"}, // Wildcard
    },
    CreatedAt: time.Now(),
}
```

### Role Hierarchy

Roles can inherit permissions from parent roles:

```go
viewerID := "role-viewer"
editorID := "role-editor"

viewer := &breitheamh.Role{
    ID:   viewerID,
    Name: "viewer",
    Permissions: []breitheamh.Permission{
        {ID: "p1", Name: "posts.view"},
    },
}

editor := &breitheamh.Role{
    ID:       editorID,
    Name:     "editor",
    ParentID: &viewerID,  // Inherits from viewer
    Permissions: []breitheamh.Permission{
        {ID: "p2", Name: "posts.create"},
        {ID: "p3", Name: "posts.update"},
    },
}

// Editor has: posts.view (inherited), posts.create, posts.update
allPerms := editor.GetAllPermissions(roleProvider)
```

### Assigning Roles to Users

```go
user := &breitheamh.BaseUser{
    UserID:    "user-1",
    UserEmail: "admin@example.com",
    UserRoles: []breitheamh.Role{
        *adminRole,
    },
}
```

### Checking Roles

```go
// Check single role
if user.HasRole("admin") {
    fmt.Println("User is an admin")
}

// Check any of multiple roles
if user.HasAnyRole([]string{"admin", "moderator"}) {
    fmt.Println("User has elevated privileges")
}

// Check all roles
if user.HasAllRoles([]string{"editor", "reviewer"}) {
    fmt.Println("User can edit and review")
}
```

## Permissions

Permissions provide fine-grained access control.

### Permission Naming Convention

Use dot notation for hierarchical permissions:

```
users.view
users.create
users.update
users.delete

posts.view
posts.create
posts.update
posts.delete
posts.publish
```

### Wildcard Permissions

Use wildcards for broad permissions:

```go
perm := breitheamh.Permission{
    ID:   "perm-admin",
    Name: "posts.*",  // Matches posts.create, posts.update, etc.
}
```

### Permission Groups

Organize permissions into groups:

```go
userPerms := []breitheamh.Permission{
    {ID: "p1", Name: "users.view", GroupName: "users"},
    {ID: "p2", Name: "users.create", GroupName: "users"},
    {ID: "p3", Name: "users.update", GroupName: "users"},
    {ID: "p4", Name: "users.delete", GroupName: "users"},
}

postPerms := []breitheamh.Permission{
    {ID: "p5", Name: "posts.view", GroupName: "posts"},
    {ID: "p6", Name: "posts.create", GroupName: "posts"},
}
```

### Assigning Permissions

Permissions can be assigned to both roles and users directly:

```go
// Assign to role
role := &breitheamh.Role{
    Name: "editor",
    Permissions: []breitheamh.Permission{
        {Name: "posts.create"},
        {Name: "posts.update"},
    },
}

// Assign directly to user (bypassing roles)
user := &breitheamh.BaseUser{
    UserPermissions: []breitheamh.Permission{
        {Name: "posts.delete"}, // Special permission
    },
}
```

### Checking Permissions

```go
// Check single permission
if user.Can("posts.create") {
    // User can create posts
}

// Check permission with wildcard
if user.Can("posts.view") && user.HasPermission("posts.*") {
    // User has all post permissions
}

// Super admin bypass
user.IsSuperAdmin = true
if user.Can("anything") {
    // Always returns true for super admins
}
```

### Permission Caching

Enable caching for better performance:

```go
config := &breitheamh.PermissionCacheConfig{
    TTL:     5 * time.Minute,
    MaxSize: 10000,
}

cache := breitheamh.NewPermissionCache(config)
```

## Policies

Policies encapsulate authorization logic for specific resources.

### Defining a Policy

```go
type PostPolicy struct{}

func (p *PostPolicy) View(user breitheamh.User, post *Post) bool {
    // Anyone can view published posts
    if post.Published {
        return true
    }
    // Only author can view drafts
    return user.GetID() == post.AuthorID
}

func (p *PostPolicy) Update(user breitheamh.User, post *Post) bool {
    // Only author or admin can update
    return user.GetID() == post.AuthorID || user.HasRole("admin")
}

func (p *PostPolicy) Delete(user breitheamh.User, post *Post) bool {
    // Only admin can delete
    return user.HasRole("admin")
}

func (p *PostPolicy) Publish(user breitheamh.User, post *Post) bool {
    // Author or editor can publish
    return user.GetID() == post.AuthorID || user.HasAnyRole([]string{"editor", "admin"})
}

// Before hook - runs before all policy methods
func (p *PostPolicy) Before(user breitheamh.User, ability string) *bool {
    // Super admins bypass all checks
    if user.HasRole("super-admin") {
        allow := true
        return &allow
    }
    return nil // Continue to normal policy check
}
```

### Registering Policies

```go
registry := breitheamh.NewPolicyRegistry()
registry.Register("Post", &PostPolicy{})
registry.Register("User", &UserPolicy{})
```

### Using Policies

```go
post := &Post{
    ID:       "post-1",
    AuthorID: "user-1",
    Title:    "My Post",
    Published: false,
}

// Check authorization
canUpdate := registry.Authorize(user, "update", "Post", post)
if canUpdate {
    // Allow update
    post.Update(data)
} else {
    return errors.New("unauthorized")
}
```

### Policy with Context

```go
func (p *PostPolicy) UpdateWithContext(ctx context.Context, user breitheamh.User, post *Post) bool {
    // Check request context for additional authorization info
    if ipBanned := ctx.Value("ip_banned"); ipBanned != nil {
        return false
    }
    return user.GetID() == post.AuthorID
}
```

## Gates

Gates provide simple boolean authorization checks.

### Defining Gates

```go
registry := breitheamh.NewGateRegistry()

// Simple closure-based gate
registry.Define("update-post", func(user breitheamh.User, args ...interface{}) bool {
    post := args[0].(*Post)
    return user.GetID() == post.AuthorID || user.HasRole("admin")
})

// Gate with multiple arguments
registry.Define("assign-role", func(user breitheamh.User, args ...interface{}) bool {
    targetUser := args[0].(breitheamh.User)
    role := args[1].(string)
    
    // Only admins can assign roles
    if !user.HasRole("admin") {
        return false
    }
    
    // Super admins cannot be modified
    if targetUser.HasRole("super-admin") {
        return false
    }
    
    return true
})
```

### Using Gates

```go
// Check gate
if registry.Allows(user, "update-post", post) {
    // Authorized
    post.Update(data)
} else {
    return errors.New("unauthorized")
}

// Check with Denies
if registry.Denies(user, "assign-role", targetUser, "admin") {
    return errors.New("cannot assign admin role")
}
```

### Before/After Interceptors

```go
// Before interceptor - runs before all gates
registry.Before(func(user breitheamh.User, ability string, args ...interface{}) *bool {
    if user.HasRole("super-admin") {
        allow := true
        return &allow
    }
    return nil
})

// After interceptor - runs after gate check
registry.After(func(user breitheamh.User, ability string, result bool, args ...interface{}) bool {
    // Log authorization decision
    log.Printf("User %s attempted %s: %v", user.GetID(), ability, result)
    return result
})
```

## Checking Authorization

### In Application Code

```go
// Using permissions
if !user.Can("posts.delete") {
    return errors.New("insufficient permissions")
}

// Using roles
if !user.HasRole("admin") {
    return errors.New("admin access required")
}

// Using policies
if !policyRegistry.Authorize(user, "update", "Post", post) {
    return errors.New("not authorized to update this post")
}

// Using gates
if !gateRegistry.Allows(user, "publish-post", post) {
    return errors.New("not authorized to publish")
}
```

### In HTTP Middleware

```go
// Permission middleware
func RequirePermission(permission string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := getUserFromContext(r.Context())
            if user == nil || !user.Can(permission) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// Use it
http.Handle("/posts/create", RequirePermission("posts.create")(createPostHandler))
```

## Best Practices

### 1. Use Roles for Broad Categorization

```go
// Good: Define roles for user types
roles := []string{"viewer", "editor", "admin"}

// Avoid: Too many granular roles
// Bad: "can-edit-posts", "can-delete-comments", etc.
```

### 2. Use Permissions for Fine-Grained Control

```go
// Good: Specific permissions
permissions := []string{
    "posts.create",
    "posts.update",
    "posts.delete",
    "users.ban",
}
```

### 3. Use Policies for Resource-Specific Logic

```go
// Good: Complex business logic in policies
func (p *PostPolicy) Update(user User, post *Post) bool {
    // Check ownership
    if user.GetID() == post.AuthorID {
        return true
    }
    
    // Check if user is editor in same department
    if user.Department == post.Department && user.HasRole("editor") {
        return true
    }
    
    return false
}
```

### 4. Use Gates for Simple Checks

```go
// Good: Simple boolean checks
registry.Define("view-dashboard", func(user User, args ...interface{}) bool {
    return user.IsEmailVerified() && !user.IsBanned()
})
```

### 5. Combine Strategies

```go
// Combine roles, permissions, and policies
func canUpdatePost(user User, post *Post) bool {
    // Must have permission
    if !user.Can("posts.update") {
        return false
    }
    
    // Must pass policy check
    if !postPolicy.Update(user, post) {
        return false
    }
    
    return true
}
```

### 6. Cache Permission Checks

```go
// Cache expensive authorization checks
cache := make(map[string]bool)
cacheKey := fmt.Sprintf("%s:%s:%s", user.GetID(), "posts.update", post.ID)

if result, ok := cache[cacheKey]; ok {
    return result
}

result := postPolicy.Update(user, post)
cache[cacheKey] = result
return result
```

## Next Steps

- Read the [Authentication Guide](AUTHENTICATION_GUIDE.md) for login and guards
- See [Middleware Integration Guide](MIDDLEWARE_GUIDE.md) for HTTP middleware
- Check [examples/](../examples/) for complete working examples
