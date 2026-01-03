# Breitheamh Auth

**Breitheamh** (Old Irish: "judge, arbiter") is a production-ready authentication and authorization library for Go applications, inspired by Laravel's Spatie permissions package and built-in auth system.

[![CI](https://github.com/toutaio/toutago-breitheamh-auth/workflows/CI/badge.svg)](https://github.com/toutaio/toutago-breitheamh-auth/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/toutaio/toutago-breitheamh-auth.svg)](https://pkg.go.dev/github.com/toutaio/toutago-breitheamh-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/toutaio/toutago-breitheamh-auth)](https://goreportcard.com/report/github.com/toutaio/toutago-breitheamh-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Features

### Authentication
- 🔐 Multiple guard system (JWT, session-based, API token, custom)
- 🎫 Token generation and validation
- 🔄 Token refresh and revocation
- 🔒 Password hashing (bcrypt, argon2)
- 📧 Email verification workflow
- 🛡️ Multi-factor authentication (TOTP)
- 💾 Remember me functionality

### Authorization
- 👥 Role-based access control (RBAC)
- ✅ Permission management with wildcards (e.g., `posts.*`, `*.create`)
- 📋 Policy classes for resource-specific authorization
- 🚪 Gates for simple boolean checks
- 🔗 Permission groups and inheritance
- 🏢 Team/organization scoping support
- ⚡ Super admin bypass capability

### Security
- 🔐 CSRF protection tokens
- 🚦 Rate limiting per user/IP
- 📝 Audit trail for auth events
- 🔑 Secure token storage
- 🛡️ Account locking after failed attempts
- 📊 Password policy enforcement

## 📦 Installation

```bash
go get github.com/toutaio/toutago-breitheamh-auth
```

## 🚀 Quick Start

### Basic Authentication

```go
package main

import (
    "context"
    "log"
    
    "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
    // Create a hasher
    hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
    
    // Hash a password
    hashedPassword, err := hasher.Hash("secret123")
    if err != nil {
        log.Fatal(err)
    }
    
    // Create a user
    user := breitheamh.NewBaseUser("user-1", "user@example.com", hashedPassword)
    
    // Verify password
    err = hasher.Verify("secret123", user.GetPassword())
    if err != nil {
        log.Fatal("Invalid password")
    }
    
    log.Println("Authentication successful!")
}
```

### Permission Management

```go
// Create permissions
createPost := breitheamh.Permission{
    ID:   "perm-1",
    Name: "posts.create",
}

editPost := breitheamh.Permission{
    ID:   "perm-2",
    Name: "posts.edit",
}

// Create a role
editorRole := breitheamh.Role{
    ID:          "role-1",
    Name:        "editor",
    Permissions: []breitheamh.Permission{createPost, editPost},
}

// Assign role to user
user.AssignRole(editorRole)

// Check permissions
if user.HasPermission("posts.create") {
    log.Println("User can create posts")
}

// Wildcard permissions work too
adminPerm := breitheamh.Permission{
    ID:   "perm-3",
    Name: "posts.*",
}
user.GivePermission(adminPerm)

if user.HasPermission("posts.delete") {
    log.Println("User can delete posts (via wildcard)")
}
```

## 🏗️ Architecture

Breitheamh follows a clean, interface-first design:

```
pkg/breitheamh/
├── user.go              # User and UserProvider interfaces
├── guard.go             # Guard interface and manager
├── role.go              # Role struct and logic
├── permission.go        # Permission matching
├── hasher.go            # Password hashing utilities
├── base_user.go         # Default User implementation
└── guard_manager.go     # Guard management
```

## 🔧 Core Interfaces

### User
```go
type User interface {
    GetID() string
    GetPassword() string
    HasRole(role string) bool
    HasPermission(permission string) bool
    GetRoles() []Role
    GetPermissions() []Permission
}
```

### Guard
```go
type Guard interface {
    Authenticate(ctx context.Context, credentials interface{}) (User, error)
    Validate(ctx context.Context, token string) (User, error)
    Logout(ctx context.Context, user User) error
    Name() string
}
```

### UserProvider
```go
type UserProvider interface {
    FindByID(ctx context.Context, id string) (User, error)
    FindByCredentials(ctx context.Context, credentials map[string]interface{}) (User, error)
    UpdateUser(ctx context.Context, user User) error
}
```

## 📚 Examples

Check out the [examples](./examples) directory for complete working examples:

- **[basic-auth](./examples/basic-auth)** - Password hashing, JWT tokens, and permissions
- **[policy-authorization](./examples/policy-authorization)** - Gates and policy-based authorization
- **[session-auth](./examples/session-auth)** - Session management and multi-guard setup
- **[http-middleware](./examples/http-middleware)** - HTTP server with authentication middleware
- **[api-token](./examples/api-token)** - API token authentication for third-party integrations

## 🎯 Roadmap

- [x] Core interfaces and types
- [x] Password hashing (bcrypt, argon2)
- [x] Permission matching with wildcards
- [x] Base user implementation
- [x] Guard manager
- [x] JWT guard implementation
- [x] Session guard implementation
- [x] API token guard implementation
- [x] Token management and refresh
- [x] Policy-based authorization
- [x] Authorization gates
- [x] HTTP middleware
- [ ] 2FA support
- [ ] Rate limiting
- [ ] Audit logging
- [ ] User provider adapters (SQL, datamapper)
- [x] Comprehensive test suite (84.9% coverage)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌐 Part of Toutā Framework

Breitheamh is part of the [Toutā Framework](https://github.com/toutaio) ecosystem:

- **toutago** - Core framework
- **toutago-cosan-router** - HTTP router
- **toutago-datamapper** - Data persistence
- **toutago-scela-bus** - Message bus
- **toutago-breitheamh-auth** - Authentication & authorization (this library)

## 📚 Documentation

- [Quick Start Guide](docs/QUICK_START.md) _(coming soon)_
- [Authentication Guide](docs/AUTHENTICATION.md) _(coming soon)_
- [Authorization Guide](docs/AUTHORIZATION.md) _(coming soon)_
- [API Reference](https://pkg.go.dev/github.com/toutaio/toutago-breitheamh-auth)

## 💬 Etymology

**Breitheamh** (pronounced BREH-yuv) is Old Irish for "judge" or "arbiter", reflecting the library's role in judging authentication credentials and arbitrating access permissions.

---

Made with ❤️ by the Toutā team
