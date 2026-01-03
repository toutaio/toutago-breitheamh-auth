# API Reference

Complete API reference for Breitheamh Auth package.

## Table of Contents

- [Interfaces](#interfaces)
- [Core Types](#core-types)
- [Guards](#guards)
- [Authorization](#authorization)
- [Middleware](#middleware)
- [Utilities](#utilities)

## Interfaces

### User

The `User` interface represents an authenticatable user.

```go
type User interface {
    GetAuthIdentifier() interface{}
    GetAuthPassword() string
}
```

**Methods:**

- `GetAuthIdentifier()` - Returns the unique identifier for the user (typically ID)
- `GetAuthPassword()` - Returns the hashed password for authentication

### Authenticatable

Extended user interface with authorization capabilities.

```go
type Authenticatable interface {
    User
    GetRoles() []*Role
    GetPermissions() []*Permission
    HasRole(role string) bool
    HasPermission(permission string) bool
    Can(action string, resource ...interface{}) bool
}
```

**Methods:**

- `GetRoles()` - Returns all roles assigned to the user
- `GetPermissions()` - Returns all permissions (direct + role-based)
- `HasRole(role string)` - Checks if user has a specific role
- `HasPermission(permission string)` - Checks if user has a permission
- `Can(action, resource)` - Policy-based authorization check

### Guard

The `Guard` interface defines authentication guard behavior.

```go
type Guard interface {
    User(ctx context.Context, token string) (User, error)
    Login(ctx context.Context, credentials map[string]interface{}) (*TokenPair, error)
    Logout(ctx context.Context, token string) error
}
```

**Methods:**

- `User(ctx, token)` - Retrieves the authenticated user from token
- `Login(ctx, credentials)` - Authenticates user and returns tokens
- `Logout(ctx, token)` - Revokes authentication token

### UserProvider

The `UserProvider` interface abstracts user storage.

```go
type UserProvider interface {
    RetrieveByID(ctx context.Context, id interface{}) (User, error)
    RetrieveByCredentials(ctx context.Context, credentials map[string]interface{}) (User, error)
    RetrieveByToken(ctx context.Context, identifier interface{}, token string) (User, error)
    UpdateRememberToken(ctx context.Context, user User, token string) error
}
```

**Methods:**

- `RetrieveByID(ctx, id)` - Finds user by unique identifier
- `RetrieveByCredentials(ctx, credentials)` - Finds user by login credentials
- `RetrieveByToken(ctx, identifier, token)` - Finds user by remember token
- `UpdateRememberToken(ctx, user, token)` - Updates the remember token

### Policy

The `Policy` interface defines resource authorization.

```go
type Policy interface {
    Before(ctx context.Context, user User, action string) *bool
    After(ctx context.Context, user User, action string, result bool) bool
}
```

**Methods:**

- `Before(ctx, user, action)` - Pre-authorization hook
- `After(ctx, user, action, result)` - Post-authorization hook

## Core Types

### BaseUser

Default user implementation.

```go
type BaseUser struct {
    ID            interface{}
    Email         string
    Password      string
    Name          string
    RememberToken string
    roles         []*Role
    permissions   []*Permission
}
```

**Methods:**

```go
func (u *BaseUser) GetAuthIdentifier() interface{}
func (u *BaseUser) GetAuthPassword() string
func (u *BaseUser) SetRoles(roles []*Role)
func (u *BaseUser) SetPermissions(permissions []*Permission)
func (u *BaseUser) GetRoles() []*Role
func (u *BaseUser) GetPermissions() []*Permission
func (u *BaseUser) HasRole(role string) bool
func (u *BaseUser) HasAnyRole(roles ...string) bool
func (u *BaseUser) HasAllRoles(roles ...string) bool
func (u *BaseUser) HasPermission(permission string) bool
func (u *BaseUser) Can(action string, resource ...interface{}) bool
```

### Role

Represents a user role with permissions.

```go
type Role struct {
    ID          interface{}
    Name        string
    DisplayName string
    Description string
    Permissions []*Permission
    ParentID    interface{}
    Children    []*Role
}
```

**Methods:**

```go
func (r *Role) HasPermission(permission string) bool
func (r *Role) AddPermission(permission *Permission)
func (r *Role) RemovePermission(permissionName string)
func (r *Role) GetAllPermissions() []*Permission
```

### Permission

Represents a permission.

```go
type Permission struct {
    ID          interface{}
    Name        string
    DisplayName string
    Description string
}
```

**Methods:**

```go
func (p *Permission) Matches(pattern string) bool
```

### TokenPair

JWT token pair for authentication.

```go
type TokenPair struct {
    AccessToken  string
    RefreshToken string
    ExpiresIn    int64
}
```

## Guards

### JWTGuard

JWT-based authentication guard.

```go
type JWTGuard struct {
    config   JWTConfig
    provider UserProvider
}
```

**Constructor:**

```go
func NewJWTGuard(config JWTConfig) *JWTGuard
```

**Configuration:**

```go
type JWTConfig struct {
    SecretKey          string
    AccessTokenExpiry  time.Duration
    RefreshTokenExpiry time.Duration
    Issuer             string
}
```

**Methods:**

```go
func (g *JWTGuard) SetProvider(provider UserProvider)
func (g *JWTGuard) Login(ctx context.Context, credentials map[string]interface{}) (*TokenPair, error)
func (g *JWTGuard) User(ctx context.Context, token string) (User, error)
func (g *JWTGuard) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
func (g *JWTGuard) Logout(ctx context.Context, token string) error
func (g *JWTGuard) Revoke(ctx context.Context, token string) error
func (g *JWTGuard) BlacklistToken(token string)
func (g *JWTGuard) IsBlacklisted(token string) bool
```

### SessionGuard

Session-based authentication guard.

```go
type SessionGuard struct {
    store  SessionStore
    config SessionConfig
}
```

**Constructor:**

```go
func NewSessionGuard(store SessionStore, config SessionConfig) *SessionGuard
```

**Configuration:**

```go
type SessionConfig struct {
    SessionName        string
    SessionExpiry      time.Duration
    CookiePath         string
    CookieDomain       string
    SecureCookie       bool
    HTTPOnlyCookie     bool
    SameSite           http.SameSite
    RememberTokenName  string
    RememberTokenExpiry time.Duration
}
```

**Methods:**

```go
func (g *SessionGuard) Login(w http.ResponseWriter, r *http.Request, credentials map[string]interface{}, remember bool) error
func (g *SessionGuard) User(r *http.Request) (User, error)
func (g *SessionGuard) Logout(w http.ResponseWriter, r *http.Request) error
func (g *SessionGuard) IsAuthenticated(r *http.Request) bool
func (g *SessionGuard) RegenerateSession(w http.ResponseWriter, r *http.Request) error
func (g *SessionGuard) UpdateSessionData(r *http.Request, data map[string]interface{}) error
func (g *SessionGuard) GetSessionData(r *http.Request) (map[string]interface{}, error)
func (g *SessionGuard) SetFlash(w http.ResponseWriter, r *http.Request, key, message string)
func (g *SessionGuard) GetFlash(r *http.Request, key string) string
```

### APITokenGuard

API token-based authentication.

```go
type APITokenGuard struct {
    provider UserProvider
    hasher   TokenHasher
}
```

**Constructor:**

```go
func NewAPITokenGuard(provider UserProvider) *APITokenGuard
```

**Methods:**

```go
func (g *APITokenGuard) GenerateToken(ctx context.Context, user User, name string, abilities []string) (*APIToken, error)
func (g *APITokenGuard) ValidateToken(ctx context.Context, token string) (User, *APIToken, error)
func (g *APITokenGuard) RevokeToken(ctx context.Context, tokenID interface{}) error
func (g *APITokenGuard) RevokeAllTokens(ctx context.Context, user User) error
```

## Authorization

### Authorizer

Main authorization manager.

```go
type Authorizer struct {
    policies map[string]Policy
    gates    map[string]GateFunc
}
```

**Constructor:**

```go
func NewAuthorizer() *Authorizer
```

**Methods:**

```go
func (a *Authorizer) RegisterPolicy(resourceType string, policy Policy)
func (a *Authorizer) DefineGate(name string, gate GateFunc)
func (a *Authorizer) Authorize(ctx context.Context, user User, action string, resource ...interface{}) bool
func (a *Authorizer) CheckGate(ctx context.Context, user User, gateName string, args ...interface{}) bool
func (a *Authorizer) Can(ctx context.Context, user User, permission string) bool
func (a *Authorizer) HasRole(ctx context.Context, user User, role string) bool
```

### PermissionTrie

Efficient wildcard permission matching.

```go
type PermissionTrie struct {
    root *TrieNode
}
```

**Constructor:**

```go
func NewPermissionTrie() *PermissionTrie
```

**Methods:**

```go
func (t *PermissionTrie) Insert(permission string)
func (t *PermissionTrie) Match(permission string) bool
func (t *PermissionTrie) Remove(permission string)
```

**Supports Wildcards:**

```go
trie.Insert("posts.*")           // Matches posts.create, posts.update, etc.
trie.Insert("users.*.view")      // Matches users.123.view, users.456.view
trie.Match("posts.create")       // true
trie.Match("posts.delete")       // true
```

### PolicyRegistry

Manages policies and resolution.

```go
type PolicyRegistry struct {
    policies map[string]Policy
}
```

**Constructor:**

```go
func NewPolicyRegistry() *PolicyRegistry
```

**Methods:**

```go
func (r *PolicyRegistry) Register(resourceType string, policy Policy)
func (r *PolicyRegistry) Resolve(resource interface{}) Policy
func (r *PolicyRegistry) Authorize(ctx context.Context, user User, action string, resource ...interface{}) bool
```

### GateRegistry

Manages authorization gates.

```go
type GateRegistry struct {
    gates   map[string]GateFunc
    before  []GateInterceptor
    after   []GateInterceptor
}
```

**Types:**

```go
type GateFunc func(ctx context.Context, user User, args ...interface{}) bool
type GateInterceptor func(ctx context.Context, user User, gateName string, args ...interface{}) *bool
```

**Constructor:**

```go
func NewGateRegistry() *GateRegistry
```

**Methods:**

```go
func (r *GateRegistry) Define(name string, gate GateFunc)
func (r *GateRegistry) Check(ctx context.Context, user User, gateName string, args ...interface{}) bool
func (r *GateRegistry) Allow(ctx context.Context, user User, gateName string, args ...interface{}) bool
func (r *GateRegistry) Deny(ctx context.Context, user User, gateName string, args ...interface{}) bool
func (r *GateRegistry) Before(interceptor GateInterceptor)
func (r *GateRegistry) After(interceptor GateInterceptor)
```

## Middleware

### AuthMiddleware

Requires authentication.

```go
func AuthMiddleware(guard Guard) func(http.Handler) http.Handler
```

**Usage:**

```go
http.Handle("/api/", AuthMiddleware(guard)(handler))
```

### RequirePermission

Requires specific permission.

```go
func RequirePermission(permission string) func(http.Handler) http.Handler
```

**Usage:**

```go
http.Handle("/admin/", RequirePermission("admin.access")(handler))
```

### RequireRole

Requires specific role.

```go
func RequireRole(role string) func(http.Handler) http.Handler
```

**Usage:**

```go
http.Handle("/admin/", RequireRole("administrator")(handler))
```

### RequireAnyRole

Requires any of the specified roles.

```go
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler
```

**Usage:**

```go
http.Handle("/mod/", RequireAnyRole("moderator", "admin")(handler))
```

### RequireAllRoles

Requires all specified roles.

```go
func RequireAllRoles(roles ...string) func(http.Handler) http.Handler
```

**Usage:**

```go
http.Handle("/special/", RequireAllRoles("editor", "verified")(handler))
```

### AuthorizePolicy

Policy-based authorization middleware.

```go
func AuthorizePolicy(action string, resourceGetter func(*http.Request) interface{}) func(http.Handler) http.Handler
```

**Usage:**

```go
http.HandleFunc("/posts/{id}", AuthorizePolicy("update", func(r *http.Request) interface{} {
    id := mux.Vars(r)["id"]
    return getPost(id)
})(updatePostHandler))
```

## Utilities

### Password Hashing

```go
// Bcrypt
func HashPasswordBcrypt(password string) (string, error)
func VerifyPasswordBcrypt(password, hash string) bool

// Argon2
func HashPasswordArgon2(password string) (string, error)
func VerifyPasswordArgon2(password, hash string) bool
```

### Context Helpers

```go
// Store user in context
func WithUser(ctx context.Context, user User) context.Context

// Retrieve user from context
func UserFromContext(ctx context.Context) (User, bool)

// Check if user is authenticated
func IsAuthenticated(ctx context.Context) bool
```

### Token Generation

```go
// Generate random token
func GenerateToken(length int) (string, error)

// Generate remember token
func GenerateRememberToken() (string, error)

// Hash token
func HashToken(token string) string
```

## Error Types

```go
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrInvalidToken      = errors.New("invalid token")
    ErrTokenExpired      = errors.New("token has expired")
    ErrUnauthorized      = errors.New("unauthorized")
    ErrForbidden         = errors.New("forbidden")
)
```

## Constants

```go
const (
    // Token types
    TokenTypeAccess  = "access"
    TokenTypeRefresh = "refresh"
    
    // Context keys
    ContextKeyUser = "breitheamh:user"
    
    // Default expiry times
    DefaultAccessTokenExpiry  = 15 * time.Minute
    DefaultRefreshTokenExpiry = 7 * 24 * time.Hour
    DefaultSessionExpiry      = 24 * time.Hour
)
```

## Examples

### Custom User Provider

```go
type DatabaseProvider struct {
    db *sql.DB
}

func (p *DatabaseProvider) RetrieveByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
    email := credentials["email"].(string)
    
    var user breitheamh.BaseUser
    err := p.db.QueryRowContext(ctx, 
        "SELECT id, email, password, name FROM users WHERE email = ?",
        email,
    ).Scan(&user.ID, &user.Email, &user.Password, &user.Name)
    
    if err != nil {
        return nil, breitheamh.ErrUserNotFound
    }
    
    return &user, nil
}
```

### Custom Policy

```go
type PostPolicy struct{}

func (p *PostPolicy) Before(ctx context.Context, user breitheamh.User, action string) *bool {
    // Super admin can do anything
    if user.(breitheamh.Authenticatable).HasRole("super-admin") {
        result := true
        return &result
    }
    return nil
}

func (p *PostPolicy) Update(ctx context.Context, user breitheamh.User, post *Post) bool {
    return post.AuthorID == user.GetAuthIdentifier()
}

func (p *PostPolicy) Delete(ctx context.Context, user breitheamh.User, post *Post) bool {
    auth := user.(breitheamh.Authenticatable)
    return post.AuthorID == user.GetAuthIdentifier() || auth.HasRole("moderator")
}
```

### Custom Gate

```go
authorizer.DefineGate("admin-access", func(ctx context.Context, user breitheamh.User, args ...interface{}) bool {
    auth := user.(breitheamh.Authenticatable)
    return auth.HasRole("admin") && auth.HasPermission("admin.access")
})

// Use gate
if authorizer.CheckGate(ctx, user, "admin-access") {
    // Allow access
}
```

## Related Documentation

- [Quick Start Guide](QUICK_START.md)
- [Authentication Guide](AUTHENTICATION_GUIDE.md)
- [Authorization Guide](AUTHORIZATION_GUIDE.md)
- [JWT Guard Configuration](JWT_GUARD_CONFIG.md)
- [Session Guard Usage](SESSION_GUARD_USAGE.md)
- [Middleware Guide](MIDDLEWARE_GUIDE.md)
