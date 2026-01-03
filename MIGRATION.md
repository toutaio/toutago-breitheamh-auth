# Migration Guide to v1.0.0

This guide helps you migrate to Breitheamh Auth v1.0.0.

## Overview

Breitheamh Auth v1.0.0 is the first stable release of the authentication and authorization library for the Toutago framework ecosystem.

## New Installation

For new projects, install with:

```bash
go get github.com/toutaio/toutago-breitheamh-auth@v1.0.0
```

## Migrating from Pre-1.0 Versions

If you were using development versions, please note the following key changes:

### Package Structure

The main package is now stable at:

```go
import "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
```

### Core Concepts

#### 1. Authentication Guards

Guards are the primary mechanism for authentication:

```go
// JWT Guard setup
jwtGuard := breitheamh.NewJWTGuard(
    "jwt",                    // guard name
    userProvider,             // UserProvider implementation
    tokenManager,             // TokenManager for JWT operations
    hasher,                   // Password hasher
)

// Register with auth manager
authManager := breitheamh.NewAuthManager()
authManager.RegisterGuard("jwt", jwtGuard)
```

#### 2. User Providers

Implement the `UserProvider` interface for your storage backend:

```go
type UserProvider interface {
    FindByID(ctx context.Context, id string) (Authenticatable, error)
    FindByCredentials(ctx context.Context, credentials map[string]interface{}) (Authenticatable, error)
}
```

Built-in providers:
- SQL provider (generic database support)
- Datamapper provider (toutago-datamapper integration)

#### 3. Authorization

Three authorization mechanisms are available:

**Roles:**
```go
user := &breitheamh.BaseUser{}
user.AssignRole("admin")
if user.HasRole("admin") {
    // authorized
}
```

**Permissions:**
```go
user.GrantPermission("posts.create")
if user.HasPermission("posts.create") {
    // authorized
}

// Wildcard support
user.GrantPermission("posts.*")
if user.HasPermission("posts.update") {
    // authorized - matches wildcard
}
```

**Policies:**
```go
type PostPolicy struct{}

func (p *PostPolicy) Update(user breitheamh.Authenticatable, post *Post) bool {
    return post.UserID == user.GetAuthIdentifier()
}

policyManager.RegisterPolicy("Post", &PostPolicy{})

if policyManager.Authorize(user, "update", post) {
    // authorized
}
```

### HTTP Middleware

Integration with Cosan router:

```go
import "github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/cosan"

router := cosan.NewRouter()

// Authentication middleware
router.Use(cosan.Authenticate(authManager, "jwt"))

// Authorization middleware
router.Use(cosan.AuthorizeRole(authManager, policyManager, "admin"))
router.Use(cosan.AuthorizePermission(authManager, policyManager, "posts.create"))
```

### Security Features

#### Password Hashing

```go
hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)

// Hash password
hashed, err := hasher.Hash("password")

// Verify password
err := hasher.Verify("password", hashed)
```

#### Two-Factor Authentication

```go
// Generate TOTP secret
secret, err := breitheamh.GenerateTOTPSecret()

// Generate QR code URL for user to scan
qrURL := breitheamh.GenerateTOTPQRCode(secret, "user@example.com", "YourApp")

// Verify TOTP code
valid := breitheamh.VerifyTOTP(secret, "123456")

// Generate backup codes
backupCodes, err := breitheamh.GenerateBackupCodes(10)
```

#### Rate Limiting

```go
limiter := breitheamh.NewRateLimiter(100, time.Minute)

if !limiter.Allow(userID) {
    // rate limit exceeded
}
```

#### Brute Force Protection

```go
bruteForce := breitheamh.NewBruteForceProtector(5, 15*time.Minute)

bruteForce.RecordAttempt(userID)

if bruteForce.IsLocked(userID) {
    // account is locked
}
```

## Breaking Changes from Development Versions

### API Changes

1. **Guard Constructor**: Changed to accept explicit dependencies
   - Before: `NewJWTGuard(provider, secret, config)`
   - After: `NewJWTGuard(name, provider, tokenManager, hasher)`

2. **Authenticatable Interface**: Simplified to return `string` for ID
   - Before: `GetAuthIdentifier() interface{}`
   - After: `GetAuthIdentifier() string`

3. **Provider Methods**: Now accept `context.Context`
   - Before: `FindByID(id string)`
   - After: `FindByID(ctx context.Context, id string)`

### Removed Features

- Legacy session storage (replaced with pluggable SessionStore interface)
- Built-in database migrations (use external migration tools)

## Configuration

### Recommended Configuration

```go
// JWT Configuration
jwtConfig := breitheamh.JWTConfig{
    SigningMethod: "HS256",
    Issuer:        "your-app",
}

// Password Hasher
hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)

// Rate Limiter
rateLimiter := breitheamh.NewRateLimiter(100, time.Minute)

// Brute Force Protection
bruteForceProtector := breitheamh.NewBruteForceProtector(
    5,              // max attempts
    15*time.Minute, // lockout duration
)
```

## Testing

### Unit Tests

```go
// Use built-in test providers
provider := providers.NewSQLProvider(db, "users")

// Mock authenticatable
user := &breitheamh.BaseUser{
    ID:    "1",
    Email: "test@example.com",
}
```

### Integration Tests

See `pkg/breitheamh/integration_test.go` for examples of full authentication flows.

## Performance

### Benchmarks

Run benchmarks to verify performance:

```bash
go test -bench=. -benchmem ./pkg/breitheamh/...
```

Key performance metrics (on reference hardware):
- Password hashing (bcrypt): ~46ms per operation
- Permission matching: <100ns per operation
- Cache get: ~35ns per operation (parallel)
- JWT token validation: ~1-2μs per operation

### Optimization Tips

1. **Enable Caching**: Use permission and role caching with appropriate TTL
2. **Batch Permission Checks**: Check multiple permissions in one call when possible
3. **Lazy Loading**: Leverage provider pattern for on-demand user loading
4. **Connection Pooling**: Configure database connection pools appropriately

## Examples

Comprehensive examples are available in the `examples/` directory:

- `basic-auth/`: Simple username/password authentication
- `jwt-api/`: JWT-based API authentication
- `session-auth/`: Session-based authentication
- `policy-authorization/`: Policy-based authorization
- `2fa-example/`: Two-factor authentication
- `multi-tenant/`: Multi-tenant application
- `cosan-integration/`: Cosan router integration
- `datamapper-integration/`: Datamapper provider

## Support

For questions or issues:
- GitHub Issues: https://github.com/toutaio/toutago-breitheamh-auth/issues
- Documentation: See `docs/` directory
- Examples: See `examples/` directory

## What's Next

After migrating to v1.0.0:

1. Review security best practices in `docs/SECURITY.md`
2. Set up monitoring and logging for authentication events
3. Configure rate limiting and brute force protection
4. Enable two-factor authentication for sensitive operations
5. Implement audit logging for compliance

## Version Support

- v1.0.0 will receive security updates for at least 12 months
- Go 1.21+ is required
- Breaking changes will only occur in major version bumps (v2.0.0, etc.)
