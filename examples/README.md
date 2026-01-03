# Breitheamh Authentication Examples

This directory contains comprehensive examples demonstrating various features and use cases of the Breitheamh authentication library.

## Available Examples

### 1. Basic Authentication (`basic-auth/`)
**Demonstrates:** Simple user authentication flow with email and password.

```bash
cd examples/basic-auth
go run main.go
```

Features:
- User registration with password hashing
- Login with credentials validation
- Role and permission management
- Password verification

### 2. JWT API Authentication (`jwt-api/`)
**Demonstrates:** JWT-based API authentication with token generation and validation.

```bash
cd examples/jwt-api
go run main.go
```

Features:
- JWT token generation
- Token validation and refresh
- Protected API endpoints
- Bearer token authentication

### 3. Session Authentication (`session-auth/`)
**Demonstrates:** Session-based authentication with server-side session storage.

```bash
cd examples/session-auth
go run main.go
```

Features:
- Session creation and management
- Session TTL and expiration
- Remember me functionality

### 4. HTTP Middleware (`http-middleware/`)
**Demonstrates:** Integration of authentication middleware with HTTP handlers.

```bash
cd examples/http-middleware
go run main.go
```

Features:
- Authentication middleware
- Authorization middleware (permission and role-based)
- Middleware chaining
- Custom error responses

### 5. Policy Authorization (`policy-authorization/`)
**Demonstrates:** Policy-based authorization for resource-level access control.

```bash
cd examples/policy-authorization
go run main.go
```

Features:
- Policy registration
- Resource-based authorization
- Policy method resolution
- Before/after hooks

### 6. API Token Authentication (`api-token/`)
**Demonstrates:** Long-lived API token authentication for service-to-service communication.

```bash
cd examples/api-token
go run main.go
```

Features:
- API token generation
- Token revocation
- Rate limiting
- IP-based restrictions

### 7. Cosan Router Integration (`cosan-integration/`)
**Demonstrates:** Integration with HTTP routers for advanced routing features.

```bash
cd examples/cosan-integration
go run main.go
```

Features:
- HTTP router middleware integration
- Route groups with authentication
- Permission-based route protection
- Role-based route protection

## Running All Examples

To test all examples at once:

```bash
# Test compilation of all examples
for dir in */; do
  echo "Testing $dir"
  cd "$dir"
  go build .
  cd ..
done
```

## Common Patterns

### Authentication Flow
1. User provides credentials
2. Guard validates credentials
3. Token/session is generated
4. User is authenticated

### Authorization Flow
1. User is authenticated
2. Required permission/role is checked
3. Access is granted or denied

### Middleware Pattern
```go
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Validate token
        // Check permissions
        // Call next handler or return error
    }
}
```

## Security Best Practices

All examples demonstrate:
- ✅ Password hashing (bcrypt/argon2)
- ✅ JWT signature validation
- ✅ Token expiration handling
- ✅ CSRF protection (where applicable)
- ✅ Rate limiting
- ✅ Secure error messages (no information leakage)

## Additional Resources

- [Main Documentation](../docs/)
- [Quick Start Guide](../docs/QUICK_START.md)
- [API Reference](https://pkg.go.dev/github.com/toutaio/toutago-breitheamh-auth)
- [Contributing Guide](../CONTRIBUTING.md)

## Getting Help

If you have questions or need help with the examples:
1. Check the [documentation](../docs/)
2. Review the code comments in each example
3. Open an issue on GitHub
4. Read the test files in `pkg/breitheamh/`
