# Cosan Router Integration Example

This example demonstrates how to integrate Breitheamh authentication with Cosan router (or any HTTP router using `http.HandlerFunc`).

## Features Demonstrated

- JWT-based authentication
- Authentication middleware
- Role-based access control
- Permission-based authorization
- Multiple authorization strategies
- Public and protected routes

## Running the Example

```bash
go run main.go
```

The server will start on port 8080.

## Testing the API

### 1. Login (get JWT token)

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password123"}'
```

Response:
```json
{"token":"eyJhbGc...","user":"admin@example.com"}
```

### 2. Access protected route

```bash
curl http://localhost:8080/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 3. Access admin route (requires admin role)

```bash
curl http://localhost:8080/admin \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 4. Create post (requires posts.create permission)

```bash
curl -X POST http://localhost:8080/posts \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 5. Access content (requires any of: admin, editor, moderator roles)

```bash
curl http://localhost:8080/content \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Available Middleware

### Authentication Middleware

Requires a valid JWT token:

```go
authMiddleware := cosan.NewAuthMiddleware(cosan.AuthMiddlewareConfig{
    Guard:        jwtGuard,
    ExcludePaths: []string{"/", "/login", "/health"},
})

mux.HandleFunc("/protected", authMiddleware.Handle(handler))
```

### Role-Based Middleware

Requires a specific role:

```go
mux.HandleFunc("/admin", 
    authMiddleware.Handle(
        cosan.RequireRole("admin")(handler),
    ),
)
```

### Permission-Based Middleware

Requires a specific permission:

```go
mux.HandleFunc("/posts", 
    authMiddleware.Handle(
        cosan.RequirePermission("posts.create")(handler),
    ),
)
```

### Multiple Roles Middleware

Requires any of the specified roles:

```go
mux.HandleFunc("/content", 
    authMiddleware.Handle(
        cosan.RequireAnyRole("admin", "editor", "moderator")(handler),
    ),
)
```

## Integration with Cosan Router

While this example uses the standard `http.NewServeMux()`, the middleware works perfectly with Cosan router since both use the standard `http.HandlerFunc` signature.

To use with Cosan router:

```go
import "github.com/toutaio/toutago-cosan-router/pkg/cosan"

router := cosan.NewRouter()

// Apply authentication middleware
router.Use(authMiddleware.Handle)

// Define routes
router.GET("/profile", handleProfile)
router.GET("/admin", cosan.RequireRole("admin")(handleAdmin))
```

## User Context Helpers

Get authenticated user from context:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    user := cosan.GetUser(r.Context())
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    // Use user...
    fmt.Fprintf(w, "Hello %s", user.GetAuthIdentifier())
}
```

Get guard from context:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    guard := cosan.GetGuard(r.Context())
    // Use guard...
}
```

## Production Considerations

1. **Secret Key**: Change the JWT signing key to a strong, random secret
2. **HTTPS**: Always use HTTPS in production
3. **Token Storage**: Store refresh tokens securely
4. **Error Handling**: Implement custom error handlers for better UX
5. **Rate Limiting**: Add rate limiting to prevent brute force attacks
6. **Logging**: Add security event logging
