# JWT API Authentication Example

This example demonstrates how to build a REST API with JWT authentication using toutago-breitheamh-auth.

## Features

- User registration and login
- JWT token generation
- Token refresh
- Protected API endpoints
- Permission-based authorization
- JSON error responses

## Running the Example

```bash
cd examples/jwt-api
go run main.go
```

The server will start on `http://localhost:8080`

## API Endpoints

### Public Endpoints

**POST /api/register** - Register a new user
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secretpass"}'
```

**POST /api/login** - Login and get JWT token
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**POST /api/refresh** - Refresh access token
```bash
curl -X POST http://localhost:8080/api/refresh \
  -H "Authorization: Bearer YOUR_REFRESH_TOKEN"
```

### Protected Endpoints

**GET /api/me** - Get current user info
```bash
curl http://localhost:8080/api/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**GET /api/posts** - Get posts (requires `posts.read` permission)
```bash
curl http://localhost:8080/api/posts \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Full Workflow Example

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  | jq -r '.access_token')

# 2. Get user info
curl http://localhost:8080/api/me \
  -H "Authorization: Bearer $TOKEN"

# 3. Get posts
curl http://localhost:8080/api/posts \
  -H "Authorization: Bearer $TOKEN"
```

## Key Implementation Details

### JWT Guard Setup

```go
config := breitheamh.DefaultJWTConfig("your-secret-key")
tokenManager := breitheamh.NewJWTTokenManager(config)
guard := breitheamh.NewJWTGuard("api", provider, tokenManager, hasher)
```

### Auth Middleware

```go
authMiddleware := breitheamh.NewAuthMiddleware(guard)
  .WithErrorHandler(breitheamh.JSONErrorHandler)

http.Handle("/api/me", authMiddleware.Handle(handler))
```

### Permission Checking

```go
authorizer := breitheamh.NewAuthorizer()
if !authorizer.Can(ctx, user, "posts.read", nil) {
    // Forbidden
}
```

## Security Notes

- Change the secret key in production
- Use HTTPS in production
- Store refresh tokens securely
- Implement token rotation
- Add rate limiting
- Validate all inputs

## Next Steps

- Add more endpoints
- Implement role-based access control
- Add database persistence
- Implement token blacklisting
- Add audit logging
