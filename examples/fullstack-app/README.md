# Full-Stack Blog Application Example

This example demonstrates a complete blog application using multiple Toutago components:

- **toutago-breitheamh-auth**: Authentication and authorization
- **toutago-cosan**: HTTP routing
- **toutago-datamapper**: Database operations
- **toutago-scela-bus**: Event dispatching

## Features

### Authentication
- User registration with password hashing
- JWT-based login with access and refresh tokens
- Token refresh endpoint
- Secure password storage using bcrypt

### Authorization
- Role-based access control (admin, editor, viewer)
- Policy-based authorization for posts
- Gate-based authorization for admin features
- Resource ownership checks

### API Endpoints

#### Public Endpoints
- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login and receive JWT tokens
- `POST /auth/refresh` - Refresh access token

#### Protected Endpoints (Requires Authentication)
- `GET /api/posts` - List all posts (shows published + own drafts)
- `GET /api/posts/:id` - View a specific post
- `POST /api/posts` - Create a new post
- `PUT /api/posts/:id` - Update own post
- `DELETE /api/posts/:id` - Delete own post

#### Admin Endpoints (Requires admin role)
- `GET /api/admin/users` - List all users

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Testing the API

### 1. Register a User

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepass123",
    "name": "John Doe"
  }'
```

### 2. Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepass123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer"
}
```

### 3. Create a Post (Authenticated)

```bash
curl -X POST http://localhost:8080/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "title": "My First Post",
    "content": "This is the content of my first post.",
    "published": true
  }'
```

### 4. List Posts

```bash
curl http://localhost:8080/api/posts \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Update a Post

```bash
curl -X PUT http://localhost:8080/api/posts/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "title": "Updated Title",
    "content": "Updated content",
    "published": true
  }'
```

### 6. Refresh Token

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

## Architecture

### Components Integration

```
┌─────────────┐
│   Cosan     │  HTTP routing and request handling
│   Router    │
└──────┬──────┘
       │
┌──────▼──────┐
│ Breitheamh  │  Authentication & Authorization
│   Auth      │  - JWT guard for token validation
│             │  - Policy-based authorization
│             │  - Role & permission checking
└──────┬──────┘
       │
┌──────▼──────┐
│ Datamapper  │  Database operations (SQLite)
│             │  - User management
│             │  - Post CRUD operations
└──────┬──────┘
       │
┌──────▼──────┐
│   Scéla     │  Event dispatching
│    Bus      │  - Login events
│             │  - Audit logging
└─────────────┘
```

### Security Features

1. **Password Hashing**: All passwords are hashed using bcrypt
2. **JWT Tokens**: Short-lived access tokens (15 min) with longer refresh tokens (7 days)
3. **Authorization Checks**: Multiple layers of authorization:
   - Middleware-based authentication
   - Role-based access control
   - Policy-based resource authorization
   - Gate-based feature flags

### Database Schema

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    published BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Learning Points

### Breitheamh Auth Integration

1. **Guard Setup**: JWT guard with configurable token durations
2. **Provider Pattern**: Datamapper provider for user storage
3. **Authorization Manager**: Centralized authorization logic
4. **Middleware**: Easy integration with Cosan router

### Best Practices Demonstrated

- Separation of concerns (handlers, policies, guards)
- Clean shutdown with graceful termination
- Event-driven architecture for audit logging
- Resource-based authorization
- Secure token storage and rotation

## Production Considerations

For production use, consider:

1. Use a real database (PostgreSQL, MySQL)
2. Store JWT secret in environment variables
3. Add rate limiting and brute force protection
4. Implement HTTPS/TLS
5. Add request logging and monitoring
6. Use database migrations
7. Add input validation
8. Implement CORS properly
9. Add comprehensive error handling
10. Use structured logging
