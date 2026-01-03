# Security Best Practices

This guide covers security best practices when using **Breitheamh** for authentication and authorization.

## Table of Contents

- [Password Security](#password-security)
- [Token Security](#token-security)
- [Session Security](#session-security)
- [API Security](#api-security)
- [Authorization Security](#authorization-security)
- [Common Vulnerabilities](#common-vulnerabilities)
- [Security Checklist](#security-checklist)

## Password Security

### 1. Use Strong Password Hashing

```go
// Good - Use Argon2 (recommended)
hasher := breitheamh.NewArgon2Hasher()
hashedPassword, err := hasher.Hash("userPassword123")

// Acceptable - Use bcrypt
hasher := breitheamh.NewBcryptHasher(12) // cost=12

// Never - plain text or weak hashing
// DON'T USE: md5, sha1, sha256 without salt
```

### 2. Enforce Password Complexity

```go
type PasswordValidator struct {
    MinLength      int
    RequireUpper   bool
    RequireLower   bool
    RequireNumber  bool
    RequireSpecial bool
}

func (v *PasswordValidator) Validate(password string) error {
    if len(password) < v.MinLength {
        return errors.New("password too short")
    }
    
    if v.RequireUpper && !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
        return errors.New("password must contain uppercase letter")
    }
    
    if v.RequireLower && !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
        return errors.New("password must contain lowercase letter")
    }
    
    if v.RequireNumber && !strings.ContainsAny(password, "0123456789") {
        return errors.New("password must contain number")
    }
    
    if v.RequireSpecial && !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
        return errors.New("password must contain special character")
    }
    
    return nil
}

// Use it
validator := &PasswordValidator{
    MinLength:      12,
    RequireUpper:   true,
    RequireLower:   true,
    RequireNumber:  true,
    RequireSpecial: true,
}

if err := validator.Validate(newPassword); err != nil {
    return err
}
```

### 3. Prevent Password Reuse

```go
type UserWithPasswordHistory struct {
    breitheamh.BaseUser
    PasswordHistory []string // Store hashed passwords
}

func (u *UserWithPasswordHistory) CanUsePassword(newPassword string, hasher breitheamh.PasswordHasher) bool {
    // Check against last 5 passwords
    for i := 0; i < len(u.PasswordHistory) && i < 5; i++ {
        if hasher.Check(newPassword, u.PasswordHistory[i]) {
            return false // Password was used before
        }
    }
    return true
}
```

### 4. Implement Password Reset Safely

```go
type PasswordResetToken struct {
    Token     string
    UserID    string
    ExpiresAt time.Time
    Used      bool
}

func GenerateResetToken(userID string) (*PasswordResetToken, error) {
    // Generate cryptographically secure random token
    tokenBytes := make([]byte, 32)
    if _, err := rand.Read(tokenBytes); err != nil {
        return nil, err
    }
    
    token := base64.URLEncoding.EncodeToString(tokenBytes)
    
    return &PasswordResetToken{
        Token:     token,
        UserID:    userID,
        ExpiresAt: time.Now().Add(1 * time.Hour), // Short expiry
        Used:      false,
    }, nil
}

func ResetPassword(token, newPassword string) error {
    resetToken := findResetToken(token)
    
    // Validate token
    if resetToken == nil || resetToken.Used {
        return errors.New("invalid or used token")
    }
    
    if time.Now().After(resetToken.ExpiresAt) {
        return errors.New("token expired")
    }
    
    // Mark token as used (prevents reuse)
    resetToken.Used = true
    
    // Update password
    user := findUser(resetToken.UserID)
    user.SetPassword(newPassword)
    
    return nil
}
```

## Token Security

### 1. Use Short-Lived Access Tokens

```go
config := &breitheamh.JWTConfig{
    SecretKey:            []byte(os.Getenv("JWT_SECRET")),
    AccessTokenDuration:  15 * time.Minute,  // Short-lived
    RefreshTokenDuration: 7 * 24 * time.Hour, // Longer
}
```

### 2. Implement Token Rotation

```go
func RefreshTokens(refreshToken string) (string, string, error) {
    // Verify refresh token
    claims, err := jwtGuard.VerifyToken(refreshToken)
    if err != nil {
        return "", "", err
    }
    
    // Revoke old refresh token
    if err := jwtGuard.RevokeToken(refreshToken); err != nil {
        return "", "", err
    }
    
    // Generate new tokens
    user, err := userProvider.RetrieveByID(claims.Subject)
    if err != nil {
        return "", "", err
    }
    
    newAccessToken, newRefreshToken, err := jwtGuard.GenerateTokens(user)
    return newAccessToken, newRefreshToken, err
}
```

### 3. Use Secure Secret Keys

```go
// Good - 256-bit random secret
secretKey := make([]byte, 32)
if _, err := rand.Read(secretKey); err != nil {
    log.Fatal(err)
}

// Store in environment variable
os.Setenv("JWT_SECRET", base64.StdEncoding.EncodeToString(secretKey))

// Bad - weak or hardcoded secrets
// DON'T USE: secretKey := []byte("my-secret")
```

### 4. Implement Token Blacklist

```go
type TokenBlacklist interface {
    Add(token string, expiresAt time.Time) error
    IsBlacklisted(token string) bool
}

type RedisTokenBlacklist struct {
    client *redis.Client
}

func (b *RedisTokenBlacklist) Add(token string, expiresAt time.Time) error {
    ttl := time.Until(expiresAt)
    return b.client.Set(context.Background(), "blacklist:"+token, "1", ttl).Err()
}

func (b *RedisTokenBlacklist) IsBlacklisted(token string) bool {
    val, err := b.client.Get(context.Background(), "blacklist:"+token).Result()
    return err == nil && val == "1"
}
```

### 5. Validate Token Claims

```go
func ValidateTokenClaims(claims *breitheamh.JWTClaims) error {
    // Check expiration
    if time.Now().After(claims.ExpiresAt.Time) {
        return errors.New("token expired")
    }
    
    // Check not before
    if time.Now().Before(claims.NotBefore.Time) {
        return errors.New("token not yet valid")
    }
    
    // Check issuer
    if claims.Issuer != "your-app" {
        return errors.New("invalid issuer")
    }
    
    // Check audience
    expectedAudience := "your-api"
    validAudience := false
    for _, aud := range claims.Audience {
        if aud == expectedAudience {
            validAudience = true
            break
        }
    }
    if !validAudience {
        return errors.New("invalid audience")
    }
    
    return nil
}
```

## Session Security

### 1. Use Secure Session Cookies

```go
config := &breitheamh.SessionConfig{
    CookieName:     "session_id",
    CookiePath:     "/",
    CookieSecure:   true, // HTTPS only
    CookieHTTPOnly: true, // Prevents XSS
    CookieSameSite: http.SameSiteStrictMode, // CSRF protection
    SessionTTL:     24 * time.Hour,
}
```

### 2. Regenerate Session ID on Login

```go
func Login(w http.ResponseWriter, r *http.Request, user breitheamh.User) error {
    // Delete old session
    oldSessionID := getSessionIDFromRequest(r)
    if oldSessionID != "" {
        sessionStore.Delete(oldSessionID)
    }
    
    // Create new session (new ID)
    sessionID := generateSecureSessionID()
    session := &Session{
        ID:        sessionID,
        UserID:    user.GetID(),
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
    }
    
    sessionStore.Store(sessionID, session)
    setSessionCookie(w, sessionID)
    
    return nil
}
```

### 3. Implement Session Timeout

```go
type Session struct {
    ID             string
    UserID         string
    CreatedAt      time.Time
    LastActivityAt time.Time
    ExpiresAt      time.Time
}

func ValidateSession(sessionID string) (*Session, error) {
    session := sessionStore.Get(sessionID)
    if session == nil {
        return nil, errors.New("session not found")
    }
    
    // Check absolute expiration
    if time.Now().After(session.ExpiresAt) {
        sessionStore.Delete(sessionID)
        return nil, errors.New("session expired")
    }
    
    // Check idle timeout (30 minutes)
    idleTimeout := 30 * time.Minute
    if time.Since(session.LastActivityAt) > idleTimeout {
        sessionStore.Delete(sessionID)
        return nil, errors.New("session timed out")
    }
    
    // Update last activity
    session.LastActivityAt = time.Now()
    sessionStore.Update(session)
    
    return session, nil
}
```

### 4. Bind Sessions to IP/User-Agent

```go
type Session struct {
    ID         string
    UserID     string
    IPAddress  string
    UserAgent  string
    CreatedAt  time.Time
}

func ValidateSessionBinding(session *Session, r *http.Request) error {
    // Check IP address
    requestIP := getClientIP(r)
    if session.IPAddress != requestIP {
        return errors.New("session IP mismatch")
    }
    
    // Check User-Agent
    requestUA := r.Header.Get("User-Agent")
    if session.UserAgent != requestUA {
        return errors.New("session user-agent mismatch")
    }
    
    return nil
}
```

## API Security

### 1. Rate Limiting

```go
type RateLimiter struct {
    requests map[string][]time.Time
    mu       sync.Mutex
    limit    int
    window   time.Duration
}

func (rl *RateLimiter) Allow(key string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    now := time.Now()
    windowStart := now.Add(-rl.window)
    
    // Clean old requests
    requests := rl.requests[key]
    var validRequests []time.Time
    for _, t := range requests {
        if t.After(windowStart) {
            validRequests = append(validRequests, t)
        }
    }
    
    // Check limit
    if len(validRequests) >= rl.limit {
        return false
    }
    
    // Add current request
    validRequests = append(validRequests, now)
    rl.requests[key] = validRequests
    
    return true
}

// Use it
rateLimiter := &RateLimiter{
    requests: make(map[string][]time.Time),
    limit:    100,           // 100 requests
    window:   1 * time.Hour, // per hour
}

func RateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        key := getClientIP(r)
        
        if !rateLimiter.Allow(key) {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

### 2. CORS Configuration

```go
func SetupCORS(w http.ResponseWriter, r *http.Request) {
    allowedOrigins := []string{
        "https://yourdomain.com",
        "https://app.yourdomain.com",
    }
    
    origin := r.Header.Get("Origin")
    for _, allowed := range allowedOrigins {
        if origin == allowed {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            break
        }
    }
    
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
    w.Header().Set("Access-Control-Max-Age", "3600")
}
```

### 3. API Versioning

```go
// Version in URL
r.HandleFunc("/api/v1/users", v1UsersHandler)
r.HandleFunc("/api/v2/users", v2UsersHandler)

// Or in header
func VersionMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        version := r.Header.Get("API-Version")
        if version == "" {
            version = "v1" // Default
        }
        
        ctx := context.WithValue(r.Context(), "api_version", version)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Authorization Security

### 1. Principle of Least Privilege

```go
// Good - specific permissions
user.AssignPermission("posts.create")
user.AssignPermission("posts.update")

// Bad - overly broad permissions
// user.AssignPermission("*")
```

### 2. Validate Resource Ownership

```go
func (p *PostPolicy) Update(user breitheamh.User, post *Post) bool {
    // Always check ownership
    if user.GetID() != post.AuthorID {
        return false
    }
    
    // Additional checks
    if post.Published && !user.HasRole("admin") {
        return false
    }
    
    return true
}
```

### 3. Implement Super Admin Carefully

```go
func (u *BaseUser) IsSuperAdmin() bool {
    // Use separate flag, not just a role
    return u.SuperAdmin
}

// Protect super admin assignment
func PromoteToSuperAdmin(actor, target breitheamh.User) error {
    // Only super admins can create super admins
    if !actor.IsSuperAdmin() {
        return errors.New("unauthorized")
    }
    
    // Require additional confirmation
    // Log the action
    auditLog.LogCritical("super_admin_promotion", map[string]interface{}{
        "actor":  actor.GetID(),
        "target": target.GetID(),
    })
    
    target.(*BaseUser).SuperAdmin = true
    return nil
}
```

## Common Vulnerabilities

### 1. SQL Injection Prevention

```go
// Good - parameterized queries
func FindUserByEmail(email string) (*User, error) {
    var user User
    err := db.QueryRow("SELECT * FROM users WHERE email = $1", email).Scan(&user)
    return &user, err
}

// Bad - string concatenation
// DON'T USE: query := "SELECT * FROM users WHERE email = '" + email + "'"
```

### 2. XSS Prevention

```go
import "html/template"

// Good - automatic escaping
func RenderUserProfile(w http.ResponseWriter, user *User) {
    tmpl := template.Must(template.New("profile").Parse(`
        <h1>{{.Name}}</h1>
        <p>{{.Bio}}</p>
    `))
    tmpl.Execute(w, user)
}

// Also sanitize user input
import "github.com/microcosm-cc/bluemonday"

func SanitizeHTML(input string) string {
    p := bluemonday.UGCPolicy()
    return p.Sanitize(input)
}
```

### 3. CSRF Protection

```go
type CSRFToken struct {
    Token     string
    UserID    string
    ExpiresAt time.Time
}

func GenerateCSRFToken(userID string) string {
    tokenBytes := make([]byte, 32)
    rand.Read(tokenBytes)
    token := base64.URLEncoding.EncodeToString(tokenBytes)
    
    csrfStore.Store(token, &CSRFToken{
        Token:     token,
        UserID:    userID,
        ExpiresAt: time.Now().Add(1 * time.Hour),
    })
    
    return token
}

func ValidateCSRFToken(userID, token string) bool {
    stored := csrfStore.Get(token)
    if stored == nil {
        return false
    }
    
    if stored.UserID != userID {
        return false
    }
    
    if time.Now().After(stored.ExpiresAt) {
        return false
    }
    
    return true
}
```

### 4. Timing Attack Prevention

```go
import "crypto/subtle"

// Good - constant time comparison
func ComparePasswords(hashedPassword, providedPassword string) bool {
    return subtle.ConstantTimeCompare(
        []byte(hashedPassword),
        []byte(providedPassword),
    ) == 1
}

// Bad - early return leaks information
// DON'T USE: return hashedPassword == providedPassword
```

## Security Checklist

### Development

- [ ] Use environment variables for secrets
- [ ] Enable HTTPS in production
- [ ] Use strong password hashing (Argon2/bcrypt)
- [ ] Implement rate limiting
- [ ] Validate all user input
- [ ] Use parameterized database queries
- [ ] Enable CORS properly
- [ ] Implement CSRF protection
- [ ] Use secure session cookies
- [ ] Log security events

### Authentication

- [ ] Enforce password complexity
- [ ] Implement account lockout after failed attempts
- [ ] Use short-lived access tokens (15-30 min)
- [ ] Implement token rotation
- [ ] Support 2FA/MFA
- [ ] Implement password reset flow
- [ ] Regenerate session IDs on login
- [ ] Bind sessions to IP/User-Agent

### Authorization

- [ ] Follow principle of least privilege
- [ ] Validate resource ownership
- [ ] Implement proper role hierarchy
- [ ] Use policies for complex authorization
- [ ] Audit permission changes
- [ ] Protect super admin privileges
- [ ] Check authorization on every request

### Production

- [ ] Monitor failed authentication attempts
- [ ] Set up security alerts
- [ ] Implement audit logging
- [ ] Regular security reviews
- [ ] Keep dependencies updated
- [ ] Run security scanners (gosec)
- [ ] Perform penetration testing
- [ ] Have incident response plan

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Go Security Practices](https://github.com/OWASP/Go-SCP)

## Next Steps

- Review [Authentication Guide](AUTHENTICATION_GUIDE.md)
- Review [Authorization Guide](AUTHORIZATION_GUIDE.md)
- Check [examples/](../examples/) for secure implementations
