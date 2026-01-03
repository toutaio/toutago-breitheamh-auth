// Package breitheamh provides a production-ready authentication and authorization library for Go.
//
// Breitheamh (Old Irish: "judge, arbiter") is a comprehensive auth system inspired by Laravel's
// Spatie permissions package and built-in authentication, offering flexible guard-based authentication,
// role-based access control (RBAC), policy-driven authorization, and comprehensive security features.
// Part of the Toutā Framework ecosystem.
//
// # Features
//
//   - Multiple guard system (JWT, session-based, API token, custom)
//   - Token generation, validation, refresh, and revocation
//   - Password hashing (bcrypt, argon2)
//   - Email verification workflow
//   - Multi-factor authentication (TOTP)
//   - Remember me functionality
//   - Role-based access control (RBAC)
//   - Permission management with wildcards (posts.*, *.create)
//   - Policy classes for resource-specific authorization
//   - Gates for simple boolean checks
//   - Permission groups and inheritance
//   - Team/organization scoping support
//   - Super admin bypass capability
//   - CSRF protection tokens
//   - Rate limiting per user/IP
//   - Audit trail for auth events
//   - Secure token storage
//   - Account locking after failed attempts
//   - Password policy enforcement
//
// # Quick Start
//
// Basic authentication with password hashing:
//
//	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
//	hashedPassword, _ := hasher.Hash("secret123")
//	user := breitheamh.NewBaseUser("user-1", "user@example.com", hashedPassword)
//	err := hasher.Verify("secret123", user.GetPassword())
//
// # Guards
//
// Use guards for different authentication strategies:
//
//	// JWT Guard
//	jwtGuard := breitheamh.NewJWTGuard(userProvider, secretKey)
//	user, err := jwtGuard.Authenticate(ctx, credentials)
//
//	// Session Guard
//	sessionGuard := breitheamh.NewSessionGuard(userProvider, sessionStore)
//	user, err := sessionGuard.Authenticate(ctx, credentials)
//
//	// API Token Guard
//	tokenGuard := breitheamh.NewAPITokenGuard(tokenProvider)
//	user, err := tokenGuard.Authenticate(ctx, apiToken)
//
//	// Guard Manager for multiple guards
//	manager := breitheamh.NewGuardManager()
//	manager.AddGuard("jwt", jwtGuard)
//	manager.AddGuard("session", sessionGuard)
//	user, err := manager.Guard("jwt").Authenticate(ctx, credentials)
//
// # Permissions and Roles
//
// Role-based access control with wildcard support:
//
//	// Create permissions
//	createPost := breitheamh.Permission{ID: "1", Name: "posts.create"}
//	editPost := breitheamh.Permission{ID: "2", Name: "posts.edit"}
//
//	// Create role with permissions
//	editorRole := breitheamh.Role{
//	    ID:          "role-1",
//	    Name:        "editor",
//	    Permissions: []breitheamh.Permission{createPost, editPost},
//	}
//
//	// Assign role to user
//	user.AssignRole(editorRole)
//
//	// Check permissions
//	if user.HasPermission("posts.create") {
//	    // User can create posts
//	}
//
//	// Wildcard permissions
//	adminPerm := breitheamh.Permission{ID: "3", Name: "posts.*"}
//	user.GivePermission(adminPerm)
//	user.HasPermission("posts.delete") // true via wildcard
//
// # Authorization Policies
//
// Resource-specific authorization with policies:
//
//	type Post struct { AuthorID string }
//
//	type PostPolicy struct{}
//
//	func (p *PostPolicy) Update(user breitheamh.User, post *Post) bool {
//	    return user.GetID() == post.AuthorID
//	}
//
//	// Register and check policy
//	registry := breitheamh.NewPolicyRegistry()
//	registry.Register("Post", &PostPolicy{})
//	can := registry.Check(user, "Update", post)
//
// # Gates
//
// Simple authorization checks:
//
//	gates := breitheamh.NewGateRegistry()
//	gates.Define("admin-only", func(user breitheamh.User) bool {
//	    return user.HasRole("admin")
//	})
//
//	if gates.Allows(user, "admin-only") {
//	    // User is admin
//	}
//
// # HTTP Middleware
//
// Protect HTTP routes with authentication:
//
//	authMiddleware := breitheamh.NewAuthMiddleware(guardManager, "jwt")
//	protected := authMiddleware.Require()(handler)
//
//	// Permission-based protection
//	permMiddleware := breitheamh.NewPermissionMiddleware()
//	adminOnly := permMiddleware.RequirePermission("admin")(handler)
//
// # Security Features
//
// Rate limiting and brute force protection:
//
//	limiter := breitheamh.NewRateLimiter(5, time.Minute)
//	if limiter.Allow("user-id") {
//	    // Proceed with authentication
//	}
//
//	protector := breitheamh.NewBruteForceProtector(5, 15*time.Minute)
//	if protector.IsLocked("user@example.com") {
//	    // Account is locked
//	}
//
// CSRF protection:
//
//	csrf := breitheamh.NewCSRFProtector(32)
//	token := csrf.GenerateToken()
//	valid := csrf.ValidateToken(token)
//
// Password policies:
//
//	policy := breitheamh.NewPasswordPolicy(
//	    breitheamh.WithMinLength(8),
//	    breitheamh.WithRequireUppercase(true),
//	    breitheamh.WithRequireNumbers(true),
//	)
//	if err := policy.Validate("MyP@ssw0rd"); err != nil {
//	    // Password doesn't meet policy
//	}
//
// # Context Integration
//
// Store and retrieve authenticated users from context:
//
//	ctx = breitheamh.WithUser(ctx, user)
//	user, ok := breitheamh.GetUser(ctx)
//	userID := breitheamh.GetUserID(ctx)
//
// # Audit Trail
//
// Track authentication events:
//
//	auditor := breitheamh.NewAuditor(1000)
//	auditor.Log(ctx, breitheamh.EventLogin, user.GetID(), details)
//	events := auditor.GetUserEvents(user.GetID())
//
// # Thread Safety
//
// All core types are thread-safe and can be used concurrently from multiple goroutines.
// Guards, registries, and middleware use internal synchronization for safe concurrent access.
//
// # Version
//
// This is version 0.1.1 - initial release with core authentication and authorization features.
// Requires Go 1.22 or higher.
package breitheamh
