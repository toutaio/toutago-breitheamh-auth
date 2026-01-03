package breitheamh

import "context"

// GateInterceptor is a function that runs before or after a gate check.
// It can modify the result or perform side effects.
// Returning nil continues to the next interceptor/gate, returning a bool overrides the result.
type GateInterceptor func(ctx context.Context, user User, gateName string, args ...interface{}) *bool

// GateCallback is a function that determines if access should be granted.
type GateCallback func(ctx context.Context, user User, args ...interface{}) bool

// Gate represents a simple authorization gate.
type Gate interface {
	// Allows checks if the gate allows access
	Allows(ctx context.Context, user User, args ...interface{}) bool

	// Denies checks if the gate denies access
	Denies(ctx context.Context, user User, args ...interface{}) bool

	// Name returns the gate's name
	Name() string
}

// CallbackGate implements Gate using a callback function.
type CallbackGate struct {
	name              string
	callback          GateCallback
	beforeInterceptors []GateInterceptor
	afterInterceptors  []GateInterceptor
}

// NewCallbackGate creates a new callback-based gate.
func NewCallbackGate(name string, callback GateCallback) *CallbackGate {
	return &CallbackGate{
		name:               name,
		callback:           callback,
		beforeInterceptors: []GateInterceptor{},
		afterInterceptors:  []GateInterceptor{},
	}
}

// Before adds a before interceptor to the gate.
func (g *CallbackGate) Before(interceptor GateInterceptor) *CallbackGate {
	g.beforeInterceptors = append(g.beforeInterceptors, interceptor)
	return g
}

// After adds an after interceptor to the gate.
func (g *CallbackGate) After(interceptor GateInterceptor) *CallbackGate {
	g.afterInterceptors = append(g.afterInterceptors, interceptor)
	return g
}

// Allows checks if the gate allows access.
func (g *CallbackGate) Allows(ctx context.Context, user User, args ...interface{}) bool {
	// Run before interceptors
	for _, interceptor := range g.beforeInterceptors {
		if result := interceptor(ctx, user, g.name, args...); result != nil {
			return *result
		}
	}

	// Execute the main gate callback
	result := g.callback(ctx, user, args...)

	// Run after interceptors
	for _, interceptor := range g.afterInterceptors {
		if overrideResult := interceptor(ctx, user, g.name, args...); overrideResult != nil {
			return *overrideResult
		}
	}

	return result
}

// Denies checks if the gate denies access.
func (g *CallbackGate) Denies(ctx context.Context, user User, args ...interface{}) bool {
	return !g.Allows(ctx, user, args...)
}

// Name returns the gate's name.
func (g *CallbackGate) Name() string {
	return g.name
}

// PermissionGate is a gate that checks for a specific permission.
type PermissionGate struct {
	name       string
	permission string
}

// NewPermissionGate creates a new permission-based gate.
func NewPermissionGate(name, permission string) *PermissionGate {
	return &PermissionGate{
		name:       name,
		permission: permission,
	}
}

// Allows checks if the user has the required permission.
func (g *PermissionGate) Allows(ctx context.Context, user User, args ...interface{}) bool {
	return user.HasPermission(g.permission)
}

// Denies checks if the user lacks the required permission.
func (g *PermissionGate) Denies(ctx context.Context, user User, args ...interface{}) bool {
	return !g.Allows(ctx, user, args...)
}

// Name returns the gate's name.
func (g *PermissionGate) Name() string {
	return g.name
}

// RoleGate is a gate that checks for a specific role.
type RoleGate struct {
	name string
	role string
}

// NewRoleGate creates a new role-based gate.
func NewRoleGate(name, role string) *RoleGate {
	return &RoleGate{
		name: name,
		role: role,
	}
}

// Allows checks if the user has the required role.
func (g *RoleGate) Allows(ctx context.Context, user User, args ...interface{}) bool {
	return user.HasRole(g.role)
}

// Denies checks if the user lacks the required role.
func (g *RoleGate) Denies(ctx context.Context, user User, args ...interface{}) bool {
	return !g.Allows(ctx, user, args...)
}

// Name returns the gate's name.
func (g *RoleGate) Name() string {
	return g.name
}
