package breitheamh

import "context"

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
	name     string
	callback GateCallback
}

// NewCallbackGate creates a new callback-based gate.
func NewCallbackGate(name string, callback GateCallback) *CallbackGate {
	return &CallbackGate{
		name:     name,
		callback: callback,
	}
}

// Allows checks if the gate allows access.
func (g *CallbackGate) Allows(ctx context.Context, user User, args ...interface{}) bool {
	return g.callback(ctx, user, args...)
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
