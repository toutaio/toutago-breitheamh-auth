package breitheamh

import "context"

// Policy defines authorization logic for a specific resource type.
// Policies contain methods that determine if a user can perform actions on resources.
type Policy interface {
	// Before is called before any policy method. Return true to allow, false to deny, or nil to continue.
	Before(ctx context.Context, user User, ability string) *bool
}

// PolicyRegistry manages policies for different resource types.
type PolicyRegistry struct {
	policies map[string]Policy
}

// NewPolicyRegistry creates a new policy registry.
func NewPolicyRegistry() *PolicyRegistry {
	return &PolicyRegistry{
		policies: make(map[string]Policy),
	}
}

// Register registers a policy for a resource type.
func (r *PolicyRegistry) Register(resourceType string, policy Policy) {
	r.policies[resourceType] = policy
}

// Get retrieves a policy for a resource type.
func (r *PolicyRegistry) Get(resourceType string) (Policy, bool) {
	policy, exists := r.policies[resourceType]
	return policy, exists
}

// Authorizer handles authorization checks using policies, gates, and permissions.
type Authorizer struct {
	policyRegistry *PolicyRegistry
	gates          map[string]Gate
	permissionMatcher *PermissionMatcher
}

// NewAuthorizer creates a new authorizer.
func NewAuthorizer() *Authorizer {
	return &Authorizer{
		policyRegistry: NewPolicyRegistry(),
		gates:          make(map[string]Gate),
		permissionMatcher: NewPermissionMatcher(),
	}
}

// RegisterPolicy registers a policy for a resource type.
func (a *Authorizer) RegisterPolicy(resourceType string, policy Policy) {
	a.policyRegistry.Register(resourceType, policy)
}

// DefineGate defines a gate with a callback function.
func (a *Authorizer) DefineGate(name string, callback GateCallback) {
	a.gates[name] = NewCallbackGate(name, callback)
}

// Can checks if a user can perform an ability on a resource.
func (a *Authorizer) Can(ctx context.Context, user User, ability string, resource interface{}) bool {
	// Super admins bypass all checks
	if user.IsSuperAdmin() {
		return true
	}

	// First check if there's a policy for this resource type
	if resource != nil {
		resourceType := getResourceType(resource)
		if policy, exists := a.policyRegistry.Get(resourceType); exists {
			// Check policy Before hook
			if result := policy.Before(ctx, user, ability); result != nil {
				return *result
			}

			// Try to call the policy method using reflection
			if result := callPolicyMethod(policy, ability, user, resource); result != nil {
				return *result
			}
		}
	}

	// Fall back to permission check
	return user.HasPermission(ability)
}

// Cannot checks if a user cannot perform an ability.
func (a *Authorizer) Cannot(ctx context.Context, user User, ability string, resource interface{}) bool {
	return !a.Can(ctx, user, ability, resource)
}

// Allows checks if a gate allows access for a user.
func (a *Authorizer) Allows(ctx context.Context, gateName string, user User, args ...interface{}) bool {
	gate, exists := a.gates[gateName]
	if !exists {
		return false
	}

	return gate.Allows(ctx, user, args...)
}

// Denies checks if a gate denies access for a user.
func (a *Authorizer) Denies(ctx context.Context, gateName string, user User, args ...interface{}) bool {
	return !a.Allows(ctx, gateName, user, args...)
}

// getResourceType returns a string representation of the resource type.
func getResourceType(resource interface{}) string {
	// Simple type name extraction
	// In a real implementation, this could use reflection to get the type name
	return "resource"
}

// callPolicyMethod attempts to call a policy method using reflection.
// Returns nil if the method doesn't exist or can't be called.
func callPolicyMethod(policy Policy, ability string, user User, resource interface{}) *bool {
	// This is a simplified implementation
	// In a full implementation, this would use reflection to call methods like:
	// - View(user, resource) bool
	// - Create(user, resource) bool
	// - Update(user, resource) bool
	// etc.
	return nil
}
