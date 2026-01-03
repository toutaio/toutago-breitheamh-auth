package providers

import (
	"context"
	"fmt"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// DataMapper represents the core datamapper interface from toutago-datamapper
type DataMapper interface {
	FindOne(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	FindAll(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	Insert(ctx context.Context, entity interface{}) error
	Update(ctx context.Context, entity interface{}) error
	Delete(ctx context.Context, entity interface{}) error
}

// DataMapperProvider implements UserProvider using toutago-datamapper
type DataMapperProvider struct {
	mapper          DataMapper
	userTable       string
	roleTable       string
	permissionTable string
	userRoleTable   string
	userPermTable   string
	rolePermTable   string
}

// DataMapperConfig configures the DataMapper provider
type DataMapperConfig struct {
	UserTable       string
	RoleTable       string
	PermissionTable string
	UserRoleTable   string
	UserPermTable   string
	RolePermTable   string
}

// NewDataMapperProvider creates a new DataMapper-based user provider
func NewDataMapperProvider(mapper DataMapper, config *DataMapperConfig) *DataMapperProvider {
	if config == nil {
		config = &DataMapperConfig{
			UserTable:       "users",
			RoleTable:       "roles",
			PermissionTable: "permissions",
			UserRoleTable:   "user_roles",
			UserPermTable:   "user_permissions",
			RolePermTable:   "role_permissions",
		}
	}

	return &DataMapperProvider{
		mapper:          mapper,
		userTable:       config.UserTable,
		roleTable:       config.RoleTable,
		permissionTable: config.PermissionTable,
		userRoleTable:   config.UserRoleTable,
		userPermTable:   config.UserPermTable,
		rolePermTable:   config.RolePermTable,
	}
}

// RetrieveByID retrieves a user by their unique identifier
func (p *DataMapperProvider) RetrieveByID(ctx context.Context, id interface{}) (breitheamh.User, error) {
	user := &breitheamh.BaseUser{}
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = $1", p.userTable)

	if err := p.mapper.FindOne(ctx, user, query, id); err != nil {
		return nil, fmt.Errorf("failed to retrieve user by ID: %w", err)
	}

	// Load roles and permissions
	if err := p.loadRoles(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to load user roles: %w", err)
	}

	if err := p.loadPermissions(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to load user permissions: %w", err)
	}

	return user, nil
}

// RetrieveByCredentials retrieves a user by their credentials
func (p *DataMapperProvider) RetrieveByCredentials(
	ctx context.Context,
	credentials map[string]interface{},
) (breitheamh.User, error) {
	// Typically credentials contain "email" or "username" and "password"
	identifier, ok := credentials["email"]
	if !ok {
		identifier, ok = credentials["username"]
		if !ok {
			return nil, fmt.Errorf("credentials must contain 'email' or 'username'")
		}
	}

	user := &breitheamh.BaseUser{}
	var query string

	if _, emailOk := credentials["email"]; emailOk {
		query = fmt.Sprintf("SELECT * FROM %s WHERE email = $1", p.userTable)
	} else {
		query = fmt.Sprintf("SELECT * FROM %s WHERE username = $1", p.userTable)
	}

	if err := p.mapper.FindOne(ctx, user, query, identifier); err != nil {
		return nil, fmt.Errorf("failed to retrieve user by credentials: %w", err)
	}

	// Load roles and permissions
	if err := p.loadRoles(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to load user roles: %w", err)
	}

	if err := p.loadPermissions(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to load user permissions: %w", err)
	}

	return user, nil
}

// RetrieveByToken retrieves a user by their remember token
func (p *DataMapperProvider) RetrieveByToken(ctx context.Context, identifier, token string) (breitheamh.User, error) {
	user := &breitheamh.BaseUser{}
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = $1 AND remember_token = $2", p.userTable)

	if err := p.mapper.FindOne(ctx, user, query, identifier, token); err != nil {
		return nil, fmt.Errorf("failed to retrieve user by token: %w", err)
	}

	// Load roles and permissions
	if err := p.loadRoles(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to load user roles: %w", err)
	}

	if err := p.loadPermissions(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to load user permissions: %w", err)
	}

	return user, nil
}

// UpdateRememberToken updates the remember token for a user
func (p *DataMapperProvider) UpdateRememberToken(ctx context.Context, user breitheamh.User, token string) error {
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return fmt.Errorf("user must be of type *BaseUser")
	}

	baseUser.RememberToken = token
	return p.mapper.Update(ctx, baseUser)
}

// loadRoles loads roles for a user from the database
func (p *DataMapperProvider) loadRoles(ctx context.Context, user *breitheamh.BaseUser) error {
	query := fmt.Sprintf(`
		SELECT r.* FROM %s r
		INNER JOIN %s ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`, p.roleTable, p.userRoleTable)

	var roles []breitheamh.Role
	if err := p.mapper.FindAll(ctx, &roles, query, user.ID); err != nil {
		return err
	}

	// Load permissions for each role
	for i := range roles {
		if err := p.loadRolePermissions(ctx, &roles[i]); err != nil {
			return err
		}
	}

	user.Roles = roles
	return nil
}

// loadPermissions loads direct permissions for a user
func (p *DataMapperProvider) loadPermissions(ctx context.Context, user *breitheamh.BaseUser) error {
	query := fmt.Sprintf(`
		SELECT p.* FROM %s p
		INNER JOIN %s up ON p.id = up.permission_id
		WHERE up.user_id = $1
	`, p.permissionTable, p.userPermTable)

	var permissions []breitheamh.Permission
	if err := p.mapper.FindAll(ctx, &permissions, query, user.ID); err != nil {
		return err
	}

	user.DirectPermissions = permissions
	return nil
}

// loadRolePermissions loads permissions for a role
func (p *DataMapperProvider) loadRolePermissions(ctx context.Context, role *breitheamh.Role) error {
	query := fmt.Sprintf(`
		SELECT p.* FROM %s p
		INNER JOIN %s rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
	`, p.permissionTable, p.rolePermTable)

	var permissions []breitheamh.Permission
	if err := p.mapper.FindAll(ctx, &permissions, query, role.ID); err != nil {
		return err
	}

	role.Permissions = permissions
	return nil
}

// FindByID implements the UserProvider interface
func (p *DataMapperProvider) FindByID(ctx context.Context, id string) (breitheamh.User, error) {
	return p.RetrieveByID(ctx, id)
}

// FindByCredentials implements the UserProvider interface
func (p *DataMapperProvider) FindByCredentials(
	ctx context.Context,
	credentials map[string]interface{},
) (breitheamh.User, error) {
	return p.RetrieveByCredentials(ctx, credentials)
}

// UpdateUser implements the UserProvider interface
func (p *DataMapperProvider) UpdateUser(ctx context.Context, user breitheamh.User) error {
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return fmt.Errorf("user must be of type *BaseUser")
	}
	return p.mapper.Update(ctx, baseUser)
}
