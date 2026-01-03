package providers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// SQLProvider is a generic SQL-based user provider
type SQLProvider struct {
	db                  *sql.DB
	userTable           string
	rolesTable          string
	permissionsTable    string
	userRolesTable      string
	userPermissionsTable string
	rolePermissionsTable string
	userFactory         func() breitheamh.User
}

// SQLProviderConfig holds configuration for SQL provider
type SQLProviderConfig struct {
	DB                  *sql.DB
	UserTable           string
	RolesTable          string
	PermissionsTable    string
	UserRolesTable      string
	UserPermissionsTable string
	RolePermissionsTable string
	UserFactory         func() breitheamh.User
}

// NewSQLProvider creates a new SQL-based user provider
func NewSQLProvider(config SQLProviderConfig) *SQLProvider {
	if config.UserTable == "" {
		config.UserTable = "users"
	}
	if config.RolesTable == "" {
		config.RolesTable = "roles"
	}
	if config.PermissionsTable == "" {
		config.PermissionsTable = "permissions"
	}
	if config.UserRolesTable == "" {
		config.UserRolesTable = "user_roles"
	}
	if config.UserPermissionsTable == "" {
		config.UserPermissionsTable = "user_permissions"
	}
	if config.RolePermissionsTable == "" {
		config.RolePermissionsTable = "role_permissions"
	}
	if config.UserFactory == nil {
		config.UserFactory = func() breitheamh.User {
			return &breitheamh.BaseUser{}
		}
	}

	return &SQLProvider{
		db:                  config.DB,
		userTable:           config.UserTable,
		rolesTable:          config.RolesTable,
		permissionsTable:    config.PermissionsTable,
		userRolesTable:      config.UserRolesTable,
		userPermissionsTable: config.UserPermissionsTable,
		rolePermissionsTable: config.RolePermissionsTable,
		userFactory:         config.UserFactory,
	}
}

// RetrieveByID retrieves a user by their unique identifier
func (p *SQLProvider) RetrieveByID(ctx context.Context, id interface{}) (breitheamh.User, error) {
	query := fmt.Sprintf("SELECT id, email, password, remember_token FROM %s WHERE id = ?", p.userTable)
	
	user := p.userFactory()
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return nil, errors.New("user factory must return *BaseUser")
	}

	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&baseUser.ID,
		&baseUser.Email,
		&baseUser.Password,
		&baseUser.RememberToken,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, breitheamh.ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// RetrieveByCredentials retrieves a user by their credentials
func (p *SQLProvider) RetrieveByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
	email, ok := credentials["email"].(string)
	if !ok {
		return nil, errors.New("email credential required")
	}

	query := fmt.Sprintf("SELECT id, email, password, remember_token FROM %s WHERE email = ?", p.userTable)
	
	user := p.userFactory()
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return nil, errors.New("user factory must return *BaseUser")
	}

	err := p.db.QueryRowContext(ctx, query, email).Scan(
		&baseUser.ID,
		&baseUser.Email,
		&baseUser.Password,
		&baseUser.RememberToken,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, breitheamh.ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// RetrieveByToken retrieves a user by their remember token
func (p *SQLProvider) RetrieveByToken(ctx context.Context, identifier interface{}, token string) (breitheamh.User, error) {
	query := fmt.Sprintf("SELECT id, email, password, remember_token FROM %s WHERE id = ? AND remember_token = ?", p.userTable)
	
	user := p.userFactory()
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return nil, errors.New("user factory must return *BaseUser")
	}

	err := p.db.QueryRowContext(ctx, query, identifier, token).Scan(
		&baseUser.ID,
		&baseUser.Email,
		&baseUser.Password,
		&baseUser.RememberToken,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, breitheamh.ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// UpdateRememberToken updates the remember token for a user
func (p *SQLProvider) UpdateRememberToken(ctx context.Context, user breitheamh.User, token string) error {
	query := fmt.Sprintf("UPDATE %s SET remember_token = ? WHERE id = ?", p.userTable)
	
	_, err := p.db.ExecContext(ctx, query, token, user.GetAuthIdentifier())
	return err
}

// LoadRoles loads roles for a user
func (p *SQLProvider) LoadRoles(ctx context.Context, user breitheamh.User) ([]*breitheamh.Role, error) {
	query := fmt.Sprintf(`
		SELECT r.id, r.name, r.guard_name
		FROM %s r
		INNER JOIN %s ur ON r.id = ur.role_id
		WHERE ur.user_id = ?
	`, p.rolesTable, p.userRolesTable)

	rows, err := p.db.QueryContext(ctx, query, user.GetAuthIdentifier())
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	var roles []*breitheamh.Role
	for rows.Next() {
		role := &breitheamh.Role{}
		err := rows.Scan(&role.ID, &role.Name, &role.GuardName)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// LoadPermissions loads permissions for a user
func (p *SQLProvider) LoadPermissions(ctx context.Context, user breitheamh.User) ([]*breitheamh.Permission, error) {
	directQuery := fmt.Sprintf(`
		SELECT p.id, p.name, p.guard_name, p.group_name
		FROM %s p
		INNER JOIN %s up ON p.id = up.permission_id
		WHERE up.user_id = ?
	`, p.permissionsTable, p.userPermissionsTable)

	roleQuery := fmt.Sprintf(`
		SELECT DISTINCT p.id, p.name, p.guard_name, p.group_name
		FROM %s p
		INNER JOIN %s rp ON p.id = rp.permission_id
		INNER JOIN %s ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = ?
	`, p.permissionsTable, p.rolePermissionsTable, p.userRolesTable)

	permissions := make(map[string]*breitheamh.Permission)

	rows, err := p.db.QueryContext(ctx, directQuery, user.GetAuthIdentifier())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		perm := &breitheamh.Permission{}
		err := rows.Scan(&perm.ID, &perm.Name, &perm.GuardName, &perm.GroupName)
		if err != nil {
			return nil, err
		}
		permissions[perm.Name] = perm
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}

	rows, err = p.db.QueryContext(ctx, roleQuery, user.GetAuthIdentifier())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		perm := &breitheamh.Permission{}
		err := rows.Scan(&perm.ID, &perm.Name, &perm.GuardName, &perm.GroupName)
		if err != nil {
			return nil, err
		}
		permissions[perm.Name] = perm
	}

	result := make([]*breitheamh.Permission, 0, len(permissions))
	for _, perm := range permissions {
		result = append(result, perm)
	}

	return result, rows.Err()
}

// AssignRole assigns a role to a user
func (p *SQLProvider) AssignRole(ctx context.Context, userID, roleID interface{}) error {
	query := fmt.Sprintf("INSERT INTO %s (user_id, role_id) VALUES (?, ?)", p.userRolesTable)
	_, err := p.db.ExecContext(ctx, query, userID, roleID)
	return err
}

// RemoveRole removes a role from a user
func (p *SQLProvider) RemoveRole(ctx context.Context, userID, roleID interface{}) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE user_id = ? AND role_id = ?", p.userRolesTable)
	_, err := p.db.ExecContext(ctx, query, userID, roleID)
	return err
}

// AssignPermission assigns a permission to a user
func (p *SQLProvider) AssignPermission(ctx context.Context, userID, permissionID interface{}) error {
	query := fmt.Sprintf("INSERT INTO %s (user_id, permission_id) VALUES (?, ?)", p.userPermissionsTable)
	_, err := p.db.ExecContext(ctx, query, userID, permissionID)
	return err
}

// RemovePermission removes a permission from a user
func (p *SQLProvider) RemovePermission(ctx context.Context, userID, permissionID interface{}) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE user_id = ? AND permission_id = ?", p.userPermissionsTable)
	_, err := p.db.ExecContext(ctx, query, userID, permissionID)
	return err
}

// FindByID implements the UserProvider interface
func (p *SQLProvider) FindByID(ctx context.Context, id string) (breitheamh.User, error) {
	return p.RetrieveByID(ctx, id)
}

// FindByCredentials implements the UserProvider interface
func (p *SQLProvider) FindByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
	return p.RetrieveByCredentials(ctx, credentials)
}

// UpdateUser implements the UserProvider interface
func (p *SQLProvider) UpdateUser(ctx context.Context, user breitheamh.User) error {
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return fmt.Errorf("user must be of type *BaseUser")
	}
	
	query := fmt.Sprintf(`
		UPDATE %s 
		SET email = ?, password = ?, remember_token = ?, updated_at = ?
		WHERE id = ?
	`, p.userTable)
	
	_, err := p.db.ExecContext(ctx, query,
		baseUser.Email,
		baseUser.Password,
		baseUser.RememberToken,
		baseUser.UpdatedAt,
		baseUser.ID,
	)
	return err
}

