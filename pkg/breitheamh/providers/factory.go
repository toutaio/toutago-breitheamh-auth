package providers

import (
	"database/sql"
	"fmt"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// ProviderType represents the type of user provider
type ProviderType string

const (
	// ProviderTypeMemory represents an in-memory provider
	ProviderTypeMemory ProviderType = "memory"
	// ProviderTypeSQL represents a SQL database provider
	ProviderTypeSQL ProviderType = "sql"
	// ProviderTypeDataMapper represents a datamapper provider
	ProviderTypeDataMapper ProviderType = "datamapper"
)

// ProviderFactory creates user providers based on configuration
type ProviderFactory struct {
	providers map[string]breitheamh.UserProvider
}

// NewProviderFactory creates a new provider factory
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{
		providers: make(map[string]breitheamh.UserProvider),
	}
}

// Register registers a named provider
func (f *ProviderFactory) Register(name string, provider breitheamh.UserProvider) {
	f.providers[name] = provider
}

// Get retrieves a registered provider by name
func (f *ProviderFactory) Get(name string) (breitheamh.UserProvider, error) {
	provider, ok := f.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider '%s' not registered", name)
	}
	return provider, nil
}

// CreateMemoryProvider creates a new in-memory provider
func (f *ProviderFactory) CreateMemoryProvider() breitheamh.UserProvider {
	provider := NewMemoryProvider()
	f.Register("memory", provider)
	return provider
}

// CreateSQLProvider creates a new SQL provider
func (f *ProviderFactory) CreateSQLProvider(db *sql.DB, config *SQLConfig) breitheamh.UserProvider {
	provider := NewSQLProvider(db, config)
	name := "sql"
	if config != nil && config.UserTable != "" {
		name = config.UserTable
	}
	f.Register(name, provider)
	return provider
}

// CreateDataMapperProvider creates a new DataMapper provider
func (f *ProviderFactory) CreateDataMapperProvider(mapper DataMapper, config *DataMapperConfig) breitheamh.UserProvider {
	provider := NewDataMapperProvider(mapper, config)
	name := "datamapper"
	if config != nil && config.UserTable != "" {
		name = config.UserTable
	}
	f.Register(name, provider)
	return provider
}

// MemoryProvider is exported for external use
type MemoryProvider struct {
	users map[interface{}]breitheamh.Authenticatable
}

// NewMemoryProvider creates a new in-memory user provider
func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		users: make(map[interface{}]breitheamh.Authenticatable),
	}
}

// RetrieveByID retrieves a user by ID
func (p *MemoryProvider) RetrieveByID(ctx interface{}, id interface{}) (breitheamh.Authenticatable, error) {
	user, ok := p.users[id]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// RetrieveByCredentials retrieves a user by credentials
func (p *MemoryProvider) RetrieveByCredentials(ctx interface{}, credentials map[string]interface{}) (breitheamh.Authenticatable, error) {
	identifier, ok := credentials["email"]
	if !ok {
		identifier, ok = credentials["username"]
		if !ok {
			return nil, fmt.Errorf("credentials must contain 'email' or 'username'")
		}
	}

	for _, user := range p.users {
		baseUser, ok := user.(*breitheamh.BaseUser)
		if !ok {
			continue
		}
		if baseUser.Email == identifier || baseUser.Username == identifier {
			return user, nil
		}
	}

	return nil, fmt.Errorf("user not found")
}

// RetrieveByToken retrieves a user by remember token
func (p *MemoryProvider) RetrieveByToken(ctx interface{}, identifier, token string) (breitheamh.Authenticatable, error) {
	for _, user := range p.users {
		baseUser, ok := user.(*breitheamh.BaseUser)
		if !ok {
			continue
		}
		if fmt.Sprint(baseUser.ID) == identifier && baseUser.RememberToken == token {
			return user, nil
		}
	}

	return nil, fmt.Errorf("user not found")
}

// UpdateRememberToken updates the remember token
func (p *MemoryProvider) UpdateRememberToken(ctx interface{}, user breitheamh.Authenticatable, token string) error {
	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return fmt.Errorf("user must be of type *BaseUser")
	}
	baseUser.RememberToken = token
	return nil
}

// Add adds a user to the memory store
func (p *MemoryProvider) Add(user breitheamh.Authenticatable) {
	p.users[user.GetAuthIdentifier()] = user
}
