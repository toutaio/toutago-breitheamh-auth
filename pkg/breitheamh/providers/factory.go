package providers

import (
	"fmt"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// ProviderType represents the type of user provider
type ProviderType string

const (
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

// CreateSQLProvider creates a new SQL provider
func (f *ProviderFactory) CreateSQLProvider(config SQLProviderConfig) breitheamh.UserProvider {
	provider := NewSQLProvider(config)
	name := "sql"
	if config.UserTable != "" {
		name = config.UserTable
	}
	f.Register(name, provider)
	return provider
}

// CreateDataMapperProvider creates a new DataMapper provider
func (f *ProviderFactory) CreateDataMapperProvider(
	mapper DataMapper,
	config *DataMapperConfig,
) breitheamh.UserProvider {
	provider := NewDataMapperProvider(mapper, config)
	name := "datamapper"
	if config != nil && config.UserTable != "" {
		name = config.UserTable
	}
	f.Register(name, provider)
	return provider
}
