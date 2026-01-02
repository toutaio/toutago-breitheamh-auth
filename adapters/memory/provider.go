package memory

import (
	"context"
	"sync"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Provider is an in-memory implementation of UserProvider for testing.
type Provider struct {
	users map[string]*breitheamh.BaseUser
	mu    sync.RWMutex
}

// NewProvider creates a new in-memory user provider.
func NewProvider() *Provider {
	return &Provider{
		users: make(map[string]*breitheamh.BaseUser),
	}
}

// AddUser adds a user to the in-memory store.
func (p *Provider) AddUser(user *breitheamh.BaseUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[user.ID] = user
}

// FindByID retrieves a user by their unique identifier.
func (p *Provider) FindByID(ctx context.Context, id string) (breitheamh.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	user, exists := p.users[id]
	if !exists {
		return nil, breitheamh.ErrUserNotFound
	}

	return user, nil
}

// FindByCredentials retrieves a user by their credentials.
func (p *Provider) FindByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	email, ok := credentials["email"].(string)
	if !ok {
		return nil, breitheamh.ErrUserNotFound
	}

	for _, user := range p.users {
		if user.Email == email {
			return user, nil
		}
	}

	return nil, breitheamh.ErrUserNotFound
}

// UpdateUser updates a user in the in-memory store.
func (p *Provider) UpdateUser(ctx context.Context, user breitheamh.User) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	baseUser, ok := user.(*breitheamh.BaseUser)
	if !ok {
		return breitheamh.ErrUserNotFound
	}

	if _, exists := p.users[baseUser.ID]; !exists {
		return breitheamh.ErrUserNotFound
	}

	p.users[baseUser.ID] = baseUser
	return nil
}

// RemoveUser removes a user from the in-memory store.
func (p *Provider) RemoveUser(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.users, id)
}

// Clear removes all users from the in-memory store.
func (p *Provider) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = make(map[string]*breitheamh.BaseUser)
}

// Count returns the number of users in the store.
func (p *Provider) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.users)
}
