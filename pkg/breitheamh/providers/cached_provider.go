package providers

import (
	"context"
	"sync"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// CachedProvider wraps a UserProvider with caching capabilities
type CachedProvider struct {
	provider    breitheamh.UserProvider
	userCache   map[string]*cacheEntry
	mu          sync.RWMutex
	ttl         time.Duration
	cleanupStop chan struct{}
}

type cacheEntry struct {
	user      breitheamh.User
	expiresAt time.Time
}

// CachedProviderConfig holds configuration for cached provider
type CachedProviderConfig struct {
	Provider      breitheamh.UserProvider
	TTL           time.Duration
	CleanupPeriod time.Duration
}

// NewCachedProvider creates a new cached user provider
func NewCachedProvider(config CachedProviderConfig) *CachedProvider {
	if config.TTL == 0 {
		config.TTL = 15 * time.Minute
	}
	if config.CleanupPeriod == 0 {
		config.CleanupPeriod = 5 * time.Minute
	}

	cp := &CachedProvider{
		provider:    config.Provider,
		userCache:   make(map[string]*cacheEntry),
		ttl:         config.TTL,
		cleanupStop: make(chan struct{}),
	}

	go cp.cleanupLoop(config.CleanupPeriod)

	return cp
}

// FindByID retrieves a user by ID with caching
func (cp *CachedProvider) FindByID(ctx context.Context, id string) (breitheamh.User, error) {
	cp.mu.RLock()
	if entry, exists := cp.userCache[id]; exists && time.Now().Before(entry.expiresAt) {
		cp.mu.RUnlock()
		return entry.user, nil
	}
	cp.mu.RUnlock()

	user, err := cp.provider.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	cp.mu.Lock()
	cp.userCache[id] = &cacheEntry{
		user:      user,
		expiresAt: time.Now().Add(cp.ttl),
	}
	cp.mu.Unlock()

	return user, nil
}

// FindByCredentials retrieves a user by credentials (not cached for security)
func (cp *CachedProvider) FindByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
	return cp.provider.FindByCredentials(ctx, credentials)
}

// UpdateUser updates a user and invalidates cache
func (cp *CachedProvider) UpdateUser(ctx context.Context, user breitheamh.User) error {
	err := cp.provider.UpdateUser(ctx, user)
	if err != nil {
		return err
	}

	// Invalidate by ID if available
	if baseUser, ok := user.(*breitheamh.BaseUser); ok {
		cp.mu.Lock()
		delete(cp.userCache, baseUser.ID)
		cp.mu.Unlock()
	}

	return nil
}

// Invalidate removes a user from cache
func (cp *CachedProvider) Invalidate(userID string) {
	cp.mu.Lock()
	delete(cp.userCache, userID)
	cp.mu.Unlock()
}

// InvalidateAll clears the entire cache
func (cp *CachedProvider) InvalidateAll() {
	cp.mu.Lock()
	cp.userCache = make(map[string]*cacheEntry)
	cp.mu.Unlock()
}

// Stop stops the cleanup goroutine
func (cp *CachedProvider) Stop() {
	close(cp.cleanupStop)
}

func (cp *CachedProvider) cleanupLoop(period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cp.cleanup()
		case <-cp.cleanupStop:
			return
		}
	}
}

func (cp *CachedProvider) cleanup() {
	now := time.Now()
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for id, entry := range cp.userCache {
		if now.After(entry.expiresAt) {
			delete(cp.userCache, id)
		}
	}
}
