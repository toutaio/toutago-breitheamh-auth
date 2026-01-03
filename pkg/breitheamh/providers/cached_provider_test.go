package providers

import (
	"context"
	"testing"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

type mockProvider struct {
	calls      int
	findByID   func(ctx context.Context, id string) (breitheamh.User, error)
	updateUser func(ctx context.Context, user breitheamh.User) error
}

func (m *mockProvider) FindByID(ctx context.Context, id string) (breitheamh.User, error) {
	m.calls++
	if m.findByID != nil {
		return m.findByID(ctx, id)
	}
	return &breitheamh.BaseUser{ID: id, Email: "test@example.com"}, nil
}

func (m *mockProvider) FindByCredentials(ctx context.Context, credentials map[string]interface{}) (breitheamh.User, error) {
	m.calls++
	return &breitheamh.BaseUser{Email: "test@example.com"}, nil
}

func (m *mockProvider) UpdateUser(ctx context.Context, user breitheamh.User) error {
	m.calls++
	if m.updateUser != nil {
		return m.updateUser(ctx, user)
	}
	return nil
}

func TestCachedProvider_FindByID(t *testing.T) {
	mock := &mockProvider{}
	cached := NewCachedProvider(CachedProviderConfig{
		Provider: mock,
		TTL:      100 * time.Millisecond,
	})
	defer cached.Stop()

	ctx := context.Background()

	// First call should hit the underlying provider
	user1, err := cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 1 {
		t.Errorf("expected 1 call, got %d", mock.calls)
	}

	// Second call should use cache
	user2, err := cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 1 {
		t.Errorf("expected 1 call (cached), got %d", mock.calls)
	}
	if user1.GetAuthIdentifier() != user2.GetAuthIdentifier() {
		t.Error("cached user should match original")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Third call should hit provider again
	_, err = cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 2 {
		t.Errorf("expected 2 calls (cache expired), got %d", mock.calls)
	}
}

func TestCachedProvider_Invalidate(t *testing.T) {
	mock := &mockProvider{}
	cached := NewCachedProvider(CachedProviderConfig{
		Provider: mock,
		TTL:      1 * time.Minute,
	})
	defer cached.Stop()

	ctx := context.Background()

	// Populate cache
	_, err := cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 1 {
		t.Errorf("expected 1 call, got %d", mock.calls)
	}

	// Invalidate cache
	cached.Invalidate("123")

	// Should hit provider again
	_, err = cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 2 {
		t.Errorf("expected 2 calls (cache invalidated), got %d", mock.calls)
	}
}

func TestCachedProvider_UpdateUser(t *testing.T) {
	mock := &mockProvider{}
	cached := NewCachedProvider(CachedProviderConfig{
		Provider: mock,
		TTL:      1 * time.Minute,
	})
	defer cached.Stop()

	ctx := context.Background()

	// Populate cache
	user, err := cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Update user should invalidate cache
	err = cached.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Next lookup should hit provider
	_, err = cached.FindByID(ctx, "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 3 {
		t.Errorf("expected 3 calls (FindByID, UpdateUser, FindByID), got %d", mock.calls)
	}
}

func TestCachedProvider_InvalidateAll(t *testing.T) {
	mock := &mockProvider{}
	cached := NewCachedProvider(CachedProviderConfig{
		Provider: mock,
		TTL:      1 * time.Minute,
	})
	defer cached.Stop()

	ctx := context.Background()

	// Populate cache with multiple users
	_, _ = cached.FindByID(ctx, "123")
	_, _ = cached.FindByID(ctx, "456")

	// Invalidate all
	cached.InvalidateAll()

	// Both should hit provider again
	_, _ = cached.FindByID(ctx, "123")
	_, _ = cached.FindByID(ctx, "456")

	if mock.calls != 4 {
		t.Errorf("expected 4 calls, got %d", mock.calls)
	}
}

func TestCachedProvider_Cleanup(t *testing.T) {
	mock := &mockProvider{}
	cached := NewCachedProvider(CachedProviderConfig{
		Provider:      mock,
		TTL:           50 * time.Millisecond,
		CleanupPeriod: 100 * time.Millisecond,
	})
	defer cached.Stop()

	ctx := context.Background()

	// Add some entries
	_, _ = cached.FindByID(ctx, "123")
	_, _ = cached.FindByID(ctx, "456")

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Cache should be empty after cleanup
	cached.mu.RLock()
	cacheSize := len(cached.userCache)
	cached.mu.RUnlock()

	if cacheSize != 0 {
		t.Errorf("expected empty cache after cleanup, got %d entries", cacheSize)
	}
}
