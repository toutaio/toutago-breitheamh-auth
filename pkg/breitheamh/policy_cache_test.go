package breitheamh

import (
	"context"
	"testing"
	"time"
)

func TestPolicyCache(t *testing.T) {
	cache := NewPolicyCache(100 * time.Millisecond)

	key := MakeCacheKey("user-1", "view", "Post", "post-1")

	t.Run("Set and Get", func(t *testing.T) {
		cache.Set(key, true)

		result, exists := cache.Get(key)
		if !exists {
			t.Error("Cache entry should exist")
		}
		if !result {
			t.Error("Cached result should be true")
		}
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		nonExistentKey := MakeCacheKey("user-2", "edit", "Post", "post-2")
		_, exists := cache.Get(nonExistentKey)
		if exists {
			t.Error("Non-existent key should not exist")
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		shortCache := NewPolicyCache(50 * time.Millisecond)
		shortKey := MakeCacheKey("user-3", "delete", "Post", "post-3")

		shortCache.Set(shortKey, true)

		// Should exist immediately
		_, exists := shortCache.Get(shortKey)
		if !exists {
			t.Error("Cache entry should exist before expiry")
		}

		// Wait for expiry
		time.Sleep(60 * time.Millisecond)

		// Should not exist after expiry
		_, exists = shortCache.Get(shortKey)
		if exists {
			t.Error("Cache entry should not exist after expiry")
		}
	})
}

func TestPolicyCacheInvalidation(t *testing.T) {
	cache := NewPolicyCache(1 * time.Minute)

	key1 := MakeCacheKey("user-1", "view", "Post", "post-1")
	key2 := MakeCacheKey("user-1", "edit", "Post", "post-2")
	key3 := MakeCacheKey("user-2", "view", "Post", "post-1")

	cache.Set(key1, true)
	cache.Set(key2, true)
	cache.Set(key3, true)

	t.Run("Invalidate specific key", func(t *testing.T) {
		cache.Invalidate(key1)

		_, exists := cache.Get(key1)
		if exists {
			t.Error("Invalidated key should not exist")
		}

		// Other keys should still exist
		_, exists = cache.Get(key2)
		if !exists {
			t.Error("Other keys should still exist")
		}
	})

	t.Run("Invalidate for user", func(t *testing.T) {
		cache.InvalidateForUser("user-1")

		_, exists := cache.Get(key2)
		if exists {
			t.Error("User-1 entries should be invalidated")
		}

		// User-2 entry should still exist
		_, exists = cache.Get(key3)
		if !exists {
			t.Error("User-2 entry should still exist")
		}
	})
}

func TestPolicyCacheInvalidateForResource(t *testing.T) {
	cache := NewPolicyCache(1 * time.Minute)

	key1 := MakeCacheKey("user-1", "view", "Post", "post-1")
	key2 := MakeCacheKey("user-2", "view", "Post", "post-1")
	key3 := MakeCacheKey("user-1", "view", "Post", "post-2")

	cache.Set(key1, true)
	cache.Set(key2, true)
	cache.Set(key3, true)

	cache.InvalidateForResource("Post", "post-1")

	_, exists := cache.Get(key1)
	if exists {
		t.Error("post-1 entries should be invalidated")
	}

	_, exists = cache.Get(key2)
	if exists {
		t.Error("post-1 entries should be invalidated")
	}

	_, exists = cache.Get(key3)
	if !exists {
		t.Error("post-2 entry should still exist")
	}
}

func TestPolicyCacheClear(t *testing.T) {
	cache := NewPolicyCache(1 * time.Minute)

	cache.Set(MakeCacheKey("user-1", "view", "Post", "post-1"), true)
	cache.Set(MakeCacheKey("user-2", "view", "Post", "post-2"), true)

	if cache.Size() != 2 {
		t.Errorf("Cache should have 2 entries, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Cache should be empty after clear, got %d entries", cache.Size())
	}
}

func TestPolicyCacheCleanExpired(t *testing.T) {
	cache := NewPolicyCache(50 * time.Millisecond)

	key1 := MakeCacheKey("user-1", "view", "Post", "post-1")
	key2 := MakeCacheKey("user-2", "view", "Post", "post-2")

	cache.Set(key1, true)
	time.Sleep(60 * time.Millisecond) // Wait for key1 to expire
	cache.Set(key2, true)              // key2 is fresh

	// Before cleanup, size includes expired entries
	sizeBefore := cache.Size()
	if sizeBefore != 2 {
		t.Errorf("Expected 2 entries before cleanup, got %d", sizeBefore)
	}

	cache.CleanExpired()

	// After cleanup, only fresh entry remains
	sizeAfter := cache.Size()
	if sizeAfter != 1 {
		t.Errorf("Expected 1 entry after cleanup, got %d", sizeAfter)
	}

	// key1 should be gone
	_, exists := cache.Get(key1)
	if exists {
		t.Error("Expired entry should be removed")
	}

	// key2 should still exist
	_, exists = cache.Get(key2)
	if !exists {
		t.Error("Fresh entry should still exist")
	}
}

func TestPolicyCacheCleanupRoutine(t *testing.T) {
	cache := NewPolicyCache(30 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup routine with short interval
	cache.StartCleanupRoutine(ctx, 50*time.Millisecond)

	key := MakeCacheKey("user-1", "view", "Post", "post-1")
	cache.Set(key, true)

	// Wait for entry to expire and cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Entry should be cleaned up automatically
	if cache.Size() != 0 {
		t.Errorf("Expected cache to be cleaned automatically, got %d entries", cache.Size())
	}

	// Cancel context to stop cleanup routine
	cancel()
}

func TestMakeCacheKey(t *testing.T) {
	key := MakeCacheKey("user-1", "view", "Post", "post-1")

	if key.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", key.UserID, "user-1")
	}
	if key.Ability != "view" {
		t.Errorf("Ability = %q, want %q", key.Ability, "view")
	}
	if key.ResourceType != "Post" {
		t.Errorf("ResourceType = %q, want %q", key.ResourceType, "Post")
	}
	if key.ResourceID != "post-1" {
		t.Errorf("ResourceID = %q, want %q", key.ResourceID, "post-1")
	}
}

// Benchmark tests
func BenchmarkPolicyCacheSet(b *testing.B) {
	cache := NewPolicyCache(1 * time.Minute)
	key := MakeCacheKey("user-1", "view", "Post", "post-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(key, true)
	}
}

func BenchmarkPolicyCacheGet(b *testing.B) {
	cache := NewPolicyCache(1 * time.Minute)
	key := MakeCacheKey("user-1", "view", "Post", "post-1")
	cache.Set(key, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(key)
	}
}

func BenchmarkPolicyCacheConcurrent(b *testing.B) {
	cache := NewPolicyCache(1 * time.Minute)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := MakeCacheKey("user-1", "view", "Post", "post-1")
			if i%2 == 0 {
				cache.Set(key, true)
			} else {
				cache.Get(key)
			}
			i++
		}
	})
}
