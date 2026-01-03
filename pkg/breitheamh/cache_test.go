package breitheamh

import (
	"fmt"
	"testing"
	"time"
)

func TestPermissionCache(t *testing.T) {
	cache := NewPermissionCache(100 * time.Millisecond)

	t.Run("set and get", func(t *testing.T) {
		cache.Set("user:1:permissions", []string{"read", "write"})

		value, exists := cache.Get("user:1:permissions")
		if !exists {
			t.Fatal("expected value to exist")
		}

		perms, ok := value.([]string)
		if !ok {
			t.Fatal("expected value to be []string")
		}

		if len(perms) != 2 || perms[0] != "read" || perms[1] != "write" {
			t.Errorf("unexpected permissions: %v", perms)
		}
	})

	t.Run("get non-existent key", func(t *testing.T) {
		_, exists := cache.Get("nonexistent")
		if exists {
			t.Error("expected key to not exist")
		}
	})

	t.Run("expiration", func(t *testing.T) {
		cache.Set("temp:key", "value")

		value, exists := cache.Get("temp:key")
		if !exists {
			t.Fatal("expected value to exist immediately")
		}
		if value != "value" {
			t.Errorf("expected 'value', got %v", value)
		}

		time.Sleep(150 * time.Millisecond)

		_, exists = cache.Get("temp:key")
		if exists {
			t.Error("expected value to have expired")
		}
	})

	t.Run("delete", func(t *testing.T) {
		cache.Set("delete:me", "data")
		cache.Delete("delete:me")

		_, exists := cache.Get("delete:me")
		if exists {
			t.Error("expected key to be deleted")
		}
	})

	t.Run("clear", func(t *testing.T) {
		cache.Set("key1", "value1")
		cache.Set("key2", "value2")
		cache.Clear()

		_, exists1 := cache.Get("key1")
		_, exists2 := cache.Get("key2")

		if exists1 || exists2 {
			t.Error("expected all keys to be cleared")
		}
	})
}

func TestRoleCache(t *testing.T) {
	cache := NewRoleCache(100 * time.Millisecond)

	t.Run("set and get", func(t *testing.T) {
		cache.Set("user:1:roles", []string{"admin", "editor"})

		value, exists := cache.Get("user:1:roles")
		if !exists {
			t.Fatal("expected value to exist")
		}

		roles, ok := value.([]string)
		if !ok {
			t.Fatal("expected value to be []string")
		}

		if len(roles) != 2 || roles[0] != "admin" || roles[1] != "editor" {
			t.Errorf("unexpected roles: %v", roles)
		}
	})

	t.Run("expiration", func(t *testing.T) {
		cache.Set("temp:key", "value")

		time.Sleep(150 * time.Millisecond)

		_, exists := cache.Get("temp:key")
		if exists {
			t.Error("expected value to have expired")
		}
	})
}

func BenchmarkPermissionCache(b *testing.B) {
	cache := NewPermissionCache(5 * time.Minute)

	b.Run("Set", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.Set(fmt.Sprintf("user:%d:permissions", i), []string{"read", "write"})
		}
	})

	b.Run("Get", func(b *testing.B) {
		cache.Set("benchmark:key", []string{"read", "write"})
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			cache.Get("benchmark:key")
		}
	})

	b.Run("SetParallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cache.Set(fmt.Sprintf("user:%d:permissions", i), []string{"read", "write"})
				i++
			}
		})
	})

	b.Run("GetParallel", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			cache.Set(fmt.Sprintf("user:%d:permissions", i), []string{"read", "write"})
		}
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cache.Get(fmt.Sprintf("user:%d:permissions", i%1000))
				i++
			}
		})
	})
}
