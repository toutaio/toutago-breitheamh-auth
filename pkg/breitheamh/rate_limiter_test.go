package breitheamh

import (
	"testing"
	"time"
)

func TestTokenBucketLimiter(t *testing.T) {
	limiter := NewTokenBucketLimiter(5, 10, time.Minute)
	
	t.Run("allows initial burst", func(t *testing.T) {
		key := "test-user-1"
		for i := 0; i < 10; i++ {
			if !limiter.Allow(key) {
				t.Errorf("request %d should be allowed", i)
			}
		}
	})
	
	t.Run("blocks after burst exhausted", func(t *testing.T) {
		key := "test-user-2"
		for i := 0; i < 10; i++ {
			limiter.Allow(key)
		}
		
		if limiter.Allow(key) {
			t.Error("request should be blocked after burst exhausted")
		}
	})
	
	t.Run("refills tokens over time", func(t *testing.T) {
		key := "test-user-3"
		for i := 0; i < 10; i++ {
			limiter.Allow(key)
		}
		
		time.Sleep(300 * time.Millisecond)
		
		if !limiter.Allow(key) {
			t.Error("request should be allowed after token refill")
		}
	})
	
	t.Run("reset removes limit", func(t *testing.T) {
		key := "test-user-4"
		for i := 0; i < 10; i++ {
			limiter.Allow(key)
		}
		
		limiter.Reset(key)
		
		if !limiter.Allow(key) {
			t.Error("request should be allowed after reset")
		}
	})
}

func TestSlidingWindowLimiter(t *testing.T) {
	limiter := NewSlidingWindowLimiter(5, time.Second)
	
	t.Run("allows requests within limit", func(t *testing.T) {
		key := "test-user-1"
		for i := 0; i < 5; i++ {
			if !limiter.Allow(key) {
				t.Errorf("request %d should be allowed", i)
			}
		}
	})
	
	t.Run("blocks after limit reached", func(t *testing.T) {
		key := "test-user-2"
		for i := 0; i < 5; i++ {
			limiter.Allow(key)
		}
		
		if limiter.Allow(key) {
			t.Error("request should be blocked after limit reached")
		}
	})
	
	t.Run("allows requests after window expires", func(t *testing.T) {
		key := "test-user-3"
		for i := 0; i < 5; i++ {
			limiter.Allow(key)
		}
		
		time.Sleep(1100 * time.Millisecond)
		
		if !limiter.Allow(key) {
			t.Error("request should be allowed after window expires")
		}
	})
	
	t.Run("reset removes limit", func(t *testing.T) {
		key := "test-user-4"
		for i := 0; i < 5; i++ {
			limiter.Allow(key)
		}
		
		limiter.Reset(key)
		
		if !limiter.Allow(key) {
			t.Error("request should be allowed after reset")
		}
	})
}

func BenchmarkTokenBucketLimiter(b *testing.B) {
	limiter := NewTokenBucketLimiter(1000, 2000, time.Minute)
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := string(rune('a' + (i % 26)))
			limiter.Allow(key)
			i++
		}
	})
}

func BenchmarkSlidingWindowLimiter(b *testing.B) {
	limiter := NewSlidingWindowLimiter(1000, time.Minute)
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := string(rune('a' + (i % 26)))
			limiter.Allow(key)
			i++
		}
	})
}
