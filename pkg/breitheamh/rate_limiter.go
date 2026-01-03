package breitheamh

import (
	"sync"
	"time"
)

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow(key string) bool
	Reset(key string)
}

// TokenBucketLimiter implements a token bucket rate limiter
type TokenBucketLimiter struct {
	rate       int
	burst      int
	buckets    map[string]*bucket
	mu         sync.RWMutex
	cleanupTTL time.Duration
}

type bucket struct {
	tokens     int
	lastUpdate time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(rate, burst int, cleanupTTL time.Duration) *TokenBucketLimiter {
	limiter := &TokenBucketLimiter{
		rate:       rate,
		burst:      burst,
		buckets:    make(map[string]*bucket),
		cleanupTTL: cleanupTTL,
	}

	go limiter.cleanup()

	return limiter
}

// Allow checks if the request is allowed for the given key
func (l *TokenBucketLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, exists := l.buckets[key]
	if !exists {
		b = &bucket{
			tokens:     l.burst - 1,
			lastUpdate: time.Now(),
		}
		l.buckets[key] = b
		return true
	}

	now := time.Now()
	elapsed := now.Sub(b.lastUpdate)

	tokensToAdd := int(elapsed.Seconds() * float64(l.rate))
	b.tokens += tokensToAdd

	if b.tokens > l.burst {
		b.tokens = l.burst
	}

	b.lastUpdate = now

	if b.tokens > 0 {
		b.tokens--
		return true
	}

	return false
}

// Reset removes rate limit for a key
func (l *TokenBucketLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

func (l *TokenBucketLimiter) cleanup() {
	ticker := time.NewTicker(l.cleanupTTL)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for key, b := range l.buckets {
			if now.Sub(b.lastUpdate) > l.cleanupTTL {
				delete(l.buckets, key)
			}
		}
		l.mu.Unlock()
	}
}

// SlidingWindowLimiter implements a sliding window rate limiter
type SlidingWindowLimiter struct {
	maxRequests int
	window      time.Duration
	requests    map[string][]time.Time
	mu          sync.RWMutex
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter
func NewSlidingWindowLimiter(maxRequests int, window time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		maxRequests: maxRequests,
		window:      window,
		requests:    make(map[string][]time.Time),
	}
}

// Allow checks if the request is allowed for the given key
func (l *SlidingWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-l.window)

	timestamps, exists := l.requests[key]
	if !exists {
		l.requests[key] = []time.Time{now}
		return true
	}

	var validTimestamps []time.Time
	for _, ts := range timestamps {
		if ts.After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	if len(validTimestamps) < l.maxRequests {
		l.requests[key] = append(validTimestamps, now)
		return true
	}

	l.requests[key] = validTimestamps
	return false
}

// Reset removes rate limit for a key
func (l *SlidingWindowLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.requests, key)
}
