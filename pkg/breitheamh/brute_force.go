package breitheamh

import (
	"sync"
	"time"
)

// BruteForceProtector manages account locking based on failed login attempts
type BruteForceProtector struct {
	maxAttempts    int
	lockDuration   time.Duration
	decayDuration  time.Duration
	attempts       map[string]*loginAttempts
	mu             sync.RWMutex
}

type loginAttempts struct {
	count      int
	firstAt    time.Time
	lockedUntil time.Time
}

// NewBruteForceProtector creates a new brute force protector
func NewBruteForceProtector(maxAttempts int, lockDuration, decayDuration time.Duration) *BruteForceProtector {
	return &BruteForceProtector{
		maxAttempts:   maxAttempts,
		lockDuration:  lockDuration,
		decayDuration: decayDuration,
		attempts:      make(map[string]*loginAttempts),
	}
}

// RecordFailedAttempt records a failed login attempt
func (p *BruteForceProtector) RecordFailedAttempt(identifier string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	now := time.Now()
	attempts, exists := p.attempts[identifier]
	
	if !exists {
		p.attempts[identifier] = &loginAttempts{
			count:   1,
			firstAt: now,
		}
		return
	}
	
	if now.Sub(attempts.firstAt) > p.decayDuration {
		attempts.count = 1
		attempts.firstAt = now
		attempts.lockedUntil = time.Time{}
		return
	}
	
	attempts.count++
	
	if attempts.count >= p.maxAttempts {
		attempts.lockedUntil = now.Add(p.lockDuration)
	}
}

// RecordSuccessfulAttempt clears failed attempts for an identifier
func (p *BruteForceProtector) RecordSuccessfulAttempt(identifier string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.attempts, identifier)
}

// IsLocked checks if an identifier is currently locked
func (p *BruteForceProtector) IsLocked(identifier string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	attempts, exists := p.attempts[identifier]
	if !exists {
		return false
	}
	
	if attempts.lockedUntil.IsZero() {
		return false
	}
	
	return time.Now().Before(attempts.lockedUntil)
}

// GetRemainingLockTime returns the remaining lock duration for an identifier
func (p *BruteForceProtector) GetRemainingLockTime(identifier string) time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	attempts, exists := p.attempts[identifier]
	if !exists || attempts.lockedUntil.IsZero() {
		return 0
	}
	
	remaining := time.Until(attempts.lockedUntil)
	if remaining < 0 {
		return 0
	}
	
	return remaining
}

// GetAttemptCount returns the number of failed attempts for an identifier
func (p *BruteForceProtector) GetAttemptCount(identifier string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	attempts, exists := p.attempts[identifier]
	if !exists {
		return 0
	}
	
	if time.Since(attempts.firstAt) > p.decayDuration {
		return 0
	}
	
	return attempts.count
}

// Reset removes all tracking for an identifier
func (p *BruteForceProtector) Reset(identifier string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.attempts, identifier)
}

// Cleanup removes expired entries
func (p *BruteForceProtector) Cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	now := time.Now()
	for key, attempts := range p.attempts {
		if !attempts.lockedUntil.IsZero() && now.After(attempts.lockedUntil) {
			if now.Sub(attempts.lockedUntil) > p.decayDuration {
				delete(p.attempts, key)
			}
		} else if now.Sub(attempts.firstAt) > p.decayDuration {
			delete(p.attempts, key)
		}
	}
}
