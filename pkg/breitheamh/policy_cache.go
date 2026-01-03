package breitheamh

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// PolicyCacheKey represents a unique key for caching policy decisions.
type PolicyCacheKey struct {
UserID       string
Ability      string
ResourceType string
ResourceID   string
}

// PolicyCacheEntry represents a cached policy decision with expiry.
type PolicyCacheEntry struct {
Result    bool
ExpiresAt time.Time
}

// PolicyCache provides caching for policy authorization decisions.
type PolicyCache struct {
cache map[PolicyCacheKey]*PolicyCacheEntry
mu    sync.RWMutex
ttl   time.Duration
}

// NewPolicyCache creates a new policy cache with the specified TTL.
func NewPolicyCache(ttl time.Duration) *PolicyCache {
return &PolicyCache{
cache: make(map[PolicyCacheKey]*PolicyCacheEntry),
ttl:   ttl,
}
}

// Get retrieves a cached policy decision if it exists and hasn't expired.
func (pc *PolicyCache) Get(key PolicyCacheKey) (bool, bool) {
pc.mu.RLock()
defer pc.mu.RUnlock()

entry, exists := pc.cache[key]
if !exists {
return false, false
}

// Check if expired
if time.Now().After(entry.ExpiresAt) {
return false, false
}

return entry.Result, true
}

// Set stores a policy decision in the cache with TTL.
func (pc *PolicyCache) Set(key PolicyCacheKey, result bool) {
pc.mu.Lock()
defer pc.mu.Unlock()

pc.cache[key] = &PolicyCacheEntry{
Result:    result,
ExpiresAt: time.Now().Add(pc.ttl),
}
}

// Invalidate removes a specific cache entry.
func (pc *PolicyCache) Invalidate(key PolicyCacheKey) {
pc.mu.Lock()
defer pc.mu.Unlock()

delete(pc.cache, key)
}

// InvalidateForUser removes all cache entries for a specific user.
func (pc *PolicyCache) InvalidateForUser(userID string) {
pc.mu.Lock()
defer pc.mu.Unlock()

for key := range pc.cache {
if key.UserID == userID {
delete(pc.cache, key)
}
}
}

// InvalidateForResource removes all cache entries for a specific resource.
func (pc *PolicyCache) InvalidateForResource(resourceType, resourceID string) {
pc.mu.Lock()
defer pc.mu.Unlock()

for key := range pc.cache {
if key.ResourceType == resourceType && key.ResourceID == resourceID {
delete(pc.cache, key)
}
}
}

// Clear removes all entries from the cache.
func (pc *PolicyCache) Clear() {
pc.mu.Lock()
defer pc.mu.Unlock()

pc.cache = make(map[PolicyCacheKey]*PolicyCacheEntry)
}

// CleanExpired removes expired entries from the cache.
func (pc *PolicyCache) CleanExpired() {
pc.mu.Lock()
defer pc.mu.Unlock()

now := time.Now()
for key, entry := range pc.cache {
if now.After(entry.ExpiresAt) {
delete(pc.cache, key)
}
}
}

// Size returns the number of entries in the cache.
func (pc *PolicyCache) Size() int {
pc.mu.RLock()
defer pc.mu.RUnlock()

return len(pc.cache)
}

// StartCleanupRoutine starts a background goroutine that periodically cleans expired entries.
func (pc *PolicyCache) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
ticker := time.NewTicker(interval)
go func() {
for {
select {
case <-ticker.C:
pc.CleanExpired()
case <-ctx.Done():
ticker.Stop()
return
}
}
}()
}

// MakeCacheKey creates a cache key from user, ability, and resource.
func MakeCacheKey(userID, ability, resourceType, resourceID string) PolicyCacheKey {
return PolicyCacheKey{
UserID:       userID,
Ability:      ability,
ResourceType: resourceType,
ResourceID:   resourceID,
}
}

// getResourceID attempts to extract an ID from a resource using reflection.
func getResourceID(resource interface{}) string {
	if resource == nil {
		return ""
	}

	v := reflect.ValueOf(resource)
	
	// Handle pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	// Try to get ID field
	if v.Kind() == reflect.Struct {
		// Try common ID field names
		idFields := []string{"ID", "Id", "id"}
		for _, fieldName := range idFields {
			field := v.FieldByName(fieldName)
			if field.IsValid() && field.CanInterface() {
				return fmt.Sprintf("%v", field.Interface())
			}
		}
	}

	// Fallback to string representation of the whole resource
	return fmt.Sprintf("%v", resource)
}
