package breitheamh

// PermissionMatcher provides advanced permission matching with wildcard support.
// Uses a trie-based implementation for O(n) lookup where n is the depth of the permission.
type PermissionMatcher struct {
	trie *PermissionTrie
}

// NewPermissionMatcher creates a new permission matcher.
func NewPermissionMatcher() *PermissionMatcher {
	return &PermissionMatcher{
		trie: NewPermissionTrie(),
	}
}

// AddPattern adds a permission pattern to the matcher.
func (pm *PermissionMatcher) AddPattern(pattern string) {
	pm.trie.Insert(pattern)
}

// AddPatterns adds multiple permission patterns to the matcher.
func (pm *PermissionMatcher) AddPatterns(patterns []string) {
	for _, pattern := range patterns {
		pm.trie.Insert(pattern)
	}
}

// RemovePattern removes a permission pattern from the matcher.
func (pm *PermissionMatcher) RemovePattern(pattern string) bool {
	return pm.trie.Remove(pattern)
}

// Clear removes all patterns from the matcher.
func (pm *PermissionMatcher) Clear() {
	pm.trie.Clear()
}

// Match checks if a permission matches any pattern in the matcher using the trie.
// If no patterns have been added, falls back to simple wildcard matching.
func (pm *PermissionMatcher) Match(pattern, permission string) bool {
	// If using the trie (when patterns are added)
	if pm.trie.Size() > 0 {
		return pm.trie.Match(permission)
	}

	// Fallback to simple matching for single-pattern checks
	return matchesPermissionSimple(pattern, permission)
}

// matchesPermissionSimple provides simple wildcard matching without trie.
// This is used when checking a single pattern directly.
func matchesPermissionSimple(pattern, permission string) bool {
	if pattern == "*" {
		return true
	}

	if pattern == permission {
		return true
	}

	// Check suffix wildcard (e.g., "posts.*")
	if len(pattern) > 2 && pattern[len(pattern)-2:] == ".*" {
		prefix := pattern[:len(pattern)-2]
		if len(permission) > len(prefix)+1 && permission[:len(prefix)] == prefix && permission[len(prefix)] == '.' {
			return true
		}
	}

	// Check prefix wildcard (e.g., "*.create")
	if len(pattern) > 2 && pattern[:2] == "*." {
		suffix := pattern[2:]
		if len(permission) > len(suffix)+1 && permission[len(permission)-len(suffix):] == suffix {
			// Check that there's a dot before the suffix
			if permission[len(permission)-len(suffix)-1] == '.' {
				return true
			}
		}
	}

	return false
}

// MatchAny checks if any of the patterns match the required permission.
func (pm *PermissionMatcher) MatchAny(patterns []string, permission string) bool {
	for _, pattern := range patterns {
		if matchesPermissionSimple(pattern, permission) {
			return true
		}
	}
	return false
}
