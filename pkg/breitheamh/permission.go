package breitheamh

// PermissionMatcher provides advanced permission matching with wildcard support.
type PermissionMatcher struct {
	// Future: Trie-based implementation for O(n) lookup
}

// NewPermissionMatcher creates a new permission matcher.
func NewPermissionMatcher() *PermissionMatcher {
	return &PermissionMatcher{}
}

// Match checks if a permission pattern matches the required permission.
// Supports the following patterns:
//   - Exact match: "posts.create" matches "posts.create"
//   - Suffix wildcard: "posts.*" matches "posts.create", "posts.edit", etc.
//   - Prefix wildcard: "*.create" matches "posts.create", "users.create", etc.
//   - Full wildcard: "*" matches everything
func (pm *PermissionMatcher) Match(pattern, permission string) bool {
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
		if pm.Match(pattern, permission) {
			return true
		}
	}
	return false
}
