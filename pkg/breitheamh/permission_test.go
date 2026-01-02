package breitheamh

import "testing"

func TestPermissionMatcher(t *testing.T) {
	matcher := NewPermissionMatcher()

	tests := []struct {
		name       string
		pattern    string
		permission string
		expected   bool
	}{
		{"exact match", "posts.create", "posts.create", true},
		{"exact mismatch", "posts.create", "posts.edit", false},
		{"suffix wildcard match", "posts.*", "posts.create", true},
		{"suffix wildcard match 2", "posts.*", "posts.edit", true},
		{"suffix wildcard mismatch", "posts.*", "users.create", false},
		{"prefix wildcard match", "*.create", "posts.create", true},
		{"prefix wildcard match 2", "*.create", "users.create", true},
		{"prefix wildcard mismatch", "*.create", "posts.edit", false},
		{"full wildcard", "*", "anything.goes.here", true},
		{"no match", "posts.edit", "users.create", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.Match(tt.pattern, tt.permission)
			if result != tt.expected {
				t.Errorf("Match(%q, %q) = %v, expected %v",
					tt.pattern, tt.permission, result, tt.expected)
			}
		})
	}
}

func TestPermissionMatcherMatchAny(t *testing.T) {
	matcher := NewPermissionMatcher()

	patterns := []string{"posts.create", "users.*", "*.delete"}

	tests := []struct {
		permission string
		expected   bool
	}{
		{"posts.create", true},
		{"users.create", true},
		{"users.edit", true},
		{"posts.delete", true},
		{"comments.delete", true},
		{"posts.edit", false},
		{"comments.edit", false},
	}

	for _, tt := range tests {
		t.Run(tt.permission, func(t *testing.T) {
			result := matcher.MatchAny(patterns, tt.permission)
			if result != tt.expected {
				t.Errorf("MatchAny(%v, %q) = %v, expected %v",
					patterns, tt.permission, result, tt.expected)
			}
		})
	}
}
