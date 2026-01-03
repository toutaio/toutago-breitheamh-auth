package breitheamh

import "testing"

func TestPermissionTrie_Insert(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("posts.create")
	trie.Insert("posts.edit")
	trie.Insert("posts.*")
	trie.Insert("admin.*")

	if trie.Size() != 4 {
		t.Errorf("Expected size 4, got %d", trie.Size())
	}
}

func TestPermissionTrie_Match(t *testing.T) {
	trie := NewPermissionTrie()

	// Test exact match
	trie.Insert("posts.create")
	if !trie.Match("posts.create") {
		t.Error("Should match exact permission")
	}
	if trie.Match("posts.edit") {
		t.Error("Should not match non-existent permission")
	}

	// Test wildcard match
	trie.Insert("users.*")
	if !trie.Match("users.create") {
		t.Error("Should match users.create with users.* pattern")
	}
	if !trie.Match("users.delete") {
		t.Error("Should match users.delete with users.* pattern")
	}
	if !trie.Match("users.edit") {
		t.Error("Should match users.edit with users.* pattern")
	}
	if trie.Match("posts.delete") {
		t.Error("Should not match posts.delete")
	}

	// Test multi-level wildcard
	trie.Insert("admin.*.*")
	if !trie.Match("admin.users.create") {
		t.Error("Should match admin.users.create with admin.*.* pattern")
	}
	if !trie.Match("admin.posts.delete") {
		t.Error("Should match admin.posts.delete with admin.*.* pattern")
	}
	if trie.Match("admin.settings") {
		t.Error("Should not match admin.settings (only 2 levels)")
	}
}

func TestPermissionTrie_WildcardPriority(t *testing.T) {
	trie := NewPermissionTrie()

	// Insert both wildcard and exact patterns
	trie.Insert("posts.*")
	trie.Insert("posts.create")

	// Both should match
	if !trie.Match("posts.create") {
		t.Error("Should match posts.create")
	}
	if !trie.Match("posts.edit") {
		t.Error("Should match posts.edit via wildcard")
	}
}

func TestPermissionTrie_Contains(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("posts.create")
	trie.Insert("posts.*")

	if !trie.Contains("posts.create") {
		t.Error("Should contain posts.create")
	}
	if !trie.Contains("posts.*") {
		t.Error("Should contain posts.*")
	}
	if trie.Contains("posts.edit") {
		t.Error("Should not contain posts.edit as exact pattern")
	}
}

func TestPermissionTrie_Remove(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("posts.create")
	trie.Insert("posts.edit")

	// Remove exact permission
	if !trie.Remove("posts.create") {
		t.Error("Should successfully remove posts.create")
	}
	if trie.Match("posts.create") {
		t.Error("Should not match posts.create after removal")
	}

	// posts.edit should still work
	if !trie.Match("posts.edit") {
		t.Error("posts.edit should still match")
	}

	// Test with wildcard
	trie.Insert("users.*")
	if !trie.Match("users.create") {
		t.Error("Should match via wildcard")
	}

	// Remove wildcard
	if !trie.Remove("users.*") {
		t.Error("Should successfully remove users.*")
	}
	if trie.Match("users.create") {
		t.Error("Should not match after wildcard removed")
	}

	// Remove non-existent pattern
	if trie.Remove("nonexistent.permission") {
		t.Error("Should not remove non-existent permission")
	}
}

func TestPermissionTrie_Clear(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("posts.create")
	trie.Insert("users.*")
	trie.Insert("admin.*.*")

	trie.Clear()

	if trie.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", trie.Size())
	}
	if trie.Match("posts.create") {
		t.Error("Should not match any permission after clear")
	}
}

func TestPermissionTrie_GetAllPatterns(t *testing.T) {
	trie := NewPermissionTrie()

	patterns := []string{
		"posts.create",
		"posts.edit",
		"users.*",
		"admin.*.*",
	}

	for _, p := range patterns {
		trie.Insert(p)
	}

	allPatterns := trie.GetAllPatterns()
	if len(allPatterns) != len(patterns) {
		t.Errorf("Expected %d patterns, got %d", len(patterns), len(allPatterns))
	}

	// Check all patterns are present
	patternMap := make(map[string]bool)
	for _, p := range allPatterns {
		patternMap[p] = true
	}

	for _, p := range patterns {
		if !patternMap[p] {
			t.Errorf("Missing pattern: %s", p)
		}
	}
}

func TestPermissionTrie_ComplexWildcards(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("*.create")
	if !trie.Match("posts.create") {
		t.Error("Should match posts.create with *.create pattern")
	}
	if !trie.Match("users.create") {
		t.Error("Should match users.create with *.create pattern")
	}
	if trie.Match("posts.edit") {
		t.Error("Should not match posts.edit")
	}

	trie.Insert("*.*")
	if !trie.Match("posts.anything") {
		t.Error("Should match any two-part permission")
	}
	if !trie.Match("users.whatever") {
		t.Error("Should match any two-part permission")
	}
}

func TestPermissionTrie_EmptyPermission(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("")
	if !trie.Match("") {
		t.Error("Should match empty permission")
	}
	if trie.Match("posts.create") {
		t.Error("Should not match non-empty permission")
	}
}

func TestPermissionTrie_SinglePartPermission(t *testing.T) {
	trie := NewPermissionTrie()

	trie.Insert("superadmin")
	if !trie.Match("superadmin") {
		t.Error("Should match single-part permission")
	}
	if trie.Match("admin") {
		t.Error("Should not match different single-part permission")
	}

	trie.Insert("*")
	if !trie.Match("anything") {
		t.Error("Should match any single-part permission with * wildcard")
	}
}

// Benchmark tests
func BenchmarkPermissionTrie_Insert(b *testing.B) {
	trie := NewPermissionTrie()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.Insert("posts.create")
	}
}

func BenchmarkPermissionTrie_Match(b *testing.B) {
	trie := NewPermissionTrie()
	trie.Insert("posts.create")
	trie.Insert("posts.*")
	trie.Insert("admin.*.*")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.Match("posts.create")
	}
}

func BenchmarkPermissionTrie_MatchWildcard(b *testing.B) {
	trie := NewPermissionTrie()
	trie.Insert("posts.*")
	trie.Insert("users.*")
	trie.Insert("admin.*.*")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.Match("posts.create")
	}
}

func BenchmarkPermissionTrie_LargeDataset(b *testing.B) {
	trie := NewPermissionTrie()
	// Insert 1000 permissions
	for i := 0; i < 1000; i++ {
		trie.Insert("resource.action")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.Match("resource.action")
	}
}
