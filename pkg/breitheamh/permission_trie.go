package breitheamh

import "strings"

// PermissionTrie implements a trie data structure for efficient permission lookup
// and wildcard matching.
type PermissionTrie struct {
	root *trieNode
}

// trieNode represents a node in the permission trie.
type trieNode struct {
	children map[string]*trieNode
	isEnd    bool
	wildcard bool // If true, this node represents a wildcard (*)
}

// NewPermissionTrie creates a new permission trie.
func NewPermissionTrie() *PermissionTrie {
	return &PermissionTrie{
		root: &trieNode{
			children: make(map[string]*trieNode),
		},
	}
}

// Insert adds a permission pattern to the trie.
// Supports patterns like "posts.create", "posts.*", "admin.*.*"
func (pt *PermissionTrie) Insert(pattern string) {
	parts := strings.Split(pattern, ".")
	current := pt.root

	for i, part := range parts {
		if part == "*" {
			// Wildcard node
			if _, exists := current.children["*"]; !exists {
				current.children["*"] = &trieNode{
					children: make(map[string]*trieNode),
					wildcard: true,
				}
			}
			current = current.children["*"]
		} else {
			// Regular node
			if _, exists := current.children[part]; !exists {
				current.children[part] = &trieNode{
					children: make(map[string]*trieNode),
				}
			}
			current = current.children[part]
		}

		// Mark as end if this is the last part
		if i == len(parts)-1 {
			current.isEnd = true
		}
	}
}

// Match checks if a permission matches any pattern in the trie.
// Returns true if the permission is granted by any stored pattern.
func (pt *PermissionTrie) Match(permission string) bool {
	parts := strings.Split(permission, ".")
	return pt.matchRecursive(pt.root, parts, 0)
}

// matchRecursive recursively searches the trie for a match.
func (pt *PermissionTrie) matchRecursive(node *trieNode, parts []string, index int) bool {
	// If we've consumed all parts
	if index == len(parts) {
		return node.isEnd
	}

	currentPart := parts[index]

	// Check wildcard match first
	if wildcardNode, exists := node.children["*"]; exists {
		// Wildcard at the end matches everything from here
		if wildcardNode.isEnd {
			return true
		}
		// Continue matching with wildcard
		if pt.matchRecursive(wildcardNode, parts, index+1) {
			return true
		}
	}

	// Check exact match
	if exactNode, exists := node.children[currentPart]; exists {
		if pt.matchRecursive(exactNode, parts, index+1) {
			return true
		}
	}

	return false
}

// Remove deletes a permission pattern from the trie.
// Returns true if the pattern was found and removed, false otherwise.
func (pt *PermissionTrie) Remove(pattern string) bool {
	parts := strings.Split(pattern, ".")
	found := false
	pt.removeRecursive(pt.root, parts, 0, &found)
	return found
}

// removeRecursive recursively removes a pattern from the trie.
// Returns true if the current node should be deleted.
func (pt *PermissionTrie) removeRecursive(node *trieNode, parts []string, index int, found *bool) bool {
	if index == len(parts) {
		if !node.isEnd {
			return false // Pattern not found
		}
		*found = true
		node.isEnd = false
		// Return true if this node has no children (can be deleted)
		return len(node.children) == 0
	}

	part := parts[index]
	childNode, exists := node.children[part]
	if !exists {
		return false // Pattern not found
	}

	shouldDeleteChild := pt.removeRecursive(childNode, parts, index+1, found)

	if shouldDeleteChild {
		delete(node.children, part)
		// Return true if current node is not an end and has no children
		return !node.isEnd && len(node.children) == 0
	}

	return false
}

// Contains checks if an exact permission pattern exists in the trie.
func (pt *PermissionTrie) Contains(pattern string) bool {
	parts := strings.Split(pattern, ".")
	current := pt.root

	for _, part := range parts {
		if next, exists := current.children[part]; exists {
			current = next
		} else {
			return false
		}
	}

	return current.isEnd
}

// Clear removes all permissions from the trie.
func (pt *PermissionTrie) Clear() {
	pt.root = &trieNode{
		children: make(map[string]*trieNode),
	}
}

// Size returns the number of permission patterns stored in the trie.
func (pt *PermissionTrie) Size() int {
	return pt.sizeRecursive(pt.root)
}

// sizeRecursive recursively counts the number of end nodes in the trie.
func (pt *PermissionTrie) sizeRecursive(node *trieNode) int {
	count := 0
	if node.isEnd {
		count = 1
	}

	for _, child := range node.children {
		count += pt.sizeRecursive(child)
	}

	return count
}

// GetAllPatterns returns all permission patterns stored in the trie.
func (pt *PermissionTrie) GetAllPatterns() []string {
	var patterns []string
	pt.collectPatterns(pt.root, "", &patterns)
	return patterns
}

// collectPatterns recursively collects all patterns from the trie.
func (pt *PermissionTrie) collectPatterns(node *trieNode, prefix string, patterns *[]string) {
	if node.isEnd {
		*patterns = append(*patterns, prefix)
	}

	for key, child := range node.children {
		var newPrefix string
		if prefix == "" {
			newPrefix = key
		} else {
			newPrefix = prefix + "." + key
		}
		pt.collectPatterns(child, newPrefix, patterns)
	}
}
