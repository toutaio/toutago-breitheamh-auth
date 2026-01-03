package breitheamh

import (
	"testing"
)

func BenchmarkPasswordHashing(b *testing.B) {
	password := "secure_password_123"

	b.Run("BcryptHash", func(b *testing.B) {
		hasher := NewHasher(AlgorithmBcrypt)
		for i := 0; i < b.N; i++ {
			_, err := hasher.Hash(password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	hasher := NewHasher(AlgorithmBcrypt)
	hashedPassword, _ := hasher.Hash(password)

	b.Run("BcryptVerify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := hasher.Verify(password, hashedPassword); err != nil {
				b.Fatal("password verification failed")
			}
		}
	})
}

func BenchmarkPermissionMatching(b *testing.B) {
	trie := NewPermissionTrie()
	
	permissions := []string{
		"posts.create",
		"posts.read",
		"posts.update",
		"posts.delete",
		"users.create",
		"users.read",
		"users.update",
		"users.delete",
		"admin.*",
		"reports.*",
	}

	for _, perm := range permissions {
		trie.Insert(perm)
	}

	b.Run("ExactMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !trie.Match("posts.create") {
				b.Fatal("expected match")
			}
		}
	})

	b.Run("WildcardMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !trie.Match("admin.users.delete") {
				b.Fatal("expected wildcard match")
			}
		}
	})

	b.Run("NoMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if trie.Match("comments.create") {
				b.Fatal("expected no match")
			}
		}
	})
}



