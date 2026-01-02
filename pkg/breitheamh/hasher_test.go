package breitheamh

import (
	"testing"
)

func TestHasherBcrypt(t *testing.T) {
	hasher := NewHasher(AlgorithmBcrypt)

	password := "secret123"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Verify correct password
	err = hasher.Verify(password, hash)
	if err != nil {
		t.Errorf("Failed to verify correct password: %v", err)
	}

	// Verify incorrect password
	err = hasher.Verify("wrong", hash)
	if err == nil {
		t.Error("Expected error for incorrect password")
	}
	if err != ErrHashMismatch {
		t.Errorf("Expected ErrHashMismatch, got %v", err)
	}
}

func TestHasherArgon2(t *testing.T) {
	hasher := NewHasher(AlgorithmArgon2)

	password := "secret123"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Verify correct password
	err = hasher.Verify(password, hash)
	if err != nil {
		t.Errorf("Failed to verify correct password: %v", err)
	}

	// Verify incorrect password
	err = hasher.Verify("wrong", hash)
	if err == nil {
		t.Error("Expected error for incorrect password")
	}
	if err != ErrHashMismatch {
		t.Errorf("Expected ErrHashMismatch, got %v", err)
	}
}

func BenchmarkHasherBcrypt(b *testing.B) {
	hasher := NewHasher(AlgorithmBcrypt)
	password := "secret123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.Hash(password)
	}
}

func BenchmarkHasherArgon2(b *testing.B) {
	hasher := NewHasher(AlgorithmArgon2)
	password := "secret123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.Hash(password)
	}
}
