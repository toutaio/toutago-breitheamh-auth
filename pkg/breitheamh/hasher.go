package breitheamh

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidHash indicates that the hash format is invalid
	ErrInvalidHash = errors.New("invalid hash format")

	// ErrHashMismatch indicates that the password does not match the hash
	ErrHashMismatch = errors.New("password does not match hash")
)

// HashAlgorithm represents the hashing algorithm to use
type HashAlgorithm string

const (
	// AlgorithmBcrypt uses bcrypt for password hashing
	AlgorithmBcrypt HashAlgorithm = "bcrypt"

	// AlgorithmArgon2 uses argon2id for password hashing
	AlgorithmArgon2 HashAlgorithm = "argon2"
)

// Hasher provides password hashing and verification.
type Hasher struct {
	algorithm HashAlgorithm
	bcryptCost int
	argon2Params *Argon2Params
}

// Argon2Params contains parameters for argon2id hashing.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params returns secure default parameters for argon2id.
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// NewHasher creates a new password hasher with the specified algorithm.
func NewHasher(algorithm HashAlgorithm) *Hasher {
	return &Hasher{
		algorithm:    algorithm,
		bcryptCost:   bcrypt.DefaultCost,
		argon2Params: DefaultArgon2Params(),
	}
}

// Hash hashes a password using the configured algorithm.
func (h *Hasher) Hash(password string) (string, error) {
	switch h.algorithm {
	case AlgorithmBcrypt:
		return h.hashBcrypt(password)
	case AlgorithmArgon2:
		return h.hashArgon2(password)
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", h.algorithm)
	}
}

// Verify verifies a password against a hash.
func (h *Hasher) Verify(password, hash string) error {
	// Detect algorithm from hash prefix
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return h.verifyBcrypt(password, hash)
	} else if strings.HasPrefix(hash, "$argon2id$") {
		return h.verifyArgon2(password, hash)
	}

	return ErrInvalidHash
}

// hashBcrypt hashes a password using bcrypt.
func (h *Hasher) hashBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyBcrypt verifies a password against a bcrypt hash.
func (h *Hasher) verifyBcrypt(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrHashMismatch
		}
		return err
	}
	return nil
}

// hashArgon2 hashes a password using argon2id.
func (h *Hasher) hashArgon2(password string) (string, error) {
	salt := make([]byte, h.argon2Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.argon2Params.Iterations,
		h.argon2Params.Memory,
		h.argon2Params.Parallelism,
		h.argon2Params.KeyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.argon2Params.Memory,
		h.argon2Params.Iterations,
		h.argon2Params.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// verifyArgon2 verifies a password against an argon2id hash.
func (h *Hasher) verifyArgon2(password, encodedHash string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrInvalidHash
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHash
	}

	keyLength := uint32(len(hash))

	comparisonHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	if subtle.ConstantTimeCompare(hash, comparisonHash) == 1 {
		return nil
	}

	return ErrHashMismatch
}
