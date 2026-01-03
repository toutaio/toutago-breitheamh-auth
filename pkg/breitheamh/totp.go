package breitheamh

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTPConfig holds configuration for TOTP generation
type TOTPConfig struct {
	Issuer      string
	AccountName string
	Period      int
	Digits      int
	Algorithm   string
}

// DefaultTOTPConfig returns default TOTP configuration
func DefaultTOTPConfig() *TOTPConfig {
	return &TOTPConfig{
		Issuer:      "ToutaGo",
		AccountName: "",
		Period:      30,
		Digits:      6,
		Algorithm:   "SHA1",
	}
}

// TOTP represents a TOTP generator
type TOTP struct {
	config *TOTPConfig
}

// NewTOTP creates a new TOTP generator
func NewTOTP(config *TOTPConfig) *TOTP {
	if config == nil {
		config = DefaultTOTPConfig()
	}
	if config.Period == 0 {
		config.Period = 30
	}
	if config.Digits == 0 {
		config.Digits = 6
	}
	if config.Algorithm == "" {
		config.Algorithm = "SHA1"
	}
	return &TOTP{config: config}
}

// GenerateSecret generates a random base32-encoded secret
func (t *TOTP) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateCode generates a TOTP code for the given secret at the current time
func (t *TOTP) GenerateCode(secret string) (string, error) {
	return t.GenerateCodeAt(secret, time.Now())
}

// GenerateCodeAt generates a TOTP code for the given secret at a specific time
func (t *TOTP) GenerateCodeAt(secret string, timestamp time.Time) (string, error) {
	counter := uint64(timestamp.Unix()) / uint64(t.config.Period)
	return t.generateHOTP(secret, counter)
}

// Validate validates a TOTP code against a secret with a time window
func (t *TOTP) Validate(secret, code string) bool {
	return t.ValidateWindow(secret, code, 1)
}

// ValidateWindow validates a TOTP code with a specified time window
// window specifies how many periods before and after to check
func (t *TOTP) ValidateWindow(secret, code string, window int) bool {
	now := time.Now()
	currentCounter := uint64(now.Unix()) / uint64(t.config.Period)

	for i := -window; i <= window; i++ {
		counter := currentCounter + uint64(i)
		expectedCode, err := t.generateHOTP(secret, counter)
		if err != nil {
			return false
		}
		if code == expectedCode {
			return true
		}
	}
	return false
}

// GenerateProvisioningURI generates a provisioning URI for QR code generation
func (t *TOTP) GenerateProvisioningURI(secret, accountName string) string {
	if accountName == "" {
		accountName = t.config.AccountName
	}

	issuer := t.config.Issuer
	label := accountName
	if issuer != "" {
		label = fmt.Sprintf("%s:%s", issuer, accountName)
	}

	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		label,
		secret,
		issuer,
		t.config.Algorithm,
		t.config.Digits,
		t.config.Period,
	)

	return uri
}

func (t *TOTP) generateHOTP(secret string, counter uint64) (string, error) {
	secret = strings.ToUpper(secret)
	secret = strings.ReplaceAll(secret, " ", "")

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret: %w", err)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	h := hmac.New(sha1.New, key)
	h.Write(buf)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	code := truncated % uint32(pow10(t.config.Digits))

	format := fmt.Sprintf("%%0%dd", t.config.Digits)
	return fmt.Sprintf(format, code), nil
}

func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

// TwoFactorAuthenticatable extends User interface with 2FA support
type TwoFactorAuthenticatable interface {
	User
	GetTwoFactorSecret() string
	SetTwoFactorSecret(secret string)
	HasTwoFactorEnabled() bool
	EnableTwoFactor()
	DisableTwoFactor()
}

// TwoFactorUser is a base implementation of TwoFactorAuthenticatable
type TwoFactorUser struct {
	BaseUser
	TwoFactorSecret  string
	TwoFactorEnabled bool
}

func (u *TwoFactorUser) GetTwoFactorSecret() string {
	return u.TwoFactorSecret
}

func (u *TwoFactorUser) SetTwoFactorSecret(secret string) {
	u.TwoFactorSecret = secret
}

func (u *TwoFactorUser) HasTwoFactorEnabled() bool {
	return u.TwoFactorEnabled && u.TwoFactorSecret != ""
}

func (u *TwoFactorUser) EnableTwoFactor() {
	u.TwoFactorEnabled = true
}

func (u *TwoFactorUser) DisableTwoFactor() {
	u.TwoFactorEnabled = false
}
