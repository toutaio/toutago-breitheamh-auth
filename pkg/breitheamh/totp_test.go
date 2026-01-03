package breitheamh

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPGenerateSecret(t *testing.T) {
	totp := NewTOTP(nil)

	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if len(secret) == 0 {
		t.Error("Expected non-empty secret")
	}

	// Verify it's valid base32
	if !isValidBase32(secret) {
		t.Error("Secret is not valid base32")
	}
}

func TestTOTPGenerateCode(t *testing.T) {
	totp := NewTOTP(nil)
	secret := "JBSWY3DPEHPK3PXP" // Known test secret

	code, err := totp.GenerateCodeAt(secret, time.Unix(1234567890, 0))
	if err != nil {
		t.Fatalf("GenerateCodeAt failed: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %d", len(code))
	}

	// Verify code is numeric
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("Code contains non-numeric character: %c", c)
		}
	}
}

func TestTOTPValidate(t *testing.T) {
	totp := NewTOTP(nil)
	secret, _ := totp.GenerateSecret()

	code, err := totp.GenerateCode(secret)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if !totp.Validate(secret, code) {
		t.Error("Valid code was rejected")
	}

	if totp.Validate(secret, "000000") {
		t.Error("Invalid code was accepted")
	}
}

func TestTOTPValidateWindow(t *testing.T) {
	totp := NewTOTP(nil)
	secret, _ := totp.GenerateSecret()

	now := time.Now()
	pastCode, _ := totp.GenerateCodeAt(secret, now.Add(-30*time.Second))

	// Should validate with window=1
	if !totp.ValidateWindow(secret, pastCode, 1) {
		t.Error("Code from previous period should be valid with window=1")
	}

	// Should not validate with window=0
	if totp.ValidateWindow(secret, pastCode, 0) {
		t.Error("Code from previous period should be invalid with window=0")
	}
}

func TestTOTPGenerateProvisioningURI(t *testing.T) {
	config := &TOTPConfig{
		Issuer:      "TestApp",
		AccountName: "user@example.com",
		Period:      30,
		Digits:      6,
		Algorithm:   "SHA1",
	}

	totp := NewTOTP(config)
	secret := "JBSWY3DPEHPK3PXP"

	uri := totp.GenerateProvisioningURI(secret, "user@example.com")

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Error("URI should start with otpauth://totp/")
	}

	if !strings.Contains(uri, "secret="+secret) {
		t.Error("URI should contain secret")
	}

	if !strings.Contains(uri, "issuer=TestApp") {
		t.Error("URI should contain issuer")
	}

	if !strings.Contains(uri, "digits=6") {
		t.Error("URI should contain digits")
	}

	if !strings.Contains(uri, "period=30") {
		t.Error("URI should contain period")
	}
}

func TestTOTPDifferentDigits(t *testing.T) {
	config := &TOTPConfig{
		Digits: 8,
		Period: 30,
	}

	totp := NewTOTP(config)
	secret, _ := totp.GenerateSecret()

	code, err := totp.GenerateCode(secret)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if len(code) != 8 {
		t.Errorf("Expected 8 digit code, got %d", len(code))
	}
}

func TestTwoFactorUser(t *testing.T) {
	user := &TwoFactorUser{
		BaseUser: BaseUser{
			ID:    "123",
			Email: "testuser@example.com",
		},
	}

	if user.HasTwoFactorEnabled() {
		t.Error("2FA should be disabled by default")
	}

	totp := NewTOTP(nil)
	secret, _ := totp.GenerateSecret()
	user.SetTwoFactorSecret(secret)

	if user.HasTwoFactorEnabled() {
		t.Error("2FA should still be disabled without enabling")
	}

	user.EnableTwoFactor()

	if !user.HasTwoFactorEnabled() {
		t.Error("2FA should be enabled")
	}

	if user.GetTwoFactorSecret() != secret {
		t.Error("Secret should match")
	}

	user.DisableTwoFactor()

	if user.HasTwoFactorEnabled() {
		t.Error("2FA should be disabled after disabling")
	}
}

func TestTOTPDefaultConfig(t *testing.T) {
	totp := NewTOTP(nil)

	if totp.config.Period != 30 {
		t.Errorf("Expected default period 30, got %d", totp.config.Period)
	}

	if totp.config.Digits != 6 {
		t.Errorf("Expected default digits 6, got %d", totp.config.Digits)
	}

	if totp.config.Algorithm != "SHA1" {
		t.Errorf("Expected default algorithm SHA1, got %s", totp.config.Algorithm)
	}
}

func isValidBase32(s string) bool {
	s = strings.ToUpper(s)
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for _, c := range s {
		if !strings.ContainsRune(validChars, c) {
			return false
		}
	}
	return true
}
