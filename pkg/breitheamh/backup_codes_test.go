package breitheamh

import (
	"strings"
	"testing"
)

func TestBackupCodeGenerator(t *testing.T) {
	gen := NewBackupCodeGenerator()

	codes, err := gen.GenerateCodes()
	if err != nil {
		t.Fatalf("GenerateCodes failed: %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("Expected 10 codes, got %d", len(codes))
	}

	for _, code := range codes {
		if len(strings.ReplaceAll(code, "-", "")) != 8 {
			t.Errorf("Expected 8 character code (excluding hyphens), got: %s", code)
		}
	}
}

func TestBackupCodeGeneratorCustomLength(t *testing.T) {
	gen := NewBackupCodeGenerator().WithCodeLength(12).WithCodeCount(5)

	codes, err := gen.GenerateCodes()
	if err != nil {
		t.Fatalf("GenerateCodes failed: %v", err)
	}

	if len(codes) != 5 {
		t.Errorf("Expected 5 codes, got %d", len(codes))
	}

	for _, code := range codes {
		normalized := strings.ReplaceAll(code, "-", "")
		if len(normalized) != 12 {
			t.Errorf("Expected 12 character code, got: %s", code)
		}
	}
}

func TestBackupCodeUniqueness(t *testing.T) {
	gen := NewBackupCodeGenerator()

	codes, err := gen.GenerateCodes()
	if err != nil {
		t.Fatalf("GenerateCodes failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Errorf("Duplicate code generated: %s", code)
		}
		seen[code] = true
	}
}

func TestBackupCodeValidation(t *testing.T) {
	gen := NewBackupCodeGenerator()

	validCodes := []string{"ABCD-1234", "EFGH-5678"}

	tests := []struct {
		code  string
		valid bool
	}{
		{"ABCD-1234", true},
		{"abcd-1234", true}, // Case insensitive
		{"ABCD1234", true},  // Hyphen optional
		{"abcd1234", true},  // Both
		{"EFGH-5678", true},
		{"EFGH5678", true},
		{"XXXX-XXXX", false},
		{"1234-5678", false},
	}

	for _, tt := range tests {
		result := gen.ValidateCode(tt.code, validCodes)
		if result != tt.valid {
			t.Errorf("ValidateCode(%s) = %v, expected %v", tt.code, result, tt.valid)
		}
	}
}

func TestBackupCodeUser(t *testing.T) {
	user := &BackupCodeUser{
		TwoFactorUser: TwoFactorUser{
			BaseUser: BaseUser{
				ID:    "123",
				Email: "testuser@example.com",
			},
		},
	}

	gen := NewBackupCodeGenerator()
	codes, err := user.RegenerateBackupCodes(gen)
	if err != nil {
		t.Fatalf("RegenerateBackupCodes failed: %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("Expected 10 codes, got %d", len(codes))
	}

	if !user.HasUnusedBackupCodes() {
		t.Error("Should have unused backup codes")
	}

	if user.GetUnusedBackupCodeCount() != 10 {
		t.Errorf("Expected 10 unused codes, got %d", user.GetUnusedBackupCodeCount())
	}
}

func TestBackupCodeUsage(t *testing.T) {
	user := &BackupCodeUser{
		BackupCodes: []BackupCode{
			{Code: "ABCD-1234", Used: false},
			{Code: "EFGH-5678", Used: false},
		},
	}

	// Use first code
	if !user.UseBackupCode("ABCD-1234") {
		t.Error("Valid code should be accepted")
	}

	// Try to use same code again
	if user.UseBackupCode("ABCD-1234") {
		t.Error("Used code should not be accepted again")
	}

	// Use second code with different format
	if !user.UseBackupCode("efgh5678") {
		t.Error("Valid code (case insensitive, no hyphen) should be accepted")
	}

	// Invalid code
	if user.UseBackupCode("XXXX-XXXX") {
		t.Error("Invalid code should not be accepted")
	}

	if user.HasUnusedBackupCodes() {
		t.Error("Should have no unused backup codes")
	}

	if user.GetUnusedBackupCodeCount() != 0 {
		t.Errorf("Expected 0 unused codes, got %d", user.GetUnusedBackupCodeCount())
	}
}

func TestBackupCodeNormalization(t *testing.T) {
	gen := NewBackupCodeGenerator()

	tests := []struct {
		input    string
		expected string
	}{
		{"ABCD-1234", "ABCD1234"},
		{"abcd-1234", "ABCD1234"},
		{"ABCD 1234", "ABCD1234"},
		{"abcd1234", "ABCD1234"},
		{"Ab-Cd-12-34", "ABCD1234"},
	}

	for _, tt := range tests {
		result := gen.normalizeCode(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeCode(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestBackupCodeFormat(t *testing.T) {
	gen := NewBackupCodeGenerator()

	code, err := gen.generateSingleCode()
	if err != nil {
		t.Fatalf("generateSingleCode failed: %v", err)
	}

	// Should be in XXXX-XXXX format for 8-char codes
	parts := strings.Split(code, "-")
	if len(parts) != 2 {
		t.Errorf("Expected code with hyphen, got: %s", code)
	}

	if len(parts[0]) != 4 || len(parts[1]) != 4 {
		t.Errorf("Expected XXXX-XXXX format, got: %s", code)
	}

	// Should be uppercase hexadecimal
	for _, c := range strings.ReplaceAll(code, "-", "") {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Errorf("Code contains invalid character: %c in %s", c, code)
		}
	}
}
