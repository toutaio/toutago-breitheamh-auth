package breitheamh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// BackupCode represents a single backup code
type BackupCode struct {
	Code string
	Used bool
}

// BackupCodeGenerator generates and validates backup codes for 2FA
type BackupCodeGenerator struct {
	codeLength int
	codeCount  int
}

// NewBackupCodeGenerator creates a new backup code generator
func NewBackupCodeGenerator() *BackupCodeGenerator {
	return &BackupCodeGenerator{
		codeLength: 8,
		codeCount:  10,
	}
}

// WithCodeLength sets the length of each backup code
func (g *BackupCodeGenerator) WithCodeLength(length int) *BackupCodeGenerator {
	g.codeLength = length
	return g
}

// WithCodeCount sets the number of backup codes to generate
func (g *BackupCodeGenerator) WithCodeCount(count int) *BackupCodeGenerator {
	g.codeCount = count
	return g
}

// GenerateCodes generates a set of backup codes
func (g *BackupCodeGenerator) GenerateCodes() ([]string, error) {
	codes := make([]string, g.codeCount)

	for i := 0; i < g.codeCount; i++ {
		code, err := g.generateSingleCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate code: %w", err)
		}
		codes[i] = code
	}

	return codes, nil
}

// generateSingleCode generates a single random backup code
func (g *BackupCodeGenerator) generateSingleCode() (string, error) {
	bytes := make([]byte, g.codeLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	code := hex.EncodeToString(bytes)

	// Format as XXXX-XXXX for 8-character codes
	if g.codeLength == 8 {
		return strings.ToUpper(fmt.Sprintf("%s-%s", code[:4], code[4:])), nil
	}

	return strings.ToUpper(code[:g.codeLength]), nil
}

// ValidateCode validates a backup code
func (g *BackupCodeGenerator) ValidateCode(code string, validCodes []string) bool {
	normalizedInput := g.normalizeCode(code)

	for _, validCode := range validCodes {
		if g.normalizeCode(validCode) == normalizedInput {
			return true
		}
	}

	return false
}

// normalizeCode removes hyphens and converts to uppercase
func (g *BackupCodeGenerator) normalizeCode(code string) string {
	normalized := strings.ReplaceAll(code, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	return strings.ToUpper(normalized)
}

// BackupCodeAuthenticatable extends TwoFactorAuthenticatable with backup codes
type BackupCodeAuthenticatable interface {
	TwoFactorAuthenticatable
	GetBackupCodes() []BackupCode
	SetBackupCodes(codes []BackupCode)
	UseBackupCode(code string) bool
}

// BackupCodeUser extends TwoFactorUser with backup code support
type BackupCodeUser struct {
	TwoFactorUser
	BackupCodes []BackupCode
}

func (u *BackupCodeUser) GetBackupCodes() []BackupCode {
	return u.BackupCodes
}

func (u *BackupCodeUser) SetBackupCodes(codes []BackupCode) {
	u.BackupCodes = codes
}

// UseBackupCode marks a backup code as used and returns true if valid
func (u *BackupCodeUser) UseBackupCode(code string) bool {
	normalizeCode := func(c string) string {
		normalized := strings.ReplaceAll(c, "-", "")
		normalized = strings.ReplaceAll(normalized, " ", "")
		return strings.ToUpper(normalized)
	}

	normalizedInput := normalizeCode(code)

	for i := range u.BackupCodes {
		if !u.BackupCodes[i].Used && normalizeCode(u.BackupCodes[i].Code) == normalizedInput {
			u.BackupCodes[i].Used = true
			return true
		}
	}

	return false
}

// HasUnusedBackupCodes returns true if there are unused backup codes
func (u *BackupCodeUser) HasUnusedBackupCodes() bool {
	for _, code := range u.BackupCodes {
		if !code.Used {
			return true
		}
	}
	return false
}

// GetUnusedBackupCodeCount returns the number of unused backup codes
func (u *BackupCodeUser) GetUnusedBackupCodeCount() int {
	count := 0
	for _, code := range u.BackupCodes {
		if !code.Used {
			count++
		}
	}
	return count
}

// RegenerateBackupCodes generates new backup codes and replaces existing ones
func (u *BackupCodeUser) RegenerateBackupCodes(generator *BackupCodeGenerator) ([]string, error) {
	codes, err := generator.GenerateCodes()
	if err != nil {
		return nil, err
	}

	backupCodes := make([]BackupCode, len(codes))
	for i, code := range codes {
		backupCodes[i] = BackupCode{Code: code, Used: false}
	}

	u.BackupCodes = backupCodes
	return codes, nil
}
