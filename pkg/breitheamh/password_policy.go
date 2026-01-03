package breitheamh

import (
	"errors"
	"regexp"
	"unicode"
)

var (
	// ErrPasswordTooShort is returned when a password is too short
	ErrPasswordTooShort = errors.New("password is too short")
	// ErrPasswordTooLong is returned when a password is too long
	ErrPasswordTooLong = errors.New("password is too long")
	// ErrPasswordNoUppercase is returned when a password lacks uppercase letters
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	// ErrPasswordNoLowercase is returned when a password lacks lowercase letters
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	// ErrPasswordNoDigit is returned when a password lacks digits
	ErrPasswordNoDigit = errors.New("password must contain at least one digit")
	// ErrPasswordNoSpecial is returned when a password lacks special characters
	ErrPasswordNoSpecial = errors.New("password must contain at least one special character")
	// ErrPasswordCommonPattern is returned when a password matches common patterns
	ErrPasswordCommonPattern = errors.New("password contains common patterns")
)

// PasswordPolicy defines password validation rules
type PasswordPolicy struct {
	MinLength          int
	MaxLength          int
	RequireUppercase   bool
	RequireLowercase   bool
	RequireDigit       bool
	RequireSpecial     bool
	ForbiddenPatterns  []string
	CustomValidators   []PasswordValidator
}

// PasswordValidator is a custom password validation function
type PasswordValidator func(password string) error

// DefaultPasswordPolicy returns a reasonable default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
		ForbiddenPatterns: []string{
			"password",
			"12345",
			"qwerty",
			"admin",
		},
	}
}

// Validate checks if a password meets the policy requirements
func (p *PasswordPolicy) Validate(password string) error {
	if len(password) < p.MinLength {
		return ErrPasswordTooShort
	}
	
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		return ErrPasswordTooLong
	}
	
	if p.RequireUppercase && !containsUppercase(password) {
		return ErrPasswordNoUppercase
	}
	
	if p.RequireLowercase && !containsLowercase(password) {
		return ErrPasswordNoLowercase
	}
	
	if p.RequireDigit && !containsDigit(password) {
		return ErrPasswordNoDigit
	}
	
	if p.RequireSpecial && !containsSpecial(password) {
		return ErrPasswordNoSpecial
	}
	
	if err := p.checkForbiddenPatterns(password); err != nil {
		return err
	}
	
	for _, validator := range p.CustomValidators {
		if err := validator(password); err != nil {
			return err
		}
	}
	
	return nil
}

func containsUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	for _, r := range s {
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}

func (p *PasswordPolicy) checkForbiddenPatterns(password string) error {
	lowerPassword := toLower(password)
	
	for _, pattern := range p.ForbiddenPatterns {
		matched, err := regexp.MatchString(toLower(pattern), lowerPassword)
		if err != nil {
			continue
		}
		if matched {
			return ErrPasswordCommonPattern
		}
	}
	
	return nil
}

func toLower(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		runes[i] = unicode.ToLower(r)
	}
	return string(runes)
}

// AddForbiddenPattern adds a pattern to the forbidden list
func (p *PasswordPolicy) AddForbiddenPattern(pattern string) {
	p.ForbiddenPatterns = append(p.ForbiddenPatterns, pattern)
}

// AddCustomValidator adds a custom validation function
func (p *PasswordPolicy) AddCustomValidator(validator PasswordValidator) {
	p.CustomValidators = append(p.CustomValidators, validator)
}
