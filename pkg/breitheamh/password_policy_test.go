package breitheamh

import (
	"errors"
	"testing"
)

func TestPasswordPolicy(t *testing.T) {
	t.Run("default policy validates strong password", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		if err := policy.Validate("MyP@ssw0rd123"); err != nil {
			t.Errorf("strong password should pass: %v", err)
		}
	})

	t.Run("rejects password too short", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		if err := policy.Validate("Abc1!"); err != ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("rejects password too long", func(t *testing.T) {
		policy := &PasswordPolicy{
			MinLength: 8,
			MaxLength: 20,
		}

		longPassword := "ThisPasswordIsWayTooLongToBeAccepted123!"
		if err := policy.Validate(longPassword); err != ErrPasswordTooLong {
			t.Errorf("expected ErrPasswordTooLong, got %v", err)
		}
	})

	t.Run("rejects password without uppercase", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		if err := policy.Validate("myp@ssw0rd"); err != ErrPasswordNoUppercase {
			t.Errorf("expected ErrPasswordNoUppercase, got %v", err)
		}
	})

	t.Run("rejects password without lowercase", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		if err := policy.Validate("MYP@SSW0RD"); err != ErrPasswordNoLowercase {
			t.Errorf("expected ErrPasswordNoLowercase, got %v", err)
		}
	})

	t.Run("rejects password without digit", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		if err := policy.Validate("MyP@ssword"); err != ErrPasswordNoDigit {
			t.Errorf("expected ErrPasswordNoDigit, got %v", err)
		}
	})

	t.Run("rejects password without special character", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		if err := policy.Validate("MyPassword123"); err != ErrPasswordNoSpecial {
			t.Errorf("expected ErrPasswordNoSpecial, got %v", err)
		}
	})

	t.Run("rejects common patterns", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		commonPasswords := []string{
			"Password123!",
			"Admin12345!",
			"Qwerty123!",
		}

		for _, pwd := range commonPasswords {
			if err := policy.Validate(pwd); err != ErrPasswordCommonPattern {
				t.Errorf("password '%s' should be rejected for common pattern, got %v", pwd, err)
			}
		}
	})

	t.Run("allows disabling requirements", func(t *testing.T) {
		policy := &PasswordPolicy{
			MinLength:        6,
			RequireUppercase: false,
			RequireLowercase: false,
			RequireDigit:     false,
			RequireSpecial:   false,
		}

		if err := policy.Validate("simple"); err != nil {
			t.Errorf("simple password should pass with relaxed policy: %v", err)
		}
	})

	t.Run("custom forbidden pattern", func(t *testing.T) {
		policy := DefaultPasswordPolicy()
		policy.AddForbiddenPattern("company")

		if err := policy.Validate("Company123!"); err != ErrPasswordCommonPattern {
			t.Errorf("expected ErrPasswordCommonPattern for custom pattern, got %v", err)
		}
	})

	t.Run("custom validator", func(t *testing.T) {
		policy := DefaultPasswordPolicy()

		customErr := errors.New("password cannot contain username")
		policy.AddCustomValidator(func(password string) error {
			if toLower(password) == "john123!" {
				return customErr
			}
			return nil
		})

		if err := policy.Validate("John123!"); err != customErr {
			t.Errorf("expected custom error, got %v", err)
		}
	})

	t.Run("multiple custom validators", func(t *testing.T) {
		policy := &PasswordPolicy{
			MinLength: 8,
		}

		err1 := errors.New("error 1")
		err2 := errors.New("error 2")

		policy.AddCustomValidator(func(password string) error {
			if password == "trigger1" {
				return err1
			}
			return nil
		})

		policy.AddCustomValidator(func(password string) error {
			if password == "trigger2" {
				return err2
			}
			return nil
		})

		if err := policy.Validate("trigger1"); err != err1 {
			t.Errorf("expected first custom error, got %v", err)
		}

		if err := policy.Validate("trigger2"); err != err2 {
			t.Errorf("expected second custom error, got %v", err)
		}
	})

	t.Run("unicode support", func(t *testing.T) {
		policy := &PasswordPolicy{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireDigit:     true,
			RequireSpecial:   true,
		}

		if err := policy.Validate("Pássw0rd!"); err != nil {
			t.Errorf("password with unicode should pass: %v", err)
		}
	})
}

func TestPasswordPolicyHelpers(t *testing.T) {
	t.Run("containsUppercase", func(t *testing.T) {
		if !containsUppercase("Hello") {
			t.Error("should detect uppercase")
		}
		if containsUppercase("hello") {
			t.Error("should not detect uppercase")
		}
	})

	t.Run("containsLowercase", func(t *testing.T) {
		if !containsLowercase("Hello") {
			t.Error("should detect lowercase")
		}
		if containsLowercase("HELLO") {
			t.Error("should not detect lowercase")
		}
	})

	t.Run("containsDigit", func(t *testing.T) {
		if !containsDigit("test123") {
			t.Error("should detect digit")
		}
		if containsDigit("test") {
			t.Error("should not detect digit")
		}
	})

	t.Run("containsSpecial", func(t *testing.T) {
		if !containsSpecial("test!") {
			t.Error("should detect special character")
		}
		if containsSpecial("test") {
			t.Error("should not detect special character")
		}
	})
}

func BenchmarkPasswordPolicyValidation(b *testing.B) {
	policy := DefaultPasswordPolicy()
	password := "MyP@ssw0rd123"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			policy.Validate(password)
		}
	})
}
