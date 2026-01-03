package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh/providers"
)

func main() {
	fmt.Println("=== Two-Factor Authentication (2FA) Example ===\n")

	// Setup
	provider := providers.NewMemoryProvider()
	jwtGuard := breitheamh.NewJWTGuard("secret-key", provider, 24*time.Hour)

	// Create user
	user := breitheamh.NewBaseUser(1, "user@example.com", "John Doe")
	hashedPassword, _ := breitheamh.HashPasswordBcrypt("password123", 10)
	user.SetPassword(hashedPassword)
	provider.AddUser(user)

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Enable 2FA
	fmt.Println("Step 1: Enable Two-Factor Authentication")
	fmt.Println("Generating TOTP secret...")

	totpManager := breitheamh.NewTOTPManager()
	secret, err := totpManager.GenerateSecret(user.GetEmail())
	if err != nil {
		fmt.Printf("Error generating secret: %v\n", err)
		return
	}

	user.SetTwoFactorSecret(secret)

	// Generate QR code URL
	qrURL := totpManager.GenerateQRCodeURL(user.GetEmail(), secret, "MyApp")
	fmt.Printf("\nScan this QR code with your authenticator app:\n%s\n\n", qrURL)
	fmt.Println("Or manually enter this secret in your authenticator app:")
	fmt.Printf("Secret: %s\n\n", secret)

	// Generate backup codes
	fmt.Println("Generating backup codes (save these in a safe place):")
	backupCodes := breitheamh.GenerateBackupCodes(8)
	hashedBackupCodes := breitheamh.HashBackupCodes(backupCodes)
	user.SetBackupCodes(hashedBackupCodes)

	fmt.Println("Your backup codes (each can be used only once):")
	for i, code := range backupCodes {
		fmt.Printf("  %d. %s\n", i+1, code)
	}
	fmt.Println()

	// Wait for user to set up their authenticator
	fmt.Print("Press Enter after setting up your authenticator app...")
	reader.ReadString('\n')

	// Verify 2FA setup
	fmt.Println("\nStep 2: Verify 2FA Setup")
	for {
		fmt.Print("Enter the 6-digit code from your authenticator app: ")
		input, _ := reader.ReadString('\n')
		code := strings.TrimSpace(input)

		if totpManager.ValidateCode(secret, code) {
			user.EnableTwoFactor()
			fmt.Println("✓ 2FA enabled successfully!\n")
			break
		}

		fmt.Println("✗ Invalid code. Please try again.\n")
	}

	// Step 3: Login with 2FA
	fmt.Println("Step 3: Login with Two-Factor Authentication")
	
	// First, authenticate with password
	fmt.Println("Authenticating with email and password...")
	credentials := map[string]interface{}{
		"email":    "user@example.com",
		"password": "password123",
	}

	_, err = jwtGuard.Attempt(credentials)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}

	fmt.Println("✓ Password authentication successful")
	fmt.Println("⚠ 2FA required to complete login\n")

	// Now require 2FA
	for {
		fmt.Print("Enter your 6-digit 2FA code (or 'backup' to use backup code): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "backup" {
			// Use backup code
			fmt.Print("Enter backup code: ")
			backupInput, _ := reader.ReadString('\n')
			backupCode := strings.TrimSpace(backupInput)

			if user.UseBackupCode(backupCode) {
				fmt.Println("✓ Backup code accepted!")
				fmt.Printf("✓ Remaining backup codes: %d\n\n", len(user.GetBackupCodes()))
				break
			}

			fmt.Println("✗ Invalid backup code. Please try again.\n")
			continue
		}

		if totpManager.ValidateCode(user.GetTwoFactorSecret(), input) {
			fmt.Println("✓ 2FA code verified!")
			break
		}

		fmt.Println("✗ Invalid 2FA code. Please try again.\n")
	}

	// Generate final JWT token after 2FA
	token, _ := jwtGuard.Attempt(credentials)
	fmt.Println("\n✓ Login successful!")
	fmt.Printf("JWT Token: %s...\n", token[:50])

	// Demo: Disable 2FA
	fmt.Println("\n---")
	fmt.Print("Demo: Disable 2FA? (yes/no): ")
	input, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(input)) == "yes" {
		fmt.Print("Enter your 2FA code to confirm: ")
		codeInput, _ := reader.ReadString('\n')
		code := strings.TrimSpace(codeInput)

		if totpManager.ValidateCode(user.GetTwoFactorSecret(), code) {
			user.DisableTwoFactor()
			fmt.Println("✓ 2FA disabled successfully!")
		} else {
			fmt.Println("✗ Invalid code. 2FA remains enabled.")
		}
	}

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("\nSecurity Tips:")
	fmt.Println("1. Never share your 2FA secret or backup codes")
	fmt.Println("2. Store backup codes in a secure location")
	fmt.Println("3. Use a reputable authenticator app (Google Authenticator, Authy, etc.)")
	fmt.Println("4. Enable 2FA on all important accounts")
}
