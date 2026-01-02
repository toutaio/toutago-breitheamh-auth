package main

import (
	"context"
	"fmt"
	"log"

	"github.com/toutaio/toutago-breitheamh-auth/adapters/memory"
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

func main() {
	fmt.Println("🔐 Breitheamh Auth - Basic Authentication Example")
	fmt.Println("==================================================\n")

	// 1. Create a hasher
	hasher := breitheamh.NewHasher(breitheamh.AlgorithmBcrypt)
	fmt.Println("✓ Created password hasher (bcrypt)")

	// 2. Hash a password
	hashedPassword, err := hasher.Hash("secret123")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("✓ Hashed password:", hashedPassword[:50]+"...")

	// 3. Create a user
	user := breitheamh.NewBaseUser("user-1", "alice@example.com", hashedPassword)
	fmt.Println("✓ Created user:", user.Email)

	// 4. Assign permissions
	createPermission := breitheamh.Permission{
		ID:   "perm-1",
		Name: "posts.create",
	}
	user.GivePermission(createPermission)
	fmt.Println("✓ Granted permission: posts.create")

	// 5. Assign wildcard permission
	adminPermission := breitheamh.Permission{
		ID:   "perm-2",
		Name: "users.*",
	}
	user.GivePermission(adminPermission)
	fmt.Println("✓ Granted permission: users.*")

	// 6. Check permissions
	fmt.Println("\nPermission Checks:")
	fmt.Printf("  - Can create posts? %v\n", user.HasPermission("posts.create"))
	fmt.Printf("  - Can edit users? %v (via wildcard)\n", user.HasPermission("users.edit"))
	fmt.Printf("  - Can delete posts? %v\n", user.HasPermission("posts.delete"))

	// 7. Create a role
	editorRole := breitheamh.Role{
		ID:   "role-1",
		Name: "editor",
		Permissions: []breitheamh.Permission{
			{ID: "perm-3", Name: "posts.edit"},
			{ID: "perm-4", Name: "posts.delete"},
		},
	}
	user.AssignRole(editorRole)
	fmt.Println("\n✓ Assigned role: editor")

	fmt.Println("\nRole Checks:")
	fmt.Printf("  - Has editor role? %v\n", user.HasRole("editor"))
	fmt.Printf("  - Can delete posts? %v (via role)\n", user.HasPermission("posts.delete"))

	// 8. Setup JWT authentication
	fmt.Println("\n🎫 JWT Authentication:")

	provider := memory.NewProvider()
	provider.AddUser(user)

	jwtConfig := breitheamh.DefaultJWTConfig("my-super-secret-key-min-32-chars-long!!!")
	tokenManager := breitheamh.NewJWTTokenManager(jwtConfig)

	guard := breitheamh.NewJWTGuard("jwt", provider, tokenManager, hasher)
	fmt.Println("✓ Created JWT guard")

	// 9. Authenticate and get token
	ctx := context.Background()
	authUser, token, err := guard.Attempt(ctx, breitheamh.Credentials{
		Email:    "alice@example.com",
		Password: "secret123",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Authentication successful for: %s\n", authUser.GetAuthIdentifier())
	fmt.Printf("  - Access Token: %s...\n", token.AccessToken[:40])
	fmt.Printf("  - Refresh Token: %s...\n", token.RefreshToken[:40])
	fmt.Printf("  - Expires In: %d seconds\n", token.ExpiresIn)

	// 10. Validate token
	validatedUser, err := guard.Validate(ctx, token.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Token validated for user: %s\n", validatedUser.GetID())

	// 11. Demonstrate password verification
	fmt.Println("\n🔑 Password Verification:")
	err = hasher.Verify("secret123", user.GetPassword())
	if err != nil {
		fmt.Println("  ✗ Wrong password!")
	} else {
		fmt.Println("  ✓ Password is correct!")
	}

	err = hasher.Verify("wrongpassword", user.GetPassword())
	if err != nil {
		fmt.Println("  ✗ Wrong password (as expected)")
	}

	fmt.Println("\n✅ Example completed successfully!")
}
