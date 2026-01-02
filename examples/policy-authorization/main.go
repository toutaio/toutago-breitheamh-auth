package main

import (
	"context"
	"fmt"

	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Post represents a blog post.
type Post struct {
	ID        string
	Title     string
	Content   string
	AuthorID  string
	Published bool
}

// PostPolicy defines authorization rules for posts.
type PostPolicy struct{}

// Before is called before any policy method.
func (p *PostPolicy) Before(ctx context.Context, user breitheamh.User, ability string) *bool {
	// Super admins can do anything
	if user.HasPermission("superadmin") {
		allow := true
		return &allow
	}
	return nil
}

func main() {
	fmt.Println("Policy-Based Authorization Example")
	fmt.Println("===================================")
	fmt.Println()

	// Create users
	john := breitheamh.NewBaseUser("user-1", "john@example.com", "password")
	jane := breitheamh.NewBaseUser("user-2", "jane@example.com", "password")
	admin := breitheamh.NewBaseUser("admin-1", "admin@example.com", "password")

	// Assign permissions
	john.GivePermission(breitheamh.Permission{ID: "1", Name: "posts.create"})
	jane.GivePermission(breitheamh.Permission{ID: "2", Name: "posts.edit.any"})
	admin.GivePermission(breitheamh.Permission{ID: "3", Name: "superadmin"})

	fmt.Println("Users created:")
	fmt.Printf("  - John: posts.create\n")
	fmt.Printf("  - Jane: posts.edit.any\n")
	fmt.Printf("  - Admin: superadmin\n")
	fmt.Println()

	// Create posts
	johnPost := &Post{
		ID:        "post-1",
		Title:     "John's First Post",
		AuthorID:  "user-1",
		Published: true,
	}

	janePost := &Post{
		ID:        "post-2",
		Title:     "Jane's Draft",
		AuthorID:  "user-2",
		Published: false,
	}

	// Create authorizer and register policy
	authorizer := breitheamh.NewAuthorizer()
	policy := &PostPolicy{}
	authorizer.RegisterPolicy("post", policy)

	ctx := context.Background()

	// Test authorization with permissions
	fmt.Println("Permission-Based Authorization:")
	fmt.Printf("  - John can create posts? %v\n", authorizer.Can(ctx, john, "posts.create", nil))
	fmt.Printf("  - Jane can create posts? %v\n", authorizer.Can(ctx, jane, "posts.create", nil))
	fmt.Printf("  - Jane can edit any post? %v\n", authorizer.Can(ctx, jane, "posts.edit.any", nil))
	fmt.Println()

	// Test gates
	fmt.Println("Gate-Based Authorization:")

	// Define a gate for published posts
	authorizer.DefineGate("view-post", func(ctx context.Context, user breitheamh.User, args ...interface{}) bool {
		if len(args) == 0 {
			return false
		}
		post, ok := args[0].(*Post)
		if !ok {
			return false
		}
		// Anyone can view published posts, only author can view drafts
		return post.Published || post.AuthorID == user.GetID()
	})

	fmt.Printf("  - John can view John's post? %v\n", authorizer.Allows(ctx, "view-post", john, johnPost))
	fmt.Printf("  - Jane can view John's published post? %v\n", authorizer.Allows(ctx, "view-post", jane, johnPost))
	fmt.Printf("  - John can view Jane's draft? %v\n", authorizer.Allows(ctx, "view-post", john, janePost))
	fmt.Printf("  - Jane can view Jane's draft? %v\n", authorizer.Allows(ctx, "view-post", jane, janePost))
	fmt.Println()

	// Test permission gate
	fmt.Println("Permission Gates:")
	createGate := breitheamh.NewPermissionGate("create-posts", "posts.create")
	fmt.Printf("  - John can pass create-posts gate? %v\n", createGate.Allows(ctx, john))
	fmt.Printf("  - Jane can pass create-posts gate? %v\n", createGate.Allows(ctx, jane))
	fmt.Println()

	// Test role gate
	fmt.Println("Role Gates:")
	editorRole := breitheamh.Role{ID: "1", Name: "editor"}
	john.AssignRole(editorRole)

	editorGate := breitheamh.NewRoleGate("editors-only", "editor")
	fmt.Printf("  - John can pass editors-only gate? %v\n", editorGate.Allows(ctx, john))
	fmt.Printf("  - Jane can pass editors-only gate? %v\n", editorGate.Allows(ctx, jane))
	fmt.Println()

	// Test superadmin bypass (would use policy Before hook in real implementation)
	fmt.Println("Superadmin Bypass:")
	fmt.Printf("  - Admin can do anything? %v\n", admin.HasPermission("superadmin"))
	fmt.Println()

	// Demonstrate Cannot
	fmt.Println("Denial Checks:")
	fmt.Printf("  - Jane cannot delete posts? %v\n", authorizer.Cannot(ctx, jane, "posts.delete", nil))
	fmt.Println()

	fmt.Println("Example completed successfully")
}
