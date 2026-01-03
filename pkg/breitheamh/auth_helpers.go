package breitheamh

import "context"

// authenticateWithPassword is a shared helper for password-based authentication
func authenticateWithPassword(
	ctx context.Context,
	provider UserProvider,
	hasher *Hasher,
	email, password string,
) (User, error) {
	// Find user by credentials
	user, err := provider.FindByCredentials(ctx, map[string]interface{}{
		"email": email,
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check if account is locked
	if baseUser, ok := user.(*BaseUser); ok {
		if baseUser.IsLocked() {
			return nil, ErrAccountLocked
		}
	}

	// Verify password
	err = hasher.Verify(password, user.GetPassword())
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
