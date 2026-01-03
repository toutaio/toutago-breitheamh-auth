package breitheamh

import (
	"testing"
	"time"
)

func TestCSRFTokenManager(t *testing.T) {
	t.Run("generates unique tokens", func(t *testing.T) {
		manager := NewCSRFTokenManager(time.Hour, 32)
		
		token1, err := manager.GenerateToken("session1")
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		
		token2, err := manager.GenerateToken("session2")
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		
		if token1 == token2 {
			t.Error("tokens should be unique")
		}
		
		if len(token1) == 0 || len(token2) == 0 {
			t.Error("tokens should not be empty")
		}
	})
	
	t.Run("validates correct token", func(t *testing.T) {
		manager := NewCSRFTokenManager(time.Hour, 32)
		sessionID := "test-session"
		
		token, err := manager.GenerateToken(sessionID)
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		
		if err := manager.ValidateToken(sessionID, token); err != nil {
			t.Errorf("valid token should pass validation: %v", err)
		}
	})
	
	t.Run("rejects invalid token", func(t *testing.T) {
		manager := NewCSRFTokenManager(time.Hour, 32)
		sessionID := "test-session"
		
		manager.GenerateToken(sessionID)
		
		if err := manager.ValidateToken(sessionID, "invalid-token"); err != ErrInvalidCSRFToken {
			t.Errorf("expected ErrInvalidCSRFToken, got %v", err)
		}
	})
	
	t.Run("rejects token for different session", func(t *testing.T) {
		manager := NewCSRFTokenManager(time.Hour, 32)
		
		token, _ := manager.GenerateToken("session1")
		
		if err := manager.ValidateToken("session2", token); err != ErrInvalidCSRFToken {
			t.Errorf("expected ErrInvalidCSRFToken, got %v", err)
		}
	})
	
	t.Run("rejects expired token", func(t *testing.T) {
		manager := NewCSRFTokenManager(100*time.Millisecond, 32)
		sessionID := "test-session"
		
		token, err := manager.GenerateToken(sessionID)
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		
		time.Sleep(150 * time.Millisecond)
		
		if err := manager.ValidateToken(sessionID, token); err != ErrExpiredCSRFToken {
			t.Errorf("expected ErrExpiredCSRFToken, got %v", err)
		}
	})
	
	t.Run("invalidates token", func(t *testing.T) {
		manager := NewCSRFTokenManager(time.Hour, 32)
		sessionID := "test-session"
		
		token, _ := manager.GenerateToken(sessionID)
		manager.InvalidateToken(sessionID)
		
		if err := manager.ValidateToken(sessionID, token); err != ErrInvalidCSRFToken {
			t.Errorf("expected ErrInvalidCSRFToken after invalidation, got %v", err)
		}
	})
	
	t.Run("refreshes token", func(t *testing.T) {
		manager := NewCSRFTokenManager(time.Hour, 32)
		sessionID := "test-session"
		
		oldToken, _ := manager.GenerateToken(sessionID)
		
		newToken, err := manager.RefreshToken(sessionID)
		if err != nil {
			t.Fatalf("failed to refresh token: %v", err)
		}
		
		if oldToken == newToken {
			t.Error("refreshed token should be different")
		}
		
		if err := manager.ValidateToken(sessionID, oldToken); err != ErrInvalidCSRFToken {
			t.Error("old token should be invalid after refresh")
		}
		
		if err := manager.ValidateToken(sessionID, newToken); err != nil {
			t.Errorf("new token should be valid: %v", err)
		}
	})
	
	t.Run("cleans up expired tokens", func(t *testing.T) {
		manager := NewCSRFTokenManager(50*time.Millisecond, 32)
		
		manager.GenerateToken("session1")
		manager.GenerateToken("session2")
		
		time.Sleep(100 * time.Millisecond)
		
		manager.mu.RLock()
		count := len(manager.tokens)
		manager.mu.RUnlock()
		
		if count != 0 {
			t.Errorf("expected 0 tokens after cleanup, got %d", count)
		}
	})
}

func TestCSRFTokenManagerConcurrency(t *testing.T) {
	manager := NewCSRFTokenManager(time.Hour, 32)
	
	done := make(chan bool)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			sessionID := string(rune('a' + id))
			for j := 0; j < 100; j++ {
				token, _ := manager.GenerateToken(sessionID)
				manager.ValidateToken(sessionID, token)
				if j%10 == 0 {
					manager.InvalidateToken(sessionID)
				}
			}
			done <- true
		}(i)
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkCSRFTokenGeneration(b *testing.B) {
	manager := NewCSRFTokenManager(time.Hour, 32)
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sessionID := string(rune('a' + (i % 26)))
			manager.GenerateToken(sessionID)
			i++
		}
	})
}

func BenchmarkCSRFTokenValidation(b *testing.B) {
	manager := NewCSRFTokenManager(time.Hour, 32)
	tokens := make(map[string]string)
	
	for i := 0; i < 26; i++ {
		sessionID := string(rune('a' + i))
		token, _ := manager.GenerateToken(sessionID)
		tokens[sessionID] = token
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sessionID := string(rune('a' + (i % 26)))
			manager.ValidateToken(sessionID, tokens[sessionID])
			i++
		}
	})
}
