package breitheamh

import (
	"testing"
	"time"
)

func TestBruteForceProtector(t *testing.T) {
	t.Run("allows attempts under threshold", func(t *testing.T) {
		protector := NewBruteForceProtector(3, time.Minute, time.Hour)
		identifier := "user@example.com"
		
		protector.RecordFailedAttempt(identifier)
		protector.RecordFailedAttempt(identifier)
		
		if protector.IsLocked(identifier) {
			t.Error("user should not be locked with 2 attempts")
		}
		
		if count := protector.GetAttemptCount(identifier); count != 2 {
			t.Errorf("expected 2 attempts, got %d", count)
		}
	})
	
	t.Run("locks account after max attempts", func(t *testing.T) {
		protector := NewBruteForceProtector(3, time.Minute, time.Hour)
		identifier := "user@example.com"
		
		for i := 0; i < 3; i++ {
			protector.RecordFailedAttempt(identifier)
		}
		
		if !protector.IsLocked(identifier) {
			t.Error("user should be locked after 3 attempts")
		}
		
		remaining := protector.GetRemainingLockTime(identifier)
		if remaining <= 0 || remaining > time.Minute {
			t.Errorf("unexpected remaining lock time: %v", remaining)
		}
	})
	
	t.Run("unlocks account after lock duration", func(t *testing.T) {
		protector := NewBruteForceProtector(2, 100*time.Millisecond, time.Hour)
		identifier := "user@example.com"
		
		protector.RecordFailedAttempt(identifier)
		protector.RecordFailedAttempt(identifier)
		
		if !protector.IsLocked(identifier) {
			t.Error("user should be locked")
		}
		
		time.Sleep(150 * time.Millisecond)
		
		if protector.IsLocked(identifier) {
			t.Error("user should be unlocked after lock duration")
		}
	})
	
	t.Run("resets attempts on successful login", func(t *testing.T) {
		protector := NewBruteForceProtector(3, time.Minute, time.Hour)
		identifier := "user@example.com"
		
		protector.RecordFailedAttempt(identifier)
		protector.RecordFailedAttempt(identifier)
		protector.RecordSuccessfulAttempt(identifier)
		
		if count := protector.GetAttemptCount(identifier); count != 0 {
			t.Errorf("expected 0 attempts after successful login, got %d", count)
		}
		
		if protector.IsLocked(identifier) {
			t.Error("user should not be locked after successful login")
		}
	})
	
	t.Run("decays attempts after decay duration", func(t *testing.T) {
		protector := NewBruteForceProtector(3, time.Minute, 100*time.Millisecond)
		identifier := "user@example.com"
		
		protector.RecordFailedAttempt(identifier)
		protector.RecordFailedAttempt(identifier)
		
		time.Sleep(150 * time.Millisecond)
		
		if count := protector.GetAttemptCount(identifier); count != 0 {
			t.Errorf("expected 0 attempts after decay, got %d", count)
		}
		
		protector.RecordFailedAttempt(identifier)
		if count := protector.GetAttemptCount(identifier); count != 1 {
			t.Errorf("expected 1 attempt, got %d", count)
		}
	})
	
	t.Run("reset clears all data", func(t *testing.T) {
		protector := NewBruteForceProtector(2, time.Minute, time.Hour)
		identifier := "user@example.com"
		
		protector.RecordFailedAttempt(identifier)
		protector.RecordFailedAttempt(identifier)
		
		protector.Reset(identifier)
		
		if protector.IsLocked(identifier) {
			t.Error("user should not be locked after reset")
		}
		
		if count := protector.GetAttemptCount(identifier); count != 0 {
			t.Errorf("expected 0 attempts after reset, got %d", count)
		}
	})
	
	t.Run("cleanup removes expired entries", func(t *testing.T) {
		protector := NewBruteForceProtector(2, 50*time.Millisecond, 50*time.Millisecond)
		identifier := "user@example.com"
		
		protector.RecordFailedAttempt(identifier)
		
		time.Sleep(100 * time.Millisecond)
		
		protector.Cleanup()
		
		if count := protector.GetAttemptCount(identifier); count != 0 {
			t.Errorf("expected 0 attempts after cleanup, got %d", count)
		}
	})
}

func TestBruteForceProtectorConcurrency(t *testing.T) {
	protector := NewBruteForceProtector(100, time.Minute, time.Hour)
	identifier := "user@example.com"
	
	done := make(chan bool)
	
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				protector.RecordFailedAttempt(identifier)
				protector.IsLocked(identifier)
				protector.GetAttemptCount(identifier)
			}
			done <- true
		}()
	}
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	if !protector.IsLocked(identifier) {
		t.Error("user should be locked after concurrent attempts")
	}
}
