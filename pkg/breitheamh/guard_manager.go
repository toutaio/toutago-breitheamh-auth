package breitheamh

import (
	"fmt"
	"sync"
)

// defaultGuardManager is the default implementation of GuardManager.
type defaultGuardManager struct {
	guards      map[string]Guard
	defaultName string
	mu          sync.RWMutex
}

// NewGuardManager creates a new guard manager.
func NewGuardManager() GuardManager {
	return &defaultGuardManager{
		guards: make(map[string]Guard),
	}
}

// Guard returns a guard by name.
func (gm *defaultGuardManager) Guard(name string) Guard {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	guard, ok := gm.guards[name]
	if !ok {
		panic(fmt.Sprintf("guard %s not found", name))
	}

	return guard
}

// RegisterGuard registers a new guard.
func (gm *defaultGuardManager) RegisterGuard(name string, guard Guard) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.guards[name] = guard

	// Set as default if it's the first guard
	if gm.defaultName == "" {
		gm.defaultName = name
	}
}

// DefaultGuard returns the default guard.
func (gm *defaultGuardManager) DefaultGuard() Guard {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	if gm.defaultName == "" {
		panic("no default guard set")
	}

	guard, ok := gm.guards[gm.defaultName]
	if !ok {
		panic(fmt.Sprintf("default guard %s not found", gm.defaultName))
	}

	return guard
}

// SetDefaultGuard sets the default guard.
func (gm *defaultGuardManager) SetDefaultGuard(name string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if _, ok := gm.guards[name]; !ok {
		panic(fmt.Sprintf("cannot set non-existent guard %s as default", name))
	}

	gm.defaultName = name
}
