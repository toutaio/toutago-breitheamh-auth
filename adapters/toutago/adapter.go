package toutago

import (
	"github.com/toutaio/toutago-breitheamh-auth/pkg/breitheamh"
)

// Adapter integrates Breitheamh with the main Toutago framework
type Adapter struct {
	guardManager breitheamh.GuardManager
}

// NewAdapter creates a new Toutago framework adapter
func NewAdapter(guardManager breitheamh.GuardManager) *Adapter {
	return &Adapter{
		guardManager: guardManager,
	}
}

// GuardManager returns the underlying breitheamh guard manager
func (a *Adapter) GuardManager() breitheamh.GuardManager {
	return a.guardManager
}

// Guard returns a guard by name
func (a *Adapter) Guard(name string) breitheamh.Guard {
	return a.guardManager.Guard(name)
}

// DefaultGuard returns the default guard
func (a *Adapter) DefaultGuard() breitheamh.Guard {
	return a.guardManager.DefaultGuard()
}
