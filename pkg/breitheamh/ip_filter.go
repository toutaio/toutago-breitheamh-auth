package breitheamh

import (
	"net"
	"sync"
)

// IPFilter manages IP whitelisting and blacklisting
type IPFilter struct {
	whitelist map[string]bool
	blacklist map[string]bool
	mu        sync.RWMutex
	mode      IPFilterMode
}

// IPFilterMode defines the filtering strategy
type IPFilterMode int

const (
	// IPFilterModePermissive allows all IPs except those blacklisted
	IPFilterModePermissive IPFilterMode = iota
	// IPFilterModeRestrictive only allows whitelisted IPs
	IPFilterModeRestrictive
)

// NewIPFilter creates a new IP filter
func NewIPFilter(mode IPFilterMode) *IPFilter {
	return &IPFilter{
		whitelist: make(map[string]bool),
		blacklist: make(map[string]bool),
		mode:      mode,
	}
}

// AddToWhitelist adds an IP or CIDR range to the whitelist
func (f *IPFilter) AddToWhitelist(ipOrCIDR string) error {
	if _, _, err := net.ParseCIDR(ipOrCIDR); err == nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.whitelist[ipOrCIDR] = true
		return nil
	}

	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.whitelist[ipOrCIDR] = true
		return nil
	}

	return &net.ParseError{Type: "IP address or CIDR", Text: ipOrCIDR}
}

// AddToBlacklist adds an IP or CIDR range to the blacklist
func (f *IPFilter) AddToBlacklist(ipOrCIDR string) error {
	if _, _, err := net.ParseCIDR(ipOrCIDR); err == nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.blacklist[ipOrCIDR] = true
		return nil
	}

	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.blacklist[ipOrCIDR] = true
		return nil
	}

	return &net.ParseError{Type: "IP address or CIDR", Text: ipOrCIDR}
}

// RemoveFromWhitelist removes an IP or CIDR from the whitelist
func (f *IPFilter) RemoveFromWhitelist(ipOrCIDR string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.whitelist, ipOrCIDR)
}

// RemoveFromBlacklist removes an IP or CIDR from the blacklist
func (f *IPFilter) RemoveFromBlacklist(ipOrCIDR string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blacklist, ipOrCIDR)
}

// IsAllowed checks if an IP is allowed based on the filter rules
func (f *IPFilter) IsAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check blacklist first
	if f.isInList(ip, f.blacklist) {
		return false
	}

	// In restrictive mode, IP must be whitelisted
	if f.mode == IPFilterModeRestrictive {
		return f.isInList(ip, f.whitelist)
	}

	// In permissive mode, allow if not blacklisted
	return true
}

func (f *IPFilter) isInList(ip net.IP, list map[string]bool) bool {
	ipStr := ip.String()
	if list[ipStr] {
		return true
	}

	for cidr := range list {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// SetMode changes the filter mode
func (f *IPFilter) SetMode(mode IPFilterMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
}

// ClearWhitelist removes all entries from the whitelist
func (f *IPFilter) ClearWhitelist() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.whitelist = make(map[string]bool)
}

// ClearBlacklist removes all entries from the blacklist
func (f *IPFilter) ClearBlacklist() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blacklist = make(map[string]bool)
}
