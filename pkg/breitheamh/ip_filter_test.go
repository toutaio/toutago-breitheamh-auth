package breitheamh

import (
	"testing"
)

func TestIPFilter(t *testing.T) {
	t.Run("permissive mode allows all by default", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		if !filter.IsAllowed("192.168.1.1") {
			t.Error("permissive mode should allow all IPs by default")
		}
	})

	t.Run("restrictive mode denies all by default", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		if filter.IsAllowed("192.168.1.1") {
			t.Error("restrictive mode should deny all IPs by default")
		}
	})

	t.Run("blacklist blocks IPs in permissive mode", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		if err := filter.AddToBlacklist("192.168.1.100"); err != nil {
			t.Fatalf("failed to add to blacklist: %v", err)
		}

		if filter.IsAllowed("192.168.1.100") {
			t.Error("blacklisted IP should be blocked")
		}

		if !filter.IsAllowed("192.168.1.101") {
			t.Error("non-blacklisted IP should be allowed")
		}
	})

	t.Run("whitelist allows IPs in restrictive mode", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		if err := filter.AddToWhitelist("10.0.0.5"); err != nil {
			t.Fatalf("failed to add to whitelist: %v", err)
		}

		if !filter.IsAllowed("10.0.0.5") {
			t.Error("whitelisted IP should be allowed")
		}

		if filter.IsAllowed("10.0.0.6") {
			t.Error("non-whitelisted IP should be blocked in restrictive mode")
		}
	})

	t.Run("CIDR range blacklisting", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		if err := filter.AddToBlacklist("192.168.1.0/24"); err != nil {
			t.Fatalf("failed to add CIDR to blacklist: %v", err)
		}

		if filter.IsAllowed("192.168.1.50") {
			t.Error("IP in blacklisted CIDR range should be blocked")
		}

		if !filter.IsAllowed("192.168.2.50") {
			t.Error("IP outside blacklisted CIDR range should be allowed")
		}
	})

	t.Run("CIDR range whitelisting", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		if err := filter.AddToWhitelist("10.0.0.0/16"); err != nil {
			t.Fatalf("failed to add CIDR to whitelist: %v", err)
		}

		if !filter.IsAllowed("10.0.5.100") {
			t.Error("IP in whitelisted CIDR range should be allowed")
		}

		if filter.IsAllowed("11.0.0.1") {
			t.Error("IP outside whitelisted CIDR range should be blocked")
		}
	})

	t.Run("blacklist takes precedence over whitelist", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		filter.AddToWhitelist("192.168.1.100")
		filter.AddToBlacklist("192.168.1.100")

		if filter.IsAllowed("192.168.1.100") {
			t.Error("blacklist should take precedence over whitelist")
		}
	})

	t.Run("remove from whitelist", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		filter.AddToWhitelist("10.0.0.5")
		filter.RemoveFromWhitelist("10.0.0.5")

		if filter.IsAllowed("10.0.0.5") {
			t.Error("IP should be blocked after removal from whitelist")
		}
	})

	t.Run("remove from blacklist", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		filter.AddToBlacklist("192.168.1.100")
		filter.RemoveFromBlacklist("192.168.1.100")

		if !filter.IsAllowed("192.168.1.100") {
			t.Error("IP should be allowed after removal from blacklist")
		}
	})

	t.Run("change filter mode", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		if !filter.IsAllowed("192.168.1.1") {
			t.Error("IP should be allowed in permissive mode")
		}

		filter.SetMode(IPFilterModeRestrictive)

		if filter.IsAllowed("192.168.1.1") {
			t.Error("IP should be blocked after switching to restrictive mode")
		}
	})

	t.Run("clear whitelist", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		filter.AddToWhitelist("10.0.0.1")
		filter.AddToWhitelist("10.0.0.2")
		filter.ClearWhitelist()

		if filter.IsAllowed("10.0.0.1") || filter.IsAllowed("10.0.0.2") {
			t.Error("all IPs should be blocked after clearing whitelist")
		}
	})

	t.Run("clear blacklist", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		filter.AddToBlacklist("192.168.1.1")
		filter.AddToBlacklist("192.168.1.2")
		filter.ClearBlacklist()

		if !filter.IsAllowed("192.168.1.1") || !filter.IsAllowed("192.168.1.2") {
			t.Error("all IPs should be allowed after clearing blacklist")
		}
	})

	t.Run("invalid IP returns false", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModePermissive)

		if filter.IsAllowed("not-an-ip") {
			t.Error("invalid IP should return false")
		}
	})

	t.Run("IPv6 support", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		if err := filter.AddToWhitelist("2001:db8::1"); err != nil {
			t.Fatalf("failed to add IPv6 to whitelist: %v", err)
		}

		if !filter.IsAllowed("2001:db8::1") {
			t.Error("whitelisted IPv6 should be allowed")
		}
	})

	t.Run("IPv6 CIDR support", func(t *testing.T) {
		filter := NewIPFilter(IPFilterModeRestrictive)

		if err := filter.AddToWhitelist("2001:db8::/32"); err != nil {
			t.Fatalf("failed to add IPv6 CIDR to whitelist: %v", err)
		}

		if !filter.IsAllowed("2001:db8::100") {
			t.Error("IP in whitelisted IPv6 CIDR should be allowed")
		}
	})
}

func TestIPFilterConcurrency(t *testing.T) {
	filter := NewIPFilter(IPFilterModePermissive)

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				ip := "192.168.1." + string(rune('0'+id))
				filter.AddToBlacklist(ip)
				filter.IsAllowed(ip)
				if j%10 == 0 {
					filter.RemoveFromBlacklist(ip)
				}
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkIPFilterPermissive(b *testing.B) {
	filter := NewIPFilter(IPFilterModePermissive)
	filter.AddToBlacklist("192.168.1.100")

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			filter.IsAllowed("192.168.1." + string(rune('0'+(i%10))))
			i++
		}
	})
}

func BenchmarkIPFilterRestrictive(b *testing.B) {
	filter := NewIPFilter(IPFilterModeRestrictive)
	filter.AddToWhitelist("10.0.0.0/8")

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			filter.IsAllowed("10.0.0." + string(rune('0'+(i%10))))
			i++
		}
	})
}
