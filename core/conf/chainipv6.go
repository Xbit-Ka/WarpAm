//go:build windows

/* AwgChain - patch 18: IPv6 does not walk around the chain.
 *
 * Until now the inner hop only claimed 0.0.0.0/1 + 128.0.0.0/1, so every
 * IPv6 packet kept using the physical adapter: the provider saw it, and a
 * web page could read the real address over v6 while v4 went through the
 * chain. The kill switch blocked v6 at the firewall, but only while it was
 * armed, and blocking is not routing.
 *
 * Two honest outcomes, decided by the inner hop itself:
 *
 *   the inner hop has an IPv6 address  -> it also claims ::/1 + 8000::/1,
 *                                         v6 rides the chain like v4
 *   the inner hop has no IPv6 address  -> v6 resolvers are dropped from the
 *                                         config and ipv6-lock.ps1 unbinds
 *                                         v6 from the physical adapter
 *
 * Never leave the third state: v6 up on the physical adapter while v4 is in
 * the chain.
 */

package conf

import "net"

// ChainConfigHasIPv6 reports whether this hop can carry IPv6 at all, which is
// true exactly when its Interface section holds a v6 address.
func ChainConfigHasIPv6(c *Config) bool {
	if c == nil {
		return false
	}
	for _, addr := range c.Interface.Addresses {
		if addr.IP != nil && addr.IP.To4() == nil {
			return true
		}
	}
	return false
}

// chainSplitDefaultV6 is the v6 twin of chainSplitDefault: a pair of halves
// beats any ::/0 that another adapter may hold.
func chainSplitDefaultV6() []IPCidr {
	return []IPCidr{
		{IP: net.ParseIP("::"), Cidr: 1},
		{IP: net.ParseIP("8000::"), Cidr: 1},
	}
}

// chainSplitDefaultFor returns the AllowedIPs of the inner hop: both v4
// halves always, both v6 halves when the hop has a v6 address of its own.
func chainSplitDefaultFor(hop *Config) []IPCidr {
	out := chainSplitDefault()
	if ChainConfigHasIPv6(hop) {
		out = append(out, chainSplitDefaultV6()...)
	}
	return out
}

// chainFilterDNS keeps v6 resolvers only when the chain can reach them.
// A v6 resolver on a v4-only chain is a leak when v6 is up and a long
// timeout on every lookup when it is not.
func chainFilterDNS(servers []net.IP, allowV6 bool) []net.IP {
	if allowV6 {
		return servers
	}
	out := make([]net.IP, 0, len(servers))
	for _, ip := range servers {
		if ip == nil {
			continue
		}
		if ip.To4() == nil {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// ChainIPv6Note is what the interface shows about the chain and IPv6.
func ChainIPv6Note(inner *Config) string {
	if ChainConfigHasIPv6(inner) {
		return "IPv6 РёРґС‘С‚ С‡РµСЂРµР· С†РµРїРѕС‡РєСѓ (::/1 + 8000::/1)"
	}
	return "IPv6 Сѓ РІРЅСѓС‚СЂРµРЅРЅРµРіРѕ Р·РІРµРЅР° РЅРµС‚: v6 РЅСѓР¶РЅРѕ РІС‹РєР»СЋС‡РёС‚СЊ (awgchain.bat ipv6on)"
}