//go:build windows

/* AwgChain - patch 6, part 1.
 *
 * Everything the manager needs to know about chains lives here, in a file of
 * its own, so that no upstream file has to grow chain logic. The three call
 * sites in the upstream code are one-liners added by patch6.ps1.
 *
 * A hop is recognised by the PinEndpointVia field that patch 1 added to the
 * [Interface] section. Two hops belong to the same chain when one of them
 * pins its endpoint through the other:
 *
 *     hop2-amnezia:  PinEndpointVia = hop1-warp
 *     hop1-warp:     PinEndpointVia = Ethernet
 *
 * That is a deliberate, narrow rule. Two unrelated tunnels that happen to
 * overlap are still treated exactly as upstream treats them.
 */

package manager

import (
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// isChainHop reports whether this config is a hop of a chain.
func isChainHop(c *conf.Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Interface.PinEndpointVia) != ""
}

// chainSiblings reports whether the two configs are hops of one chain, in
// which case their overlapping AllowedIPs are intentional and neither may be
// stopped on account of the other.
func chainSiblings(a, b *conf.Config) bool {
	if !isChainHop(a) || !isChainHop(b) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(a.Interface.PinEndpointVia), strings.TrimSpace(b.Name)) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(b.Interface.PinEndpointVia), strings.TrimSpace(a.Name)) {
		return true
	}
	return false
}

// chainHopByName is the same question asked with only a tunnel name in hand.
// A missing or unreadable config answers no.
func chainHopByName(name string) bool {
	c, err := conf.LoadFromName(name)
	if err != nil {
		return false
	}
	return isChainHop(c)
}
