//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 100: a proxy tunnel rides over another WarpAm tunnel.
 *
 * A separate tunnel (the proxy only) normally sends its own packets
 * straight out of the physical card. With the box "through a tunnel" the
 * manager writes the name of another tunnel of this program next to the
 * proxy settings, and this file turns that wish into the very mechanism a
 * chain hop already uses: PinEndpointVia. It is set in memory only, the
 * config file of the tunnel is never touched. The socket is then pinned to
 * the adapter of the parent, the endpoint gets a host route there, and the
 * tunnel waits for the parent instead of going out of the card on its own.
 *
 * WarpAm pack 102: the box counts in all three modes, not only in "the proxy
 * only". A tunnel that carries the machine and rides on another one is the
 * same picture as the chain warpam-hop1 -> warpam: its socket is pinned to
 * the parent, its endpoint has a host route there. Two more things are
 * needed for it, and both are here: the parent must not follow the default
 * route (the child takes it, and the parent would then send itself into the
 * child), and the kill switch of the parent must let the child out.
 *
 * WarpAm pack 105: a tunnel that goes through another one always gets the
 * MTU counted here, even when its config has a number of its own. That
 * number is meant for the straight way out and is too big inside another
 * tunnel: the handshake gets through, the big packets are lost. A tunnel
 * that goes straight out keeps its config as it is. A hidden hop of a chain
 * is never a parent: the chain looks after it.
 */

package tunnel

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainViaEntry is the part of a settings record this file cares about.
type chainViaEntry struct {
	Proxy          bool
	ProxySplit     bool
	ProxyVia       bool
	ProxyViaTunnel string
}

// parent is the tunnel this record rides on, or an empty string. Pack 102:
// the mode of the tunnel no longer matters.
func (e chainViaEntry) parent() string {
	if !e.ProxyVia {
		return ""
	}
	return strings.TrimSpace(e.ProxyViaTunnel)
}

// chainViaIsParent answers whether any tunnel is set to ride on name.
func chainViaIsParent(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return false
	}
	for tunnel, entry := range chainViaBook() {
		if strings.EqualFold(strings.TrimSpace(tunnel), name) {
			continue
		}
		if strings.EqualFold(entry.parent(), name) {
			return true
		}
	}
	return false
}

// chainViaRidesOn answers whether child is set to ride on parent.
func chainViaRidesOn(child, parent string) bool {
	parent = strings.TrimSpace(parent)
	if len(parent) == 0 {
		return false
	}
	return strings.EqualFold(chainViaParentIn(chainViaBook(), strings.TrimSpace(child)), parent)
}

// chainViaBook reads the settings book of the manager. A missing or broken
// file means no tunnel rides on another one.
func chainViaBook() map[string]chainViaEntry {
	raw, err := os.ReadFile(chainSplitSettingsPath())
	if err != nil {
		return nil
	}
	var book struct {
		Tunnels map[string]chainViaEntry
	}
	if json.Unmarshal(raw, &book) != nil {
		return nil
	}
	return book.Tunnels
}

// chainViaParentIn finds the parent of one tunnel in the book.
func chainViaParentIn(book map[string]chainViaEntry, name string) string {
	for tunnel, entry := range book {
		if strings.EqualFold(strings.TrimSpace(tunnel), name) {
			return entry.parent()
		}
	}
	return ""
}

// chainViaCountMTU (WarpAm pack 105) gives the MTU of a tunnel that goes
// through a tunnel with parentMTU: the parent minus the header of this
// tunnel (60 for IPv4, 80 for IPv6) and its junk S4.
func chainViaCountMTU(parentMTU int, config *conf.Config) int {
	overhead := 60
	if len(config.Peers) != 0 {
		if ip := net.ParseIP(strings.Trim(config.Peers[0].Endpoint.Host, "[]")); ip != nil && ip.To4() == nil {
			overhead = 80
		}
	}
	mtu := parentMTU - overhead - int(config.Interface.TransportPacketJunkSize)
	// WarpAm pack 103: 1280 is the floor of IPv6 only, and the IPv6 side of
	// the interface is raised to it on its own. For IPv4 that floor made the
	// packets bigger than the lower tunnel carries, so the real number is
	// kept, down to 576.
	const chainViaMTUFloor = 576
	if mtu < chainViaMTUFloor {
		mtu = chainViaMTUFloor
	}
	return mtu
}

// chainViaCarryMTU (WarpAm pack 105) gives the MTU the tunnel name really
// runs with: the number of its config, or the default, when it goes
// straight out; the counted one when it goes through a tunnel itself.
func chainViaCarryMTU(book map[string]chainViaEntry, name string, depth int) int {
	c, err := conf.LoadFromName(name)
	if err != nil {
		return conf.ChainHop1MTU
	}
	up := chainViaParentIn(book, name)
	if len(up) == 0 || depth >= chainSplitMaxDepth || conf.ChainIsHiddenHopName(up) || chainViaLoops(book, name, up) {
		if c.Interface.MTU != 0 {
			return int(c.Interface.MTU)
		}
		return conf.ChainHop1MTU
	}
	return chainViaCountMTU(chainViaCarryMTU(book, up, depth+1), c)
}

// chainViaLoops answers whether going up from parent ever comes back to
// name: through the box of this pack or through PinEndpointVia of a hop.
func chainViaLoops(book map[string]chainViaEntry, name, parent string) bool {
	hop := parent
	for i := 0; i < chainSplitMaxDepth && len(hop) != 0; i++ {
		if strings.EqualFold(hop, name) {
			return true
		}
		next := chainViaParentIn(book, hop)
		if len(next) == 0 {
			if c, err := conf.LoadFromName(hop); err == nil {
				next = strings.TrimSpace(c.Interface.PinEndpointVia)
			}
		}
		hop = next
	}
	return len(hop) != 0
}

// chainProxyViaApply is called once, right after the config is read. A hop
// of a chain already has its PinEndpointVia and is left alone.
func chainProxyViaApply(config *conf.Config) {
	if config == nil || len(strings.TrimSpace(config.Interface.PinEndpointVia)) != 0 {
		return
	}
	name := strings.TrimSpace(config.Name)
	book := chainViaBook()
	parent := chainViaParentIn(book, name)
	if len(parent) == 0 {
		return
	}
	if chainViaLoops(book, name, parent) {
		log.Printf("[WarpAm] %s: the tunnel %s leads back to this one, the box \"through a tunnel\" is ignored", name, parent)
		return
	}
	if conf.ChainIsHiddenHopName(parent) {
		log.Printf("[WarpAm] %s: %s is the hidden hop of a chain, no tunnel may go through it, the box \"through a tunnel\" is ignored", name, parent)
		return
	}

	config.Interface.PinEndpointVia = parent

	// WarpAm pack 105: the MTU the parent really runs with, counted the
	// same way when the parent goes through a tunnel itself.
	parentMTU := chainViaCarryMTU(book, parent, 0)
	var parentPeers []conf.Peer
	if pc, err := conf.LoadFromName(parent); err == nil {
		parentPeers = pc.Peers
	} else {
		log.Printf("[WarpAm] %s: no config of %s was found: %v", name, parent, err)
	}

	var endpoint net.IP
	if len(config.Peers) != 0 {
		endpoint = net.ParseIP(strings.Trim(config.Peers[0].Endpoint.Host, "[]"))
	}

	// WarpAm pack 105: always counted, the number of the config is not kept.
	written := config.Interface.MTU
	config.Interface.MTU = uint16(chainViaCountMTU(parentMTU, config))
	if written != 0 && written != config.Interface.MTU {
		log.Printf("[WarpAm] %s: MTU %d of the config is replaced by %d inside %s (the config file is not changed)", name, written, config.Interface.MTU, parent)
	}

	if endpoint != nil && parentPeers != nil {
		covered := false
		for _, peer := range parentPeers {
			for _, a := range peer.AllowedIPs {
				if n := a.IPNet(); n.Contains(endpoint) {
					covered = true
				}
			}
		}
		if !covered {
			log.Printf("[WarpAm] Warning: AllowedIPs of %s do not cover %s, the handshake of %s will not get through", parent, endpoint, name)
		}
	}

	log.Printf("[WarpAm] %s goes through %s, MTU %d", name, parent, config.Interface.MTU)
}
