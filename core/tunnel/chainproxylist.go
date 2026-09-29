//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 82: who is carrying a proxy right now.
 *
 * The kill switch of an ordinary tunnel has to know which tunnels serve a
 * local proxy and are up, so that it can leave them their way out. The
 * answer is gathered here, in the tunnel service itself: the settings book
 * says which tunnels are marked, their configuration files say where their
 * servers are, and the machine says which of their adapters exist and are
 * up. A tunnel that is not up is not in the list, so no door is cut for it.
 *
 * The list is gathered again whenever an adapter appears or changes, which
 * is exactly when a proxy tunnel is raised beside us, and the doors that
 * are new are then cut into the running rule set.
 */

package tunnel

import (
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainProxyTunnelsUp lists every tunnel that carries a local proxy only,
// has an adapter that is up, and is not the tunnel asking. The endpoint of
// its first peer is the address it has to reach.
func chainProxyTunnelsUp(exclude string) []firewall.ChainProxyTunnel {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil
	}
	list := make([]firewall.ChainProxyTunnel, 0, 2)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if len(name) == 0 || strings.EqualFold(name, strings.TrimSpace(exclude)) {
			continue
		}
		if !ChainTunnelIsSeparate(name) {
			continue
		}
		iface, err := findInterfaceByName(name)
		if err != nil || iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		c, err := conf.LoadFromName(name)
		if err != nil {
			continue
		}
		hole := firewall.ChainProxyTunnel{Name: name, LUID: uint64(iface.LUID)}
		// Pack 84: the resolvers of that tunnel travel with the door. Port
		// 53 is closed for the whole machine while the kill switch is on,
		// so without this the proxy of that tunnel could open an address
		// but never a name.
		for _, server := range c.Interface.DNS {
			if server == nil || server.To4() == nil {
				continue
			}
			hole.DNSServers = append(hole.DNSServers, server.To4())
		}
		for i := range c.Peers {
			endpoint := c.Peers[i].Endpoint
			if endpoint.IsEmpty() || endpoint.Port == 0 {
				continue
			}
			host := strings.Trim(strings.TrimSpace(endpoint.Host), "[]")
			ip := net.ParseIP(host)
			if ip == nil {
				resolved, err := net.LookupIP(host)
				if err != nil || len(resolved) == 0 {
					continue
				}
				ip = resolved[0]
			}
			if ip.To4() == nil {
				continue
			}
			hole.Endpoint = ip.To4()
			hole.Port = endpoint.Port
			break
		}
		list = append(list, hole)
	}
	return list
}

// chainProxyDoorsMu keeps the watcher below from running twice at once.
var chainProxyDoorsMu sync.Mutex

// chainProxyDoorsRefresh cuts the doors of every proxy tunnel that is up now
// into the rule set that is already running. Doors that are there already
// cost nothing.
func chainProxyDoorsRefresh(exclude string) {
	chainProxyDoorsMu.Lock()
	defer chainProxyDoorsMu.Unlock()
	list := chainProxyTunnelsUp(exclude)
	if len(list) == 0 {
		return
	}
	if err := firewall.ChainPermitProxyTunnelsNow(list); err != nil {
		log.Printf("Firewall: could not make room for the proxy tunnels: %v", err)
	}
}

// chainProxyDoorsWatch follows the machine for as long as this tunnel lives,
// so that a proxy tunnel raised after us is let out too. The callback is
// returned and has to be unregistered by the caller.
func chainProxyDoorsWatch(exclude string) (*winipcfg.InterfaceChangeCallback, error) {
	callback, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibDeleteInstance {
			return
		}
		if iface != nil && iface.Family != windows.AF_INET {
			return
		}
		go chainProxyDoorsRefresh(exclude)
	})
	if err != nil {
		return nil, err
	}
	return callback, nil
}
