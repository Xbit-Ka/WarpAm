/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 82: room for a proxy tunnel inside an ordinary kill switch.
 *
 * Pack 81 taught the chain rule set to leave a door open for every tunnel
 * that carries nothing but its own local proxy. An ordinary tunnel with a
 * 0.0.0.0/0 peer builds a kill switch of its own in blocker.go, and that one
 * knew nothing about such doors: the moment it came up, the handshake of the
 * proxy tunnel was blocked and the proxy went silent although its tunnel
 * still looked up.
 *
 * The permissions are the same two as in the chain rule set, and no wider:
 *
 *   15  the encrypted packets of that tunnel may reach its own server
 *   12  its own adapter may be used
 *
 * The session of blocker.go is dynamic and this package can add filters but
 * not delete single ones, so a door stays open until the tunnel that owns
 * the session goes down and the whole set is built again. What stays behind
 * is the permission to talk to one server address that the user raised a
 * tunnel to a moment ago, which is why this is acceptable; everything else
 * is still blocked.
 */

package firewall

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

// chainProxyHolesMu guards the doors already cut into the running session.
var (
	chainProxyHolesMu   sync.Mutex
	chainProxyHolesDone = make(map[string]bool)
)

// chainProxyHoleKey names a door, so that the same one is not cut twice.
//
// Pack 84: the resolvers are part of the name. A tunnel that is edited to
// ask a different DNS server keeps the same name, endpoint and adapter, and
// with the old key its new resolver would silently stay behind the block.
func chainProxyHoleKey(tunnel ChainProxyTunnel) string {
	endpoint := ""
	if tunnel.Endpoint != nil {
		endpoint = tunnel.Endpoint.String()
	}
	return fmt.Sprintf("%s|%s|%d|%d|%s", strings.ToLower(strings.TrimSpace(tunnel.Name)), endpoint, tunnel.Port, tunnel.LUID, chainProxyHoleDNSText(tunnel.DNSServers))
}

// chainProxyHoleDNSText writes the resolvers of one tunnel as one string.
func chainProxyHoleDNSText(servers []net.IP) string {
	if len(servers) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(servers))
	for _, server := range servers {
		if server == nil {
			continue
		}
		parts = append(parts, server.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// chainProxyHolesForget empties the list of doors. It is called when the
// session they were cut into is gone.
func chainProxyHolesForget() {
	chainProxyHolesMu.Lock()
	chainProxyHolesDone = make(map[string]bool)
	chainProxyHolesMu.Unlock()
}

// chainPermitProxyTunnels cuts the doors into an open session. The caller
// holds the transaction.
func chainPermitProxyTunnels(session uintptr, baseObjects *baseObjects, tunnels []ChainProxyTunnel) error {
	if len(tunnels) == 0 {
		return nil
	}
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))
	appIDs := []*wtFwpByteBlob{appID}

	for _, tunnel := range tunnels {
		key := chainProxyHoleKey(tunnel)
		chainProxyHolesMu.Lock()
		already := chainProxyHolesDone[key]
		chainProxyHolesMu.Unlock()
		if already {
			continue
		}
		name := strings.TrimSpace(tunnel.Name)
		if tunnel.Endpoint != nil && tunnel.Endpoint.To4() != nil && tunnel.Port != 0 {
			err = permitEndpoint(session, baseObjects, 15, appIDs, tunnel.Endpoint, tunnel.Port, 0, "AwgChain proxy tunnel "+name)
			if err != nil {
				return wrapErr(err)
			}
		}
		if tunnel.LUID != 0 {
			err = permitTunInterface(session, baseObjects, 12, tunnel.LUID)
			if err != nil {
				return wrapErr(err)
			}
			// Pack 84: port 53 is closed for the whole machine by the
			// rule set of the ordinary tunnel as well, so a proxy tunnel
			// beside it could open any port but the one it needs to
			// resolve a name. Its own resolvers get a door through its
			// own adapter, and nothing else is opened.
			if len(tunnel.DNSServers) > 0 {
				err = permitChainDNS(session, baseObjects, 14, tunnel.DNSServers, tunnel.LUID)
				if err != nil {
					return wrapErr(err)
				}
			}
		}
		chainProxyHolesMu.Lock()
		chainProxyHolesDone[key] = true
		chainProxyHolesMu.Unlock()
		log.Printf("Firewall: the proxy tunnel %s keeps its way to its server and to its own DNS (%s)", name, chainProxyHoleDNSText(tunnel.DNSServers))
	}
	return nil
}

// ChainPermitProxyTunnelsNow cuts the doors into the session that is already
// running, which is what happens when a proxy tunnel is raised after the
// ordinary tunnel that owns the kill switch. Doors that are already there
// are skipped, so this may be called as often as the machine changes.
func ChainPermitProxyTunnelsNow(tunnels []ChainProxyTunnel) error {
	if len(tunnels) == 0 {
		return nil
	}
	if wfpSession == 0 || wfpBaseObjects == nil {
		return errors.New("The firewall of this tunnel is not enabled")
	}
	baseObjects := wfpBaseObjects
	return runTransaction(wfpSession, func(session uintptr) error {
		return chainPermitProxyTunnels(session, baseObjects, tunnels)
	})
}
