//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 81: the kill switch lets the proxy tunnels through.
 *
 * This is variant A of the question asked after the log of 25 September.
 * A chain arms its kill switch and only the adapters of that chain may
 * talk to the world. A tunnel that carries nothing but its local proxy is
 * a tunnel the user raised on purpose, standing beside the chain exactly
 * as pack 80 allows, and its packets were dropped without a word: the
 * proxy went on listening, went on accepting connections and delivered
 * nothing.
 *
 * So the lock is told about those tunnels. Each of them gets two
 * permissions and no more: its own encrypted packets may leave for its own
 * server, and its own adapter may be used. The rest of the machine stays
 * shut, which is the whole reason the lock exists.
 *
 * The holes are not fixed for ever. A proxy tunnel can be raised or
 * stopped while the chain is up, so the list is signed and the signature
 * is kept next to the lock. The watch asks to arm the lock on every
 * healthy round; when the signature has moved, the lock is rebuilt with
 * the new holes, which takes a fraction of a second.
 */

package manager

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
)

// chainLockProxyTunnels lists the proxy only tunnels that are up right now
// and do not belong to this chain.
func chainLockProxyTunnels(leaf string) []firewall.ChainProxyTunnel {
	branch := chainOwnBranch(leaf)

	trackedTunnelsLock.Lock()
	names := make([]string, 0, len(trackedTunnels))
	for name, state := range trackedTunnels {
		if state == TunnelStarted {
			names = append(names, name)
		}
	}
	trackedTunnelsLock.Unlock()
	sort.Strings(names)

	out := make([]firewall.ChainProxyTunnel, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if len(name) == 0 || chainInOwnBranch(branch, name) {
			continue
		}
		if !chainLeafIsSeparate(name) {
			continue
		}
		luid, ok := chainAdapterLUID(name)
		if !ok {
			continue
		}
		text, err := chainEndpointOf(name)
		if err != nil {
			log.Printf("[WarpAm] The kill switch cannot read the endpoint of the proxy tunnel %s (%v), so that tunnel gets no way out while the lock is armed", name, err)
			continue
		}
		ip, port, ok := chainParseEndpoint(text)
		if !ok {
			log.Printf("[WarpAm] The kill switch does not understand the endpoint %q of the proxy tunnel %s", text, name)
			continue
		}
		if ip.To4() == nil {
			log.Printf("[WarpAm] The proxy tunnel %s reaches its server over IPv6, which the kill switch cannot let through yet", name)
			continue
		}
		// Pack 84: the third permission. Port 53 stays shut for the whole
		// machine while the lock is armed, and the door of the chain is
		// bound to the adapter of the chain, so a proxy tunnel beside it
		// could reach its server and any address in the world but could
		// not resolve one single name. Its own resolvers, through its own
		// adapter, are let through too.
		dns := chainProxyDNSServers(name)
		if len(dns) == 0 {
			log.Printf("[WarpAm] The proxy tunnel %s has no IPv4 DNS server of its own, so its proxy will only be able to open addresses, not names", name)
		}
		out = append(out, firewall.ChainProxyTunnel{
			Name:       name,
			Endpoint:   ip,
			Port:       port,
			LUID:       uint64(luid),
			DNSServers: dns,
		})
	}
	return out
}

// chainLockHolesSignature writes the list down as one line, so that two
// lists can be compared without looking at them.
func chainLockHolesSignature(holes []firewall.ChainProxyTunnel) string {
	if len(holes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(holes))
	for i := range holes {
		// Pack 84: the resolvers belong to the signature as well, so that
		// a tunnel whose DNS line was edited makes the lock be rebuilt.
		parts = append(parts, fmt.Sprintf("%s@%s:%d/%d+%s", holes[i].Name, holes[i].Endpoint, holes[i].Port, holes[i].LUID, chainLockHolesDNS(holes[i].DNSServers)))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// chainLockHolesDNS writes the resolvers of one hole as one string.
func chainLockHolesDNS(servers []net.IP) string {
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

// chainLockHolesLine is the same list as plain names, for the log.
func chainLockHolesLine(holes []firewall.ChainProxyTunnel) string {
	if len(holes) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(holes))
	for i := range holes {
		parts = append(parts, holes[i].Name)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
