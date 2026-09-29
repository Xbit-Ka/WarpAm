//go:build windows

/* AwgChain pack 85: what a chain knows about resolvers and about the
 * addresses a hop has to be allowed to carry.
 *
 * An Amnezia server runs its own resolver in a docker network of its own and
 * gives it the fixed address 172.29.172.254. That container is attached to
 * the network of the protocol container, so the resolver answers only to
 * packets that are already inside the tunnel. The client that writes the
 * config also drops the secondary resolver whenever that address is the
 * primary one, so such a config carries exactly one resolver and it is
 * unreachable until the hop has handshaken.
 *
 * Until this pack the chain took that line as it was and handed it to the
 * system the moment the adapter appeared. When the inner hop never handshook,
 * as on 26 September, the whole machine lost names: every Endpoint written as
 * a host name could no longer be resolved, so tunnels that had nothing to do
 * with the chain stopped connecting too, while a config with a bare address
 * kept working. Hence the three things below: know such a resolver, keep a
 * reachable one next to it, and make sure the hop is actually allowed to
 * carry the resolver address.
 */

package conf

import (
	"log"
	"net"
	"strings"
)

// ChainAmneziaDNS is the in-tunnel resolver of an Amnezia server.
const ChainAmneziaDNS = "172.29.172.254"

// ChainFallbackDNS is the pair used when a config has no resolver of its own,
// and now also the resolver added next to an in-tunnel one so that names keep
// working while the hop is not up yet.
func ChainFallbackDNS() []net.IP {
	return []net.IP{net.IPv4(1, 1, 1, 1).To4(), net.IPv4(1, 0, 0, 1).To4()}
}

// ChainDNSIsAmnezia reports whether an address is the AmneziaDNS container.
func ChainDNSIsAmnezia(server net.IP) bool {
	if server == nil {
		return false
	}
	return server.Equal(net.ParseIP(ChainAmneziaDNS))
}

// ChainDNSIsInTunnel reports whether a resolver can only be reached from
// inside this hop: the AmneziaDNS address, or an address that the hop claims
// with a prefix of its own. The two default halves are not a claim of that
// kind: they cover the whole internet and say nothing about the resolver.
func ChainDNSIsInTunnel(server net.IP, hop *Config) bool {
	if server == nil {
		return false
	}
	if ChainDNSIsAmnezia(server) {
		return true
	}
	if hop == nil {
		return false
	}
	for _, addr := range hop.Interface.Addresses {
		if addr.IP == nil {
			continue
		}
		network := addr.IPNet()
		if addr.Cidr != 0 && network.Contains(server) {
			return true
		}
	}
	for i := range hop.Peers {
		for _, allowed := range hop.Peers[i].AllowedIPs {
			if allowed.IP == nil || allowed.Cidr <= 1 {
				continue
			}
			network := allowed.IPNet()
			if network.Contains(server) {
				return true
			}
		}
	}
	return false
}

// ChainDNSWithFallback returns the resolver list to write into a hop: the
// resolvers of the config first, and a reachable pair behind them when the
// first resolver lives inside the tunnel. Windows asks the first one and only
// falls to the next after a timeout, so the order is what keeps the config
// resolver in charge while the chain is whole.
func ChainDNSWithFallback(servers []net.IP, hop *Config) []net.IP {
	if len(servers) == 0 {
		return ChainFallbackDNS()
	}
	out := append([]net.IP(nil), servers...)
	if !ChainDNSIsInTunnel(servers[0], hop) {
		return out
	}
	for _, fallback := range ChainFallbackDNS() {
		have := false
		for _, already := range out {
			if already.Equal(fallback) {
				have = true
				break
			}
		}
		if !have {
			out = append(out, fallback)
		}
	}
	log.Printf("Chain DNS: %s is reachable only inside the tunnel, so %s is kept behind it", servers[0].String(), out[len(out)-1].String())
	return out
}

// ChainAllowedCovers reports whether a set of AllowedIPs already carries an
// address.
func ChainAllowedCovers(allowed []IPCidr, ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, entry := range allowed {
		if entry.IP == nil {
			continue
		}
		if (entry.IP.To4() == nil) != (ip.To4() == nil) {
			continue
		}
		network := entry.IPNet()
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ChainHostPrefix turns an address into a prefix of one host.
func ChainHostPrefix(ip net.IP) IPCidr {
	if four := ip.To4(); four != nil {
		return IPCidr{IP: four, Cidr: 32}
	}
	return IPCidr{IP: ip.To16(), Cidr: 128}
}

// ChainEndpointIPs collects the endpoint addresses of a config. A host name is
// resolved here, while the machine still has working names, because the
// address is needed in AllowedIPs before the chain is raised.
func ChainEndpointIPs(c *Config) []net.IP {
	if c == nil {
		return nil
	}
	out := make([]net.IP, 0, len(c.Peers))
	for i := range c.Peers {
		endpoint := c.Peers[i].Endpoint
		if endpoint.IsEmpty() {
			continue
		}
		host := strings.Trim(strings.TrimSpace(endpoint.Host), "[]")
		if ip := net.ParseIP(host); ip != nil {
			out = append(out, ip)
			continue
		}
		resolved, err := net.LookupIP(host)
		if err != nil {
			log.Printf("Chain build: cannot resolve %q, so it is not added to AllowedIPs: %v", host, err)
			continue
		}
		out = append(out, resolved...)
	}
	return out
}

// ChainEnsureAllowed adds a host prefix for every address that no peer carries
// yet. The first peer is the one that gets them: a chain hop has one peer in
// every configuration seen so far, and a wrong guess here would send the
// packets to a peer that cannot answer.
func ChainEnsureAllowed(peers []Peer, ips []net.IP, why string) {
	if len(peers) == 0 {
		return
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		covered := false
		for i := range peers {
			if ChainAllowedCovers(peers[i].AllowedIPs, ip) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		prefix := ChainHostPrefix(ip)
		peers[0].AllowedIPs = append(peers[0].AllowedIPs, prefix)
		log.Printf("Chain build: %s was added to AllowedIPs (%s)", prefix.String(), why)
	}
}
