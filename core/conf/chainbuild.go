//go:build windows

/* AwgChain patch 14 - two configs become one tunnel entry.
 *
 * The pair is named after the visible hop:
 *
 *     warpam           the inner hop, the one the user sees and clicks
 *     warpam-hop1      the outer WARP hop, hidden from the list
 *
 * A second pair becomes warpam1 / warpam1-hop1, a third warpam2 and so on.
 * The old names hop2-amnezia / hop1-warp keep working as a legacy pair.
 */

package conf

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	ChainPairBase     = "warpam"
	ChainHiddenSuffix = "-hop1"
	ChainLegacyInner  = "hop2-amnezia"
	ChainLegacyOuter  = "hop1-warp"
	ChainHop1MTU      = 1420
	// ChainHop2MTU is the fixed MTU every inner hop got up to pack 95. It
	// is kept only as a name for that old value: since pack 96 the inner hop
	// gets ChainInnerMTU.
	ChainHop2MTU = 1360
)

// ChainInnerMTU is the MTU of the inner hop of a chain.
//
// Pack 96: a full packet of the inner hop has to fit into the adapter of the
// outer one. On the way it gets an IP header (20 bytes, 40 when the server of
// the inner hop is an IPv6 address), a UDP header (8), the WireGuard data
// header with its tag (32) and the S4 junk of AmneziaWG in front. The fixed
// 1360 did not count S4: with S4 15 a full packet was 1435 bytes against
// 1420 of WARP, and Windows cut every such packet in two inside WARP.
//
// An MTU the config asks for itself is kept when it is smaller. The floor is
// the IPv4 minimum; below 1280 the adapter only loses IPv6, which
// addressconfig.go already handles.
func ChainInnerMTU(inner *Config) uint16 {
	overhead := 60
	for i := range inner.Peers {
		host := strings.Trim(strings.TrimSpace(inner.Peers[i].Endpoint.Host), "[]")
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			overhead = 80
		}
	}
	mtu := ChainHop1MTU - overhead - int(inner.Interface.TransportPacketJunkSize)
	if mtu < 576 {
		mtu = 576
	}
	if own := int(inner.Interface.MTU); own > 0 && own < mtu {
		mtu = own
	}
	return uint16(mtu)
}

// ChainHiddenHopName gives the name of the outer hop that belongs to a
// visible tunnel name.
func ChainHiddenHopName(visible string) string {
	visible = strings.TrimSpace(visible)
	if strings.EqualFold(visible, ChainLegacyInner) {
		return ChainLegacyOuter
	}
	return visible + ChainHiddenSuffix
}

// ChainIsHiddenHopName reports whether a tunnel is the outer hop of a chain,
// which the interface keeps out of the list.
func ChainIsHiddenHopName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasSuffix(lower, ChainHiddenSuffix) || strings.HasPrefix(lower, "hop1-")
}

// ChainNextPairName picks warpam, then warpam1, warpam2 ... avoiding every
// name that is already taken.
func ChainNextPairName(taken []string) string {
	used := make(map[string]bool, len(taken)*2)
	for _, name := range taken {
		used[strings.ToLower(strings.TrimSpace(name))] = true
	}
	free := func(candidate string) bool {
		if used[strings.ToLower(candidate)] {
			return false
		}
		return !used[strings.ToLower(ChainHiddenHopName(candidate))]
	}
	if free(ChainPairBase) {
		return ChainPairBase
	}
	for i := 1; i < 1000; i++ {
		candidate := ChainPairBase + strconv.Itoa(i)
		if free(candidate) {
			return candidate
		}
	}
	return ChainPairBase + "-new"
}

// The address ranges Cloudflare hands out for WARP endpoints.
var chainWarpBlocks = []string{
	"162.159.192.0/19",
	"188.114.96.0/20",
	"8.6.112.0/20",
}

// ChainLooksLikeWarp reports whether a config points at Cloudflare WARP.
func ChainLooksLikeWarp(c *Config) bool {
	if c == nil {
		return false
	}
	for i := range c.Peers {
		host := strings.ToLower(strings.TrimSpace(c.Peers[i].Endpoint.Host))
		if host == "" {
			continue
		}
		if strings.Contains(host, "cloudflare") {
			return true
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			continue
		}
		for _, block := range chainWarpBlocks {
			_, network, err := net.ParseCIDR(block)
			if err == nil && network.Contains(ip) {
				return true
			}
		}
	}
	// WARP always hands out an address out of 172.16.0.0/12.
	for _, addr := range c.Interface.Addresses {
		four := addr.IP.To4()
		if four != nil && four[0] == 172 && four[1] >= 16 && four[1] <= 31 {
			return true
		}
	}
	return false
}

// ChainSortRoles decides which of two configs is the outer WARP hop.
func ChainSortRoles(a, b *Config) (warp *Config, inner *Config, err error) {
	if a == nil || b == nil {
		return nil, nil, errors.New("нужны два файла конфигурации")
	}
	aWarp := ChainLooksLikeWarp(a)
	bWarp := ChainLooksLikeWarp(b)
	switch {
	case aWarp && !bWarp:
		return a, b, nil
	case bWarp && !aWarp:
		return b, a, nil
	case aWarp && bWarp:
		return nil, nil, errors.New("оба файла похожи на конфиги WARP, внутреннего хопа нет")
	}
	return nil, nil, errors.New("ни один файл не похож на конфиг Cloudflare WARP")
}

// ChainBuild returns the two hop configs of a chain named pairName.
func ChainBuild(warp, inner *Config, outerAlias string, pairName string) (*Config, *Config, error) {
	if warp == nil || inner == nil {
		return nil, nil, errors.New("нужны два файла конфигурации")
	}
	outerAlias = strings.TrimSpace(outerAlias)
	if outerAlias == "" {
		return nil, nil, errors.New("не удалось определить адаптер с выходом в интернет")
	}
	pairName = strings.TrimSpace(pairName)
	if !TunnelNameIsValid(pairName) {
		return nil, nil, errors.New("имя цепочки не подходит: " + pairName)
	}
	hiddenName := ChainHiddenHopName(pairName)
	if !TunnelNameIsValid(hiddenName) {
		return nil, nil, errors.New("имя внешнего хопа не подходит: " + hiddenName)
	}
	if !chainHasEndpoint(warp) {
		return nil, nil, errors.New("в конфиге WARP нет строки Endpoint")
	}
	if !chainHasEndpoint(inner) {
		return nil, nil, errors.New("в конфиге Amnezia нет строки Endpoint")
	}

	hop1 := *warp
	hop1.Name = hiddenName
	hop1.Interface.Addresses = append([]IPCidr(nil), warp.Interface.Addresses...)
	hop1.Interface.TableOff = true
	hop1.Interface.PinEndpointVia = outerAlias
	hop1.Interface.MTU = ChainHop1MTU
	hop1.Interface.DNS = nil
	hop1.Interface.DNSSearch = nil
	hop1.Peers = chainCopyPeers(warp.Peers)
	// Pack 85: the outer hop has to be allowed to carry the endpoint of the
	// inner one. A WARP config claims 0.0.0.0/0, so nothing changed there,
	// but with a narrower AllowedIPs the handshake of the inner hop had no
	// way out: the outer hop handshook, carried nothing, and the whole chain
	// was rebuilt every 46 seconds, which is what the log of 26 September
	// shows for 8 minutes straight.
	ChainEnsureAllowed(hop1.Peers, ChainEndpointIPs(inner), "endpoint of the inner hop")

	hop2 := *inner
	hop2.Name = pairName
	hop2.Interface.Addresses = append([]IPCidr(nil), inner.Interface.Addresses...)
	hop2.Interface.TableOff = false
	hop2.Interface.PinEndpointVia = hiddenName
	hop2.Interface.MTU = ChainInnerMTU(inner)
	hop2.Interface.DNS = append([]net.IP(nil), inner.Interface.DNS...)
	hop2.Interface.DNSSearch = append([]string(nil), inner.Interface.DNSSearch...)
	hop2.Interface.DNS = chainFilterDNS(hop2.Interface.DNS, ChainConfigHasIPv6(&hop2))
	hop2.Peers = chainCopyPeers(inner.Peers)
	for i := range hop2.Peers {
		if chainCoversEverything(hop2.Peers[i].AllowedIPs) {
			hop2.Peers[i].AllowedIPs = chainSplitDefaultFor(&hop2)
		}
	}
	// Pack 85: two things about resolvers, both learned on 26 September.
	//
	// A resolver that lives inside the tunnel, such as the AmneziaDNS
	// container at 172.29.172.254, keeps a reachable pair behind it, because
	// otherwise the machine loses names for as long as the hop is not up, and
	// every Endpoint written as a host name stops resolving, including the
	// ones of tunnels that have nothing to do with this chain.
	//
	// And every resolver of the hop is carried by the hop: the old code only
	// replaced a default route with the two halves, so a config with a narrow
	// AllowedIPs had no route to its own resolver at all. Cloudflare used to
	// be substituted only when the DNS line was empty, which is why a config
	// with one unreachable resolver had no second chance.
	hop2.Interface.DNS = ChainDNSWithFallback(hop2.Interface.DNS, &hop2)
	ChainEnsureAllowed(hop2.Peers, hop2.Interface.DNS, "resolver of the inner hop")

	return &hop1, &hop2, nil
}

func chainHasEndpoint(c *Config) bool {
	for i := range c.Peers {
		if !c.Peers[i].Endpoint.IsEmpty() {
			return true
		}
	}
	return false
}

func chainCopyPeers(peers []Peer) []Peer {
	out := make([]Peer, len(peers))
	for i := range peers {
		out[i] = peers[i]
		out[i].AllowedIPs = append([]IPCidr(nil), peers[i].AllowedIPs...)
		out[i].RxBytes = 0
		out[i].TxBytes = 0
		out[i].LastHandshakeTime = 0
		keepalive := strings.TrimSpace(out[i].PersistentKeepalive)
		if keepalive == "" || keepalive == "0" || keepalive == "off" {
			out[i].PersistentKeepalive = "25"
		}
	}
	return out
}

func chainCoversEverything(ips []IPCidr) bool {
	for _, a := range ips {
		if a.Cidr == 0 && a.IP != nil && a.IP.IsUnspecified() {
			return true
		}
	}
	return false
}

// A pair of halves beats a single default route on every routing table, which
// is how the inner hop takes the traffic away from the outer one.
func chainSplitDefault() []IPCidr {
	return []IPCidr{
		{IP: net.IPv4(0, 0, 0, 0).To4(), Cidr: 1},
		{IP: net.IPv4(128, 0, 0, 0).To4(), Cidr: 1},
	}
}

// ChainSummary describes a built chain, for the confirmation dialog.
func ChainSummary(hop1, hop2 *Config) string {
	nl := string([]byte{10})
	var b strings.Builder
	b.WriteString("Туннель: " + hop2.Name + nl + nl)
	b.WriteString("  1. WARP " + chainEndpointOfConfig(hop1) + nl)
	b.WriteString("     через адаптер " + hop1.Interface.PinEndpointVia + ", MTU " + strconv.Itoa(int(hop1.Interface.MTU)) + nl)
	b.WriteString("  2. Amnezia " + chainEndpointOfConfig(hop2) + nl)
	b.WriteString("     внутри WARP, MTU " + strconv.Itoa(int(hop2.Interface.MTU)) + ", весь трафик" + nl)
	return b.String()
}

func chainEndpointOfConfig(c *Config) string {
	for i := range c.Peers {
		if !c.Peers[i].Endpoint.IsEmpty() {
			return c.Peers[i].Endpoint.String()
		}
	}
	return "без Endpoint"
}
