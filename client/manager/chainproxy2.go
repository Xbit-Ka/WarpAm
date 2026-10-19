//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the second proxy of a double tunnel.
 *
 * While warpam runs, its first hop warpam-hop1 holds the key of WARPv2_84,
 * and WARPv2_84 cannot be raised beside it (one key, one session on the
 * server). A way out through WARP is still wanted sometimes, so a double
 * tunnel can carry a second proxy that leaves through its first hop and not
 * through the tunnel itself. Both proxies work at the same time, each on
 * its own port. No second key is used, so nothing argues with the server.
 *
 * It is the proxy of pack 74 with the hidden hop as its tunnel: every
 * socket is nailed to the adapter of warpam-hop1 with IP_UNICAST_IF
 * (chainproxynet.go), names are asked of 1.1.1.1 through that adapter, and
 * the proxy refuses while the hop is down. It listens on this machine only
 * and speaks SOCKS5 and HTTP on the one port.
 *
 * Two things the hop did not have. IP_UNICAST_IF needs a route on the
 * adapter, and a hidden hop installs none (TableOff). So one default route
 * with metric 9000 is laid on the hop for as long as the second proxy runs,
 * the same single route pack 77 gives a tunnel that carries only its proxy:
 * one /0 cannot beat the /0 of the provider, and the two halves of warpam
 * beat it anyway, so nothing but the pinned sockets ever takes it. And the
 * kill switch lets the hop through (chainlockholes.go, and in the tunnel
 * services core/tunnel/chainproxylist.go).
 *
 * The proxy is kept under the name of the hop, so everything that already
 * follows the hops of a chain takes it down with the hop.
 */

package manager

import (
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// chainProxy2Metric is the metric of the one route the hop gets.
const chainProxy2Metric = 9000

// chainProxy2Hop is the hidden hop of a double tunnel, or "".
func chainProxy2Hop(leaf string) string {
	hop := chainParentName(leaf)
	if len(hop) == 0 || !ChainIsHiddenHop(hop) {
		return ""
	}
	return hop
}

// chainProxy2Pair is the double tunnel a hidden hop belongs to, or "".
func chainProxy2Pair(hop string) string {
	if !ChainIsHiddenHop(hop) {
		return ""
	}
	for _, child := range chainChildNames(hop) {
		if !ChainIsHiddenHop(child) {
			return child
		}
	}
	return ""
}

// chainProxy2Wanted answers whether the hidden hop carries the second proxy
// of its pair, and on which port.
func chainProxy2Wanted(hop string) (bool, int) {
	pair := chainProxy2Pair(hop)
	if len(pair) == 0 {
		return false, 0
	}
	s := ChainSettingsFor(pair)
	return s.Proxy2, s.Proxy2Port
}

// chainProxy2Address is where the second proxy of a pair listens.
func chainProxy2Address(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// chainProxy2Route lays or lifts the one route on the hop.
func chainProxy2Route(hop string, add bool) {
	luid, ok := chainAdapterLUID(hop)
	if !ok {
		return
	}
	dst := net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
	if add {
		err := luid.AddRoute(dst, net.IPv4zero.To4(), chainProxy2Metric)
		if err == nil {
			log.Printf("[WarpAm] The second proxy: %s gets one default route with metric %d, so that the pinned sockets find their way out of it", hop, chainProxy2Metric)
		} else if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			log.Printf("[WarpAm] The second proxy: the route on %s could not be laid (%v), its connections will not get out", hop, err)
		}
		return
	}
	if err := luid.DeleteRoute(dst, net.IPv4zero.To4()); err == nil {
		log.Printf("[WarpAm] The second proxy: the route on %s is taken away", hop)
	}
}

// chainProxy2Follow puts the second proxy of leaf up or takes it down, as
// the settings of leaf say. It is called wherever the first proxy is.
func chainProxy2Follow(leaf string) {
	hop := chainProxy2Hop(leaf)
	if len(hop) == 0 {
		return
	}
	wanted, port := chainProxy2Wanted(hop)
	chainProxyMu.Lock()
	running := chainProxyLive[hop]
	chainProxyMu.Unlock()
	if !wanted {
		if running != nil {
			chainProxyStop(hop, "the second proxy of "+leaf+" is switched off")
			chainProxy2Route(hop, false)
		}
		return
	}
	address := chainProxy2Address(port)
	if running != nil {
		if strings.EqualFold(running.address, address) {
			if _, up := chainAdapterLUID(hop); up {
				chainProxy2Route(hop, true)
			}
			return
		}
		chainProxyStop(hop, "the second proxy of "+leaf+" moves to "+address)
	}
	if _, up := chainAdapterLUID(hop); !up {
		return
	}
	p := &chainProxy{
		leaf:     hop,
		address:  address,
		protocol: ChainProxyProtoBoth,
		split:    true,
		onDown:   ChainProxyDownError,
		conns:    make(map[net.Conn]struct{}, 16),
		stop:     make(chan struct{}),
	}
	chainProxyMu.Lock()
	if _, already := chainProxyLive[hop]; already {
		chainProxyMu.Unlock()
		return
	}
	chainProxyLive[hop] = p
	chainProxyMu.Unlock()
	log.Printf("[WarpAm] The second proxy of %s is being started: through %s, address %s, SOCKS5 and HTTP", leaf, hop, address)
	if err := p.open(); err != nil {
		chainProxyMu.Lock()
		delete(chainProxyLive, hop)
		chainProxyMu.Unlock()
		if holder := chainProxyHolderOf(address, hop); len(holder) != 0 {
			log.Printf("[WarpAm] The second proxy of %s could not take %s (%v). That address is already held by the proxy of %s", leaf, address, err, holder)
		} else {
			log.Printf("[WarpAm] The second proxy of %s could not take %s (%v). No proxy of ours holds that address, so it belongs to another program", leaf, address, err)
		}
		return
	}
	chainProxy2Route(hop, true)
	log.Printf("[WarpAm] The second proxy of %s is listening on %s and goes out through %s", leaf, address, hop)
	go p.watch()
}

// chainProxy2PortBusy answers whether the port of the second proxy of name
// is free to take. An empty answer means it is, or that there is no second
// proxy.
func chainProxy2PortBusy(name string) (int, string) {
	s := ChainSettingsFor(name)
	hop := chainProxy2Hop(name)
	if !s.Proxy2 || len(hop) == 0 {
		return 0, ""
	}
	address := chainProxy2Address(s.Proxy2Port)
	for _, proxy := range ChainProxyState() {
		if strings.EqualFold(proxy.Leaf, hop) && strings.EqualFold(proxy.Address, address) {
			return 0, ""
		}
	}
	listener, err := net.Listen("tcp", address)
	if err == nil {
		listener.Close()
		return 0, ""
	}
	return s.Proxy2Port, chainProxyHolderOf(address, hop)
}
