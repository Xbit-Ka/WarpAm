//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 82: a proxy tunnel keeps its own way out.
 *
 * A tunnel in "only for the proxy" mode installs no default route, so the
 * machine keeps working as before while the proxy carries whatever is
 * pointed at it. Its own handshake, though, leaves through the socket that
 * monitorDefaultRoutes binds, and that socket follows the lowest metric
 * default route of the machine. The log of 25 September shows what that
 * costs:
 *
 *     Binding v4 socket to interface 10    (Ethernet, the proxy works)
 *     ... another tunnel comes up ...
 *     Binding v4 socket to interface 25    (that tunnel, the proxy dies)
 *     ... that tunnel is stopped ...
 *     Binding v4 socket to interface 10    (the proxy works again)
 *
 * The proxy tunnel was sent into the tunnel that had just taken the default
 * route, its handshake stopped coming back, and everything pointed at the
 * proxy went quiet while the tunnel still looked up.
 *
 * A hop of a chain solves this with PinEndpointVia, which names the adapter
 * to ride on. A single proxy tunnel has no such field and should not need
 * one: the adapter it wants is simply whatever real network card the machine
 * uses, and that may change when a cable is pulled or Wi-Fi takes over. So
 * this file chooses it at every network change: the lowest metric default
 * route that does not belong to a tunnel. The socket is bound there, and the
 * endpoint of every peer gets a host route on the same adapter with metric
 * 0, exactly as pinroute.go does for a hop.
 */

package tunnel

import (
	"log"
	"strings"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainProxyOwnWay reports whether this tunnel has to find its own way out.
// A tunnel that names an adapter in PinEndpointVia already has one, and a
// tunnel that is not in "only for the proxy" mode carries the machine, so
// following the default route is right for it.
func chainProxyOwnWay(config *conf.Config) bool {
	if config == nil {
		return false
	}
	if len(strings.TrimSpace(config.Interface.PinEndpointVia)) != 0 {
		return false
	}
	return ChainTunnelIsSeparate(config.Name)
}

// chainProxyIsTunnelAdapter reports whether an adapter is a tunnel rather
// than a network card. The type is the first answer: a tunnel adapter is
// virtual or an encapsulation interface. The name is the second: an adapter
// of this program is named after its tunnel.
func chainProxyIsTunnelAdapter(row *winipcfg.MibIfRow2) bool {
	switch row.Type {
	case winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel, winipcfg.IfTypeSoftwareLoopback:
		return true
	}
	alias := strings.TrimSpace(row.Alias())
	if len(alias) == 0 {
		return false
	}
	names, err := conf.ListConfigNames()
	if err != nil {
		return false
	}
	for _, name := range names {
		if strings.EqualFold(strings.TrimSpace(name), alias) {
			return true
		}
	}
	return false
}

// chainProxyPhysical finds the adapter the machine really reaches the network
// through: the lowest metric default route that is not a tunnel and not us.
// It returns the interface index, the LUID and the adapter name, or zero when
// the machine has no such route at this moment.
func chainProxyPhysical(family winipcfg.AddressFamily, ourLUID winipcfg.LUID) (uint32, winipcfg.LUID, string) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, 0, ""
	}
	lowest := ^uint32(0)
	index := uint32(0)
	luid := winipcfg.LUID(0)
	name := ""
	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if chainProxyIsTunnelAdapter(ifrow) {
			continue
		}
		iface, err := row.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		if row.Metric+iface.Metric < lowest {
			lowest = row.Metric + iface.Metric
			index = row.InterfaceIndex
			luid = row.InterfaceLUID
			name = strings.TrimSpace(ifrow.Alias())
		}
	}
	return index, luid, name
}

// chainProxyWayMu guards the adapter each proxy tunnel is currently routed
// through, so the host route on the old adapter is taken away before the new
// one is laid down.
var (
	chainProxyWayMu  sync.Mutex
	chainProxyWayVia = make(map[string]string)
)

// chainProxyRoutesVia lays the endpoint host routes of this tunnel on the
// named adapter, reusing the machinery of pinroute.go.
func chainProxyRoutesVia(config *conf.Config, via string, add bool) {
	if config == nil || len(strings.TrimSpace(via)) == 0 {
		return
	}
	clone := *config
	clone.Interface.PinEndpointVia = via
	chainPinRoutes(&clone, add)
}

// chainProxySettleRoutes moves the endpoint host routes to the adapter the
// socket has just been bound to. Nothing happens while the adapter stays the
// same, which is the usual case.
func chainProxySettleRoutes(config *conf.Config, via string) {
	if config == nil {
		return
	}
	chainProxyWayMu.Lock()
	defer chainProxyWayMu.Unlock()
	old := chainProxyWayVia[config.Name]
	if strings.EqualFold(old, via) {
		return
	}
	if len(old) != 0 {
		chainProxyRoutesVia(config, old, false)
		delete(chainProxyWayVia, config.Name)
	}
	if len(via) == 0 {
		return
	}
	chainProxyRoutesVia(config, via, true)
	chainProxyWayVia[config.Name] = via
}

// ChainProxyWayForget takes the endpoint host routes off the machine when the
// tunnel goes down.
func ChainProxyWayForget(config *conf.Config) {
	if config == nil {
		return
	}
	chainProxyWayMu.Lock()
	old := chainProxyWayVia[config.Name]
	delete(chainProxyWayVia, config.Name)
	chainProxyWayMu.Unlock()
	if len(old) != 0 {
		chainProxyRoutesVia(config, old, false)
	}
}

// bindSocketOwnWay is the counterpart of bindSocketRoute for a proxy tunnel:
// the socket is bound to the network card rather than to whatever tunnel
// happens to hold the default route. When the machine has no card with a
// default route, the old behaviour is used, since then there is nothing
// better to bind to.
func bindSocketOwnWay(family winipcfg.AddressFamily, binder conn.BindSocketToInterface, config *conf.Config, ourLUID winipcfg.LUID, lastLUID *winipcfg.LUID, lastIndex *uint32, blackholeWhenLoop bool) error {
	index, luid, name := chainProxyPhysical(family, ourLUID)
	if index == 0 || luid == 0 {
		return bindSocketRoute(family, binder, ourLUID, lastLUID, lastIndex, blackholeWhenLoop)
	}
	chainProxySettleRoutes(config, name)
	if luid == *lastLUID && index == *lastIndex {
		return nil
	}
	*lastLUID = luid
	*lastIndex = index
	if family == windows.AF_INET {
		log.Printf("Chain proxy way: binding v4 socket to interface %d (%s), the tunnel serves the proxy only", index, name)
		return binder.BindSocketToInterface4(index, false)
	} else if family == windows.AF_INET6 {
		log.Printf("Chain proxy way: binding v6 socket to interface %d (%s), the tunnel serves the proxy only", index, name)
		return binder.BindSocketToInterface6(index, false)
	}
	return nil
}
