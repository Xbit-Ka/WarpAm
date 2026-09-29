/* SPDX-License-Identifier: MIT
 *
 * VPN-chain patch #1
 *
 * Pins a tunnel's UDP socket to a specific network interface instead of
 * letting it follow the lowest-metric default route.
 *
 * Why this is the core of VPN chaining:
 * amneziawg/wireguard binds its UDP socket with IP_UNICAST_IF to whatever
 * interface currently owns the default route. Once hop2 installs 0.0.0.0/0,
 * hop1 would re-bind to hop2's own tunnel and loop. Conversely hop2 must send
 * its handshake *into* hop1. IP_UNICAST_IF overrides the routing table for
 * that one socket, so pinning is enough - no host routes needed.
 *
 * Config usage, [Interface] section:
 *   PinEndpointVia = Ethernet      ; hop1: pin to the physical adapter
 *   PinEndpointVia = hop1-warp     ; hop2: pin into hop1's tunnel adapter
 *
 * The value is a Windows adapter name (friendly name or description). A
 * tunnel adapter is named after its config, so hop1's adapter name equals
 * hop1's tunnel name.
 */

package tunnel

import (
	"fmt"
	"log"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// findInterfaceByName resolves a Windows adapter by friendly name or description.
func findInterfaceByName(name string) (*winipcfg.IPAdapterAddresses, error) {
	ifaces, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if strings.EqualFold(iface.FriendlyName(), name) || strings.EqualFold(iface.Description(), name) {
			return iface, nil
		}
	}
	return nil, chainPinNotReady(fmt.Errorf("pinned interface %q not found", name))
}

// bindSocketPinned is the PinEndpointVia counterpart of bindSocketRoute.
func bindSocketPinned(family winipcfg.AddressFamily, binder conn.BindSocketToInterface, pinVia string, lastLUID *winipcfg.LUID, lastIndex *uint32) error {
	iface, err := findInterfaceByName(pinVia)
	if err != nil {
		return err
	}
	if iface.OperStatus != winipcfg.IfOperStatusUp {
		return chainPinNotReady(fmt.Errorf("pinned interface %q is not up (oper status %d)", pinVia, iface.OperStatus))
	}

	luid := iface.LUID
	var index uint32
	if family == windows.AF_INET {
		index = iface.IfIndex
	} else if family == windows.AF_INET6 {
		index = iface.IPv6IfIndex
	}
	if index == 0 {
		return chainPinNotReady(fmt.Errorf("pinned interface %q has no index for this address family", pinVia))
	}

	if luid == *lastLUID && index == *lastIndex {
		return nil
	}
	*lastLUID = luid
	*lastIndex = index

	if family == windows.AF_INET {
		log.Printf("Pinning v4 socket to interface %d (%s)", index, pinVia)
		return binder.BindSocketToInterface4(index, false)
	} else if family == windows.AF_INET6 {
		log.Printf("Pinning v6 socket to interface %d (%s)", index, pinVia)
		return binder.BindSocketToInterface6(index, false)
	}
	return nil
}
