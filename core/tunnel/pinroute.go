//go:build windows

/* AwgChain - patch 9: the pin route travels with the tunnel.
 *
 * Patch 1 pins the UDP socket of a hop to the adapter named by
 * PinEndpointVia using IP_UNICAST_IF. That alone is not enough on Windows:
 * the socket option chooses the outgoing interface, but the stack still needs
 * a route on that interface that covers the endpoint. Hop 1 carries
 * Table = off, so its adapter has no route at all beyond its own address, and
 * the packets of hop 2 fall back to the routing table - where hop 2 has just
 * installed 0.0.0.0/1 and 128.0.0.0/1. The handshake of hop 2 then re-enters
 * hop 2 and the chain eats itself: bytes leave, nothing comes back.
 *
 * awgchain.bat used to paper over this with
 *
 *     route add <endpoint of hop 2> mask 255.255.255.255 0.0.0.0 if <hop 1>
 *
 * which the graphical interface obviously never runs. Patch 9 moves that host
 * route into the tunnel service itself, so it appears whenever the hop comes
 * up, no matter who started it.
 *
 * The next hop is taken from the default route of the pinned adapter when it
 * has one (hop 1 pinned to Ethernet: the router of the LAN) and is left
 * unspecified otherwise (hop 2 pinned to the point-to-point adapter of
 * hop 1). Metric 0 keeps it ahead of anything the hops above install.
 */

package tunnel

import (
	"errors"
	"log"
	"net"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainPinEndpointIPs collects the endpoint addresses of every peer, resolving
// host names the same way the rest of the service does.
func chainPinEndpointIPs(config *conf.Config) []net.IP {
	ips := make([]net.IP, 0, len(config.Peers))
	for i := range config.Peers {
		endpoint := config.Peers[i].Endpoint
		if endpoint.IsEmpty() {
			continue
		}
		host := strings.Trim(strings.TrimSpace(endpoint.Host), "[]")
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		resolved, err := net.LookupIP(host)
		if err != nil {
			log.Printf("Chain pin route: cannot resolve %q: %v", host, err)
			continue
		}
		ips = append(ips, resolved...)
	}
	return ips
}

// chainPinNextHop returns the gateway of the pinned adapter, or nil when the
// adapter has no default route of its own (a tunnel adapter, typically).
func chainPinNextHop(luid winipcfg.LUID, family winipcfg.AddressFamily) net.IP {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil
	}
	var best *winipcfg.MibIPforwardRow2
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID != luid {
			continue
		}
		prefix := row.DestinationPrefix.IPNet()
		ones, _ := prefix.Mask.Size()
		if ones != 0 || prefix.IP == nil || !prefix.IP.IsUnspecified() {
			continue
		}
		nextHop := row.NextHop.IP()
		if nextHop == nil || nextHop.IsUnspecified() {
			continue
		}
		if best == nil || row.Metric < best.Metric {
			best = row
		}
	}
	if best == nil {
		return nil
	}
	return best.NextHop.IP()
}

// chainPinUnpin takes every host route of one endpoint address off the pinned
// adapter.
//
// Pack 85: the old code deleted by address plus next hop and computed the next
// hop again at that moment. Two things went wrong with that. When the route
// had already gone away with its adapter, the delete failed and left
// "Element not found" in the log, which is noise. And when the gateway had
// changed since the route was added, the delete looked for a row that does
// not exist and walked away, leaving a host route on a physical adapter that
// keeps sending that one address around the chain for good.
func chainPinUnpin(luid winipcfg.LUID, destination net.IPNet, family winipcfg.AddressFamily, via string) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		log.Printf("Chain pin route: cannot read the route table to take %s off %s: %v", destination.IP.String(), via, err)
		return
	}
	ones, _ := destination.Mask.Size()
	removed := 0
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID != luid {
			continue
		}
		prefix := row.DestinationPrefix.IPNet()
		rowOnes, _ := prefix.Mask.Size()
		if rowOnes != ones || prefix.IP == nil || !prefix.IP.Equal(destination.IP) {
			continue
		}
		err = luid.DeleteRoute(prefix, row.NextHop.IP())
		if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			log.Printf("Chain pin route: could not take %s off %s: %v", destination.IP.String(), via, err)
			continue
		}
		removed++
	}
	if removed == 0 {
		log.Printf("Chain pin route: %s was no longer pinned to %s, nothing to take off", destination.IP.String(), via)
		return
	}
	log.Printf("Chain pin route: %s was taken off %s, %d route(s) removed", destination.IP.String(), via, removed)
}

// chainPinRoutes adds (or removes) one host route per peer endpoint on the
// adapter named by PinEndpointVia. Tunnels without that field are untouched,
// so this is a no-op for ordinary AmneziaWG users.
func chainPinRoutes(config *conf.Config, add bool) {
	if config == nil {
		return
	}
	via := strings.TrimSpace(config.Interface.PinEndpointVia)
	if via == "" {
		return
	}
	iface, err := findInterfaceByName(via)
	if err != nil {
		if add {
			chainPinRoutesLater(config, err)
		} else {
			log.Printf("Chain pin route: %v", err)
		}
		return
	}
	luid := iface.LUID

	for _, ip := range chainPinEndpointIPs(config) {
		var family winipcfg.AddressFamily = windows.AF_INET
		destination := net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
		if ip.To4() == nil {
			family = windows.AF_INET6
			destination = net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
		}
		if destination.IP == nil {
			continue
		}

		nextHop := chainPinNextHop(luid, family)
		if nextHop == nil {
			if family == windows.AF_INET {
				nextHop = net.IPv4zero.To4()
			} else {
				nextHop = net.IPv6zero
			}
		}

		if add {
			err = luid.AddRoute(destination, nextHop, 0)
			if err != nil && errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				log.Printf("Chain pin route: %s via %s was already pinned", ip.String(), via)
				continue
			}
			if err != nil {
				log.Printf("Chain pin route: could not pin %s via %s: %v", ip.String(), via, err)
				continue
			}
			log.Printf("Chain pin route: %s now leaves through %s (next hop %s)", ip.String(), via, nextHop.String())
			continue
		}

		chainPinUnpin(luid, destination, family, via)
	}
}
