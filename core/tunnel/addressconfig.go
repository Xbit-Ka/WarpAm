/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"log"
	"net"
	"sort"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	includedInAddresses := func(a net.IPNet) bool {
		// TODO: this makes the whole algorithm O(n^2). But we can't stick net.IPNet in a Go hashmap. Bummer!
		for _, addr := range addresses {
			ip := addr.IP
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			mA, _ := addr.Mask.Size()
			mB, _ := a.Mask.Size()
			if bytes.Equal(ip, a.IP) && mA == mB {
				return true
			}
		}
		return false
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
			if includedInAddresses(ipnet) {
				log.Printf("Cleaning up stale address %s from interface вЂ%sвЂ™", ipnet.String(), iface.FriendlyName())
				iface.LUID.DeleteIPAddress(ipnet)
			}
		}
	}
}

func configureInterface(family winipcfg.AddressFamily, conf *conf.Config, tun *tun.NativeTun) error {
	luid := winipcfg.LUID(tun.LUID())

	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
	addresses := make([]net.IPNet, len(conf.Interface.Addresses))
	var haveV4Address, haveV6Address bool
	for i, addr := range conf.Interface.Addresses {
		addresses[i] = addr.IPNet()
		if addr.Bits() == 32 {
			haveV4Address = true
		} else if addr.Bits() == 128 {
			haveV6Address = true
		}
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			allowedip.MaskSelf()
			if (allowedip.Bits() == 32 && !haveV4Address) || (allowedip.Bits() == 128 && !haveV6Address) {
				continue
			}
			route := winipcfg.RouteData{
				Destination: allowedip.IPNet(),
				Metric:      0,
			}
			if allowedip.Bits() == 32 {
				if allowedip.Cidr == 0 {
					foundDefault4 = true
				}
				route.NextHop = net.IPv4zero
			} else if allowedip.Bits() == 128 {
				if allowedip.Cidr == 0 {
					foundDefault6 = true
				}
				route.NextHop = net.IPv6zero
			}
			routes = append(routes, route)
		}
	}

	err := luid.SetIPAddressesForFamily(family, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, addresses)
		err = luid.SetIPAddressesForFamily(family, addresses)
	}
	if err != nil {
		return err
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Metric != routes[j].Metric {
			return routes[i].Metric < routes[j].Metric
		}
		if c := bytes.Compare(routes[i].NextHop, routes[j].NextHop); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask); c != 0 {
			return c < 0
		}
		return false
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	// AwgChain pack 76: a tunnel that only carries the local proxy does get
	// its routes, but as the worst ones on the machine.
	//
	// Pack 74 left it without routes at all, and that was half a solution.
	// IP_UNICAST_IF does not invent a way out: Windows still looks for a
	// route, only on the interface it was told to use, and an interface
	// without a single route has nowhere to send anything, so every
	// connection of the proxy died before it began. With a metric this high
	// the provider stays the default for everything that is not pinned,
	// while the pinned sockets of the proxy find their road here.
	const separateRouteMetric = 9000
	separate := ChainTunnelIsSeparate(conf.Name)
	if separate {
		// Pack 77: one route and only one. Pack 76 kept the routes of the
		// tunnel and gave them a bad metric, which is not enough: a config
		// that writes its AllowedIPs as 0.0.0.0/1 and 128.0.0.0/1 puts two
		// halves of the internet on this interface, and Windows picks a
		// route by the length of the mask first and by the metric only
		// after that. A /1 beats the /0 of the provider whatever the
		// metric says, and the whole machine ends up in the tunnel. A
		// single default route cannot win that way, and the pinned sockets
		// of the proxy need nothing else: one road out of this interface
		// is enough for them.
		single := winipcfg.RouteData{Metric: separateRouteMetric}
		keep := false
		if family == windows.AF_INET && haveV4Address {
			single.Destination = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
			single.NextHop = net.IPv4zero
			keep = true
		} else if family == windows.AF_INET6 && haveV6Address {
			single.Destination = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			single.NextHop = net.IPv6zero
			keep = true
		}
		deduplicatedRoutes = deduplicatedRoutes[:0]
		if keep {
			deduplicatedRoutes = append(deduplicatedRoutes, &single)
		}
		log.Printf("AwgChain: %s carries the local proxy only, so it gets one default route with metric %d and no system DNS", conf.Name, separateRouteMetric)
	}

	if !conf.Interface.TableOff {
		err = luid.SetRoutesForFamily(family, deduplicatedRoutes)
		if err != nil {
			return err
		}
	}

	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
		if conf.Interface.MTU > 0 {
		mtu := uint32(conf.Interface.MTU)
		// Windows rejects an IPv6 interface MTU below the 1280 byte minimum with
		// ERROR_INVALID_PARAMETER, which fails the whole interface configuration.
		// A tunnel nested inside another tunnel legitimately needs a smaller MTU,
		// so clamp the v6 interface only and keep the tunnel MTU as configured.
		if family == windows.AF_INET6 && mtu < 1280 {
			log.Printf("MTU %d is below the IPv6 minimum, leaving the v6 interface MTU unchanged", mtu)
		} else {
			ipif.NLMTU = mtu
		}
		tun.ForceMTU(int(conf.Interface.MTU))
	}
	if family == windows.AF_INET {
		// Pack 76: in the separate mode the interface must not win. The
		// zero here is what makes a normal tunnel the default way out, and
		// a proxy-only tunnel is not supposed to be one.
		if foundDefault4 && !separate {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		} else if separate {
			ipif.UseAutomaticMetric = false
			ipif.Metric = separateRouteMetric
		}
	} else if family == windows.AF_INET6 {
		if foundDefault6 && !separate {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		} else if separate {
			ipif.UseAutomaticMetric = false
			ipif.Metric = separateRouteMetric
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	}
	err = ipif.Set()
	if err != nil {
		return err
	}

	if separate {
		// The resolvers of this tunnel are still used, but only by the
		// proxy and only through the tunnel. Giving them to the whole
		// machine would send every name of every program into a tunnel
		// that is not supposed to carry them.
		return nil
	}

	return luid.SetDNS(family, conf.Interface.DNS, conf.Interface.DNSSearch)
}

func enableFirewall(conf *conf.Config, tun *tun.NativeTun) error {
	doNotRestrict := true
	if len(conf.Peers) == 1 && !conf.Interface.TableOff {
	nextallowedip:
		for _, allowedip := range conf.Peers[0].AllowedIPs {
			if allowedip.Cidr == 0 {
				for _, b := range allowedip.IP {
					if b != 0 {
						continue nextallowedip
					}
				}
				doNotRestrict = false
				break
			}
		}
	}
	if ChainTunnelIsSeparate(conf.Name) {
		// AwgChain pack 75: a tunnel that only carries the local proxy has no
		// routes of its own. The block-all that comes with a 0.0.0.0/0 peer
		// would then leave the machine with no way out at all: not past the
		// tunnel, because WFP forbids it, and not through the tunnel, because
		// nothing is routed there. The proxy does not need the rule either,
		// its sockets are nailed to this interface by hand.
		log.Printf("AwgChain: %s carries the local proxy only, so the traffic of the machine is left alone", conf.Name)
		return firewall.EnableFirewall(tun.LUID(), true, nil, nil)
	}
	if conf.Interface.PinEndpointVia != "" {
		// AwgChain: this tunnel is a hop of a chain. The chain-wide rule set owns
		// the kill switch; a per-tunnel block-all here would land in a permanent
		// WFP session that the chain guard cannot remove.
		log.Println("Chain hop: leaving the kill switch to the chain rule set")
		return firewall.EnableFirewall(tun.LUID(), true, conf.Interface.DNS, nil)
	}
	log.Println("Enabling firewall rules")
	// AwgChain pack 82: a tunnel that carries the machine must not shut the
	// door on a tunnel that carries only its own proxy. The ones that are up
	// now are let out straight away, and the watcher lets out the ones that
	// come up later. Nothing is gathered when this tunnel blocks nothing.
	var proxyTunnels []firewall.ChainProxyTunnel
	if !doNotRestrict {
		proxyTunnels = chainProxyTunnelsUp(conf.Name)
	}
	err := firewall.EnableFirewall(tun.LUID(), doNotRestrict, conf.Interface.DNS, proxyTunnels)
	if err != nil || doNotRestrict {
		return err
	}
	if chainProxyDoorsCallback == nil {
		callback, watchErr := chainProxyDoorsWatch(conf.Name)
		if watchErr != nil {
			log.Printf("Firewall: could not watch for proxy tunnels: %v", watchErr)
		} else {
			chainProxyDoorsCallback = callback
		}
	}
	return nil
}

// chainProxyDoorsCallback keeps the watcher of pack 82 alive for as long as
// this tunnel service runs. The service ends with its tunnel, and the
// callback goes with it.
var chainProxyDoorsCallback *winipcfg.InterfaceChangeCallback
