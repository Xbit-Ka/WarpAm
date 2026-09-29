//go:build windows

/* AwgChain pack 86: the routable IPv6 address while the lock is closed.
 *
 * The filter of pack 84 forbids IPv6 packets, it does not take the address
 * away. Windows keeps preferring IPv6 for every name that has one, the
 * packets are dropped rather than refused, and every one of those waits
 * looks to the user like a slow or a dead site. Pack 84 only wrote the fact
 * into the log, on purpose: an address torn off an adapter behind the back
 * of the user is worse than a slow page.
 *
 * This pack does take it away, under one condition that the log line of pack
 * 84 could not state: only while the kill switch is really armed. That is
 * the one moment when the address is provably useless, because nothing can
 * leave the machine over IPv6 anyway. Every address that is removed is
 * remembered with the adapter it sat on, and it is put back the moment the
 * lock is lifted, so the machine is left exactly as it was found.
 *
 * Addresses of our own tunnels are never touched, and neither is a link
 * local or a unique local address: those never leave the house and no
 * program prefers them over IPv4 to the outside.
 */

package manager

import (
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainIPv6Taken is one address that was removed and has to come back.
type chainIPv6Taken struct {
	LUID    winipcfg.LUID
	Adapter string
	Address net.IPNet
}

var (
	chainIPv6Mu    sync.Mutex
	chainIPv6Held []chainIPv6Taken
)

// chainIPv6Ours answers whether this adapter is one of our tunnels. Their
// addresses belong to the chain and are none of this file's business.
func chainIPv6Ours(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return false
	}
	names, err := conf.ListConfigNames()
	if err != nil {
		// Unreadable configurations mean we cannot tell our adapters from
		// the adapters of the machine. Nothing is removed in that case.
		return true
	}
	for _, known := range names {
		if strings.EqualFold(known, name) {
			return true
		}
	}
	return false
}

// ChainDropRoutableIPv6 removes the routable IPv6 addresses of the machine.
// It is called right after the kill switch has been armed.
func ChainDropRoutableIPv6() {
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_INET6), winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	taken := make([]chainIPv6Taken, 0, 2)
	for _, adapter := range adapters {
		if adapter.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		name := adapter.FriendlyName()
		if chainIPv6Ours(name) {
			continue
		}
		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			prefix := int(address.OnLinkPrefixLength)
			if prefix <= 0 || prefix > 128 {
				prefix = 128
			}
			entry := chainIPv6Taken{
				LUID:    adapter.LUID,
				Adapter: name,
				Address: net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, 128)},
			}
			err = adapter.LUID.DeleteIPAddress(entry.Address)
			if err != nil {
				log.Printf("[AwgChain] The routable IPv6 address %s on %s could not be removed while the lock is closed: %v", ip, name, err)
				continue
			}
			taken = append(taken, entry)
			log.Printf("[AwgChain] The routable IPv6 address %s on %s was removed while the kill switch is armed, it is put back when the lock is lifted", ip, name)
		}
	}
	if len(taken) == 0 {
		return
	}
	chainIPv6Mu.Lock()
	chainIPv6Held = append(chainIPv6Held, taken...)
	chainIPv6Mu.Unlock()
}

// ChainRestoreRoutableIPv6 puts back what was removed. It is called when the
// lock is lifted, and it is safe to call when nothing was ever removed.
func ChainRestoreRoutableIPv6() {
	chainIPv6Mu.Lock()
	taken := chainIPv6Held
	chainIPv6Held = nil
	chainIPv6Mu.Unlock()

	for _, entry := range taken {
		err := entry.LUID.AddIPAddress(entry.Address)
		if err != nil {
			log.Printf("[AwgChain] The IPv6 address %s could not be put back on %s: %v. It comes back by itself with the next router advertisement or a reconnect of that adapter", entry.Address.IP, entry.Adapter, err)
			continue
		}
		log.Printf("[AwgChain] The IPv6 address %s is back on %s", entry.Address.IP, entry.Adapter)
	}
}
