/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110: the duplicate address check is turned off before the
 * adapter gets its address.
 *
 * A tunnel that rides on a freshly raised one lost about 3 seconds at
 * every start, and always nearly the same 3 seconds: warpam through
 * warpam-hop1 took 2636, 2669, 2642, 2656, 2638 and 2642 ms, Elena through
 * ru-central 3709 and 3713 ms. Lost packets are never that regular. The
 * proxy of a new tunnel also got "a socket operation was attempted to an
 * unreachable host" in its first second. Both fit the duplicate address
 * check of Windows: a new address stays tentative, and unusable, until the
 * check is over. The original code turned the check off for IPv6 only,
 * and only after the address was already set, which does not shorten a
 * check that has begun. The adapter is a point to point link of our own,
 * there is nobody on it to collide with.
 */

package tunnel

import (
	"log"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainNoDadBeforeAddress turns the check off on the adapter itself, so
// the address set right after it is usable at once. A failure only costs
// the old wait, so it is logged and the start goes on.
func chainNoDadBeforeAddress(family winipcfg.AddressFamily, luid winipcfg.LUID) {
	ipif, err := luid.IPInterface(family)
	if err != nil {
		log.Printf("[WarpAm] The duplicate address check of the adapter could not be read (%v), the address may need a few seconds", err)
		return
	}
	if ipif.DadTransmits == 0 {
		return
	}
	before := ipif.DadTransmits
	ipif.DadTransmits = 0
	if family == windows.AF_INET6 {
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	}
	if err := ipif.Set(); err != nil {
		log.Printf("[WarpAm] The duplicate address check of the adapter could not be turned off (%v), the address may need a few seconds", err)
		return
	}
	fam := "IPv4"
	if family == windows.AF_INET6 {
		fam = "IPv6"
	}
	log.Printf("[WarpAm] The %s duplicate address check of the adapter is off (it was %d tries), so the address can be used at once", fam, before)
}
