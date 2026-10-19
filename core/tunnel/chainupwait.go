//go:build windows

/* AwgChain - pack 49: no handshake before the socket is pinned.
 *
 * Packs 45 and 47 keep the tunnel alive while the hop underneath is missing,
 * and start that hop. The stress test is green, but the log still shows a
 * small leak window at startup: the device is brought up, sends its first
 * handshake through the physical adapter, and only about two seconds later
 * the socket is pinned to the hop underneath. During that window the server
 * of this hop sees the real address of the machine.
 *
 * This file closes that window. Before the peers are brought up, the service
 * waits for the pinned adapter, starting the hop underneath in the meantime.
 * The wait is short on purpose (20 seconds) so Windows never marks the
 * service start as failed.
 *
 * Pack 101: if the hop is still missing after that, the service stops with
 * an error. Before, the peers were brought up anyway, and the first
 * handshake went out through the physical adapter, past the hop: the leak
 * of the log of 5 October. The manager now raises the hop underneath
 * before the service of this one is started at all, so this wait is the
 * last guard, not the normal path.
 */

package tunnel

import (
	"log"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const chainUpWaitTries = 10

// chainWaitForPinBeforeUp blocks until the adapter named in PinEndpointVia is
// up, so that no packet of this hop can leave through the physical adapter.
// Pack 101: it answers false when the adapter never came, and the caller
// must then not bring the peers up.
func chainWaitForPinBeforeUp(config *conf.Config) bool {
	if config == nil {
		return true
	}
	via := strings.TrimSpace(config.Interface.PinEndpointVia)
	if via == "" {
		return true
	}
	if chainPinnedInterfaceReady(via) {
		return true
	}

	log.Printf("Chain: holding the first handshake until the hop underneath (%s) is here", via)

	for try := 0; try < chainUpWaitTries; try++ {
		if try%chainPinStartEvery == 0 {
			chainStartHopBelow(via)
		}
		time.Sleep(chainPinRetryGap)
		if chainPinnedInterfaceReady(via) {
			log.Printf("Chain: the hop underneath (%s) is here, the handshake may go out", via)
			chainPinRoutes(config, true)
			return true
		}
	}

	log.Printf("Chain: the hop underneath (%s) is still missing, the peers are not brought up so nothing goes out past it", via)
	return false
}
