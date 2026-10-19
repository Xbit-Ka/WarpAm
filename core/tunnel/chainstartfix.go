/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 107: two delays of the start are taken away.
 *
 * 1. Wintun. Right after other tunnels were switched off Windows is often
 *    still removing their adapters and does not make a new one in time.
 *    One more try after a short pause is made instead of failing at once.
 *
 * 2. The first handshake. A tunnel that goes through another one sends its
 *    first handshake when the peers come up, a moment before its socket is
 *    pinned to the tunnel underneath. That packet is lost and the next try
 *    comes only 5 seconds later. So once the socket is pinned, a peer that
 *    has made no handshake yet is asked for one at once.
 */

package tunnel

import (
	"bufio"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	// chainWintunTries is how many times the adapter is asked for when
	// the machine is not just booted.
	chainWintunTries = 2
	// chainWintunPause is the pause between the tries.
	chainWintunPause = 3 * time.Second
	// chainPinHandshakeWait gives the pin a moment to take hold, and is
	// also the step of the checks after it.
	chainPinHandshakeWait = 500 * time.Millisecond
	// WarpAm pack 109: one try was not enough. The tunnel underneath had
	// often not made its own handshake yet, and the try was lost too. Now
	// the peers are looked at every half second for 5 seconds, and asked
	// again at most once a second while they have no handshake.
	// WarpAm pack 110: 15 seconds. On 6.10 Elena used up all 5 seconds and
	// was only saved by the engine's own retry 5 seconds later, 9.9 seconds
	// in all.
	chainPinHandshakeChecks = 30
	chainPinHandshakeGap    = time.Second
	// chainStartHandshakeWait is the first look at a tunnel that does not
	// ride on another one. Pack 110: its socket is bound a few milliseconds
	// after the peers come up, so a tenth of a second is enough.
	chainStartHandshakeWait = 100 * time.Millisecond
)

// chainSilentPeers returns the public keys of the peers that have made no
// handshake yet.
func chainSilentPeers(state string) []string {
	var silent []string
	key := ""
	scanner := bufio.NewScanner(strings.NewReader(state))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "public_key="):
			key = strings.TrimPrefix(line, "public_key=")
		case line == "last_handshake_time_sec=0" && len(key) != 0:
			silent = append(silent, key)
			key = ""
		}
	}
	return silent
}

// chainHandshakeAfterPin sends the handshake again for every peer that has
// made none yet, once the socket is pinned.
//
// WarpAm pack 110: every tunnel goes through here now, in two ways.
//
// A tunnel that rides on another tunnel of ours lost its first handshake
// on the wrong road, so it is sent again at once (rehandshake), as in
// packs 107 and 109.
//
// Any other tunnel, plain or pinned to the network card, lost nothing: it
// simply had not sent anything. A tunnel without PersistentKeepalive only
// makes its handshake when the first packet comes, and WARPv2_84 stood
// silent for 3.2 seconds after "Startup complete" at every start while the
// manager waited for that handshake to raise ru-central. Such a tunnel
// gets a keepalive instead. The engine sends a handshake for it at most
// once in 5 seconds, so a handshake that is already on its way is never
// thrown away, which a rehandshake would do. This also ends the false
// "went out before the socket was pinned to Ethernet" of pack 109.
func chainHandshakeAfterPin(dev *device.Device, config *conf.Config) {
	if dev == nil || len(config.Peers) == 0 {
		return
	}
	pin := strings.TrimSpace(config.Interface.PinEndpointVia)
	throughTunnel := chainPinIsTunnel(pin)
	first := chainStartHandshakeWait
	if throughTunnel {
		first = chainPinHandshakeWait
	}
	go func() {
		var asked time.Time
		tries := 0
		for i := 0; i < chainPinHandshakeChecks; i++ {
			if i == 0 {
				time.Sleep(first)
			} else {
				time.Sleep(chainPinHandshakeWait)
			}
			state, err := dev.IpcGet()
			if err != nil {
				return
			}
			silent := chainSilentPeers(state)
			if len(silent) == 0 {
				if tries > 1 && throughTunnel {
					log.Printf("[WarpAm] The handshake through %s is made after %d tries", pin, tries)
				} else if tries > 1 {
					log.Printf("[WarpAm] The handshake is made after %d tries", tries)
				}
				return
			}
			if !asked.IsZero() && time.Since(asked) < chainPinHandshakeGap {
				continue
			}
			if !throughTunnel {
				chainNudgePeers(dev, silent)
				asked = time.Now()
				tries++
				if tries == 1 {
					log.Printf("[WarpAm] Nothing has asked for a handshake %d ms after the start, so one is asked for now", first.Milliseconds())
				} else {
					log.Printf("[WarpAm] Still no handshake, it is asked for again (try %d)", tries)
				}
				continue
			}
			var b strings.Builder
			for _, k := range silent {
				fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\nrehandshake=true\n", k)
			}
			if err := dev.IpcSet(b.String()); err != nil {
				log.Printf("[WarpAm] The handshake after pinning to %s could not be asked for: %v", pin, err)
				return
			}
			asked = time.Now()
			tries++
			if tries == 1 {
				log.Printf("[WarpAm] The first handshake went out before the socket was pinned to %s, so it is sent again now", pin)
			} else {
				log.Printf("[WarpAm] Still no handshake through %s, it is sent again (try %d)", pin, tries)
			}
		}
	}()
}

// chainPinIsTunnel answers whether PinEndpointVia names another tunnel of
// the program rather than a network card. Every tunnel has its
// configuration under its own name, a network card has none.
func chainPinIsTunnel(pin string) bool {
	if len(pin) == 0 {
		return false
	}
	_, err := conf.LoadFromName(pin)
	return err == nil
}

// chainNudgePeers sends a keepalive to the silent peers. With no session
// yet, the engine answers it with a handshake, unless it sent one less
// than 5 seconds ago. The keys come hex encoded, as IpcGet writes them.
func chainNudgePeers(dev *device.Device, silent []string) {
	for _, k := range silent {
		var pk device.NoisePublicKey
		if err := pk.FromHex(k); err != nil {
			continue
		}
		if peer := dev.LookupPeer(pk); peer != nil {
			peer.SendKeepalive()
		}
	}
}
