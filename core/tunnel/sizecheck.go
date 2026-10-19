//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 95: the size switch and the size check of a tunnel.
 *
 * The engine pads a transport packet away from the length of a handshake
 * message (amneziawg-go/device/sizedodge.go). The switch for that lives in
 * the settings book of the manager, Global, SizeDodgeOff, and is read here
 * the same way chainsplit.go reads the book: once, at start, read only.
 *
 * The check only writes to the log. It names every length at which a
 * packet of one kind could be read as a packet of another kind, so a bad
 * config can be seen in the log before it starts to lose packets.
 */

package tunnel

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// sizeCheckBook is the part of settings.json this file cares about.
type sizeCheckBook struct {
	Global struct {
		SizeDodgeOff bool
	}
}

// chainSizeDodgeOn answers whether the engine should pad away from the
// handshake sizes. A missing or unreadable file means yes.
func chainSizeDodgeOn() bool {
	path := chainSplitSettingsPath()
	if len(path) == 0 {
		return true
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	var book sizeCheckBook
	if err := json.Unmarshal(raw, &book); err != nil {
		return true
	}
	return !book.Global.SizeDodgeOff
}

// The sizes of the messages without junk, as in amneziawg-go/device.
const (
	sizeCheckInit      = 148
	sizeCheckResponse  = 92
	sizeCheckCookie    = 64
	sizeCheckTransport = 32
	sizeCheckStep      = 16
	sizeCheckIPUDP     = 28
	sizeCheckWire      = 1500
	sizeCheckMTU       = 1420
)

func sizeCheckFlag(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// chainSizeCheck writes to the log what it finds in the interface of a
// config. It changes nothing.
func chainSizeCheck(config *conf.Config, dodge bool) {
	if config == nil {
		return
	}
	i := &config.Interface
	mtu := int(i.MTU)
	if mtu == 0 {
		mtu = sizeCheckMTU
	}
	s4 := int(i.TransportPacketJunkSize)
	// Pack 100: junk is the junk size of the kind, so d = junk - S4 tells
	// where a receiver looks for the type of a transport packet that has
	// the length of this kind. With d = 0 it reads the H4 of the transport
	// packet itself, and the ranges of H never overlap (uapi.go), so the
	// match of lengths is harmless. Up to pack 99 the check compared only
	// lengths and warned about tunnel 100 (S3 = S4) for nothing.
	handshakes := []struct {
		kind string
		wire int
		junk int
	}{
		{"handshake initiation (S1+148)", int(i.InitPacketJunkSize) + sizeCheckInit, int(i.InitPacketJunkSize)},
		{"handshake response (S2+92)", int(i.ResponsePacketJunkSize) + sizeCheckResponse, int(i.ResponsePacketJunkSize)},
		{"cookie reply (S3+64)", int(i.CookieReplyPacketJunkSize) + sizeCheckCookie, int(i.CookieReplyPacketJunkSize)},
	}
	harmless := []string{}
	found := false
	for a := 0; a < len(handshakes); a++ {
		for b := a + 1; b < len(handshakes); b++ {
			if handshakes[a].wire == handshakes[b].wire {
				found = true
				log.Printf("[WarpAm] Size check: %s and %s are both %d bytes on the wire", handshakes[a].kind, handshakes[b].kind, handshakes[a].wire)
			}
		}
	}
	for _, h := range handshakes {
		inner := h.wire - s4 - sizeCheckTransport
		if inner < 0 || inner > mtu {
			continue
		}
		if inner%sizeCheckStep != 0 && inner != mtu {
			continue
		}
		if h.junk == s4 {
			harmless = append(harmless, h.kind)
			continue
		}
		found = true
		switch {
		case !dodge:
			log.Printf("[WarpAm] Size check: a transport packet (S4+32+%d) is %d bytes, the same as a %s; the size dodge is off, such packets can be lost", inner, h.wire, h.kind)
		case inner+sizeCheckStep > mtu:
			log.Printf("[WarpAm] Size check: a transport packet (S4+32+%d) is %d bytes, the same as a %s, and there is no room under the MTU to pad it away", inner, h.wire, h.kind)
		default:
			log.Printf("[WarpAm] Size check: a transport packet (S4+32+%d) is %d bytes, the same as a %s; the size dodge pads it away", inner, h.wire, h.kind)
		}
	}
	if len(harmless) != 0 {
		log.Printf("[WarpAm] Size check: a transport packet can have the length of a %s, the match of lengths is harmless: the junk is the same as S4 %d (d = 0), so the type read is H4", strings.Join(harmless, ", "), s4)
	}
	if sizeCheckFlag(i.RandomTrailers) {
		risky := []string{}
		for _, h := range handshakes {
			if h.junk != s4 {
				risky = append(risky, h.kind)
			}
		}
		if len(risky) == 0 {
			log.Printf("[WarpAm] Size check: random trailers are on, the match of lengths is harmless: every handshake has the same junk as S4 %d (d = 0), so a longer packet still reads as transport", s4)
		} else {
			found = true
			log.Printf("[WarpAm] Size check: random trailers are on, every length above the size of a %s can be read as a handshake (d is not 0) and the size dodge does not work", strings.Join(risky, ", "))
		}
	}
	// Pack 96: the packets of the inner hop of a chain travel inside the
	// adapter of the outer hop, so they have to fit into its MTU and not
	// into 1500. Up to pack 95 this check could not see the 1435 byte
	// packets of a chain with S4 15 against 1420 of WARP.
	wire := sizeCheckWire
	if conf.ChainIsHiddenHopName(i.PinEndpointVia) {
		wire = conf.ChainHop1MTU
	}
	if total := mtu + s4 + sizeCheckTransport + sizeCheckIPUDP; total > wire {
		found = true
		log.Printf("[WarpAm] Size check: MTU %d + S4 %d + 32 + 28 is %d bytes, more than %d; full packets can be cut on the way", mtu, s4, total, wire)
	}
	if !found && len(harmless) == 0 {
		log.Printf("[WarpAm] Size check: no length matches")
	}
}
