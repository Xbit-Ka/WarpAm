/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// WarpAm pack 95.
//
// A transport packet on the wire is S4 + 32 + inner bytes, where inner is the
// payload after padding. With some S1..S4 that length equals S1+148, S2+92 or
// S3+64. A receiver that tries the handshake types first, as stock
// amneziawg-go on the server does, then reads four bytes of the random
// receiver index as a handshake header, and when they fall into the H1..H3
// range the packet is dropped. Pack 94 fixed our receiver, but the server
// does not run our code, so the sender has to stay away from these sizes.
// Sixteen more zero bytes of padding move the packet off the handshake size;
// the receiver strips them like any other padding.

// SetSizeDodge turns the extra padding on or off. It is on for a new device.
func (device *Device) SetSizeDodge(on bool) {
	device.sizeDodgeOff.Store(!on)
	if on {
		device.log.Verbosef("Size dodge: on")
	} else {
		device.log.Verbosef("Size dodge: off")
	}
}

// handshakeWireSize reports whether a packet of this length could be read as
// a handshake initiation, response or cookie reply.
func (device *Device) handshakeWireSize(wire int) bool {
	return wire == int(device.paddings.init.Load())+MessageInitiationSize ||
		wire == int(device.paddings.response.Load())+MessageResponseSize ||
		wire == int(device.paddings.cookie.Load())+MessageCookieReplySize
}

// dodgeHandshakeSizes returns the padding to use for a transport packet with
// junk bytes in front (S4), inner bytes of payload and pad bytes of padding
// already chosen. It only ever adds whole PaddingMultiple steps. The payload
// with padding never grows past mtu, as calculatePaddingSize guarantees, and
// the whole packet never past the message buffer. When the step does not fit,
// the packet goes as it is and is counted.
func (device *Device) dodgeHandshakeSizes(junk, inner, pad, mtu int) int {
	if device.sizeDodgeOff.Load() || device.randomTrailers.Load() {
		// With random trailers the receiver accepts any length above a
		// handshake size, so no single size can be avoided.
		return pad
	}
	wire := junk + MinMessageSize + inner + pad
	if !device.handshakeWireSize(wire) {
		return pad
	}
	limit := MaxMessageSize - junk - MinMessageSize
	if mtu > 0 && mtu < limit {
		limit = mtu
	}
	newPad := pad
	// Three target sizes at most, so the loop makes at most three steps.
	for device.handshakeWireSize(junk + MinMessageSize + inner + newPad) {
		if inner+newPad+PaddingMultiple > limit {
			if device.sizeDodgeSkipped.Add(1) == 1 {
				device.log.Errorf("Size dodge: a transport packet of %d bytes matches a handshake size and there is no room for more padding; it is sent as it is, this is logged once", wire)
			}
			return pad
		}
		newPad += PaddingMultiple
	}
	if device.sizeDodgeLogged.CompareAndSwap(false, true) {
		device.log.Verbosef("Size dodge: transport packets of %d bytes would match a handshake message, they get %d bytes more padding; this is logged once", wire, newPad-pad)
	}
	return newPad
}

// SizeDodgeSkipped returns how many packets matched a handshake size and
// could not be padded away from it.
func (device *Device) SizeDodgeSkipped() uint64 {
	return device.sizeDodgeSkipped.Load()
}
