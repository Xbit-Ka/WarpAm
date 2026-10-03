/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"testing"
)

// WarpAm pack 95: tests of sizedodge.go.

func newDodgeDevice(s1, s2, s3, s4 uint32) *Device {
	d := &Device{log: NewLogger(LogLevelSilent, "")}
	d.paddings.init.Store(s1)
	d.paddings.response.Store(s2)
	d.paddings.cookie.Store(s3)
	d.paddings.transport.Store(s4)
	return d
}

// checkDodge pads every payload length the way the send path does and checks
// that the wire length never equals a handshake size, unless the packet was
// counted as one that had no room.
func checkDodge(t *testing.T, d *Device, mtu int) {
	t.Helper()
	junk := int(d.paddings.transport.Load())
	for inner := 0; inner <= mtu; inner++ {
		pad := calculatePaddingSize(inner, mtu)
		before := d.SizeDodgeSkipped()
		got := d.dodgeHandshakeSizes(junk, inner, pad, mtu)
		if got < pad || (got-pad)%PaddingMultiple != 0 {
			t.Fatalf("S4=%d inner=%d: padding %d is not %d plus whole steps", junk, inner, got, pad)
		}
		if got > pad && inner+got > mtu {
			t.Fatalf("S4=%d inner=%d: padding %d goes past mtu %d", junk, inner, got, mtu)
		}
		wire := junk + MinMessageSize + inner + got
		if d.handshakeWireSize(wire) {
			if got != pad || d.SizeDodgeSkipped() != before+1 {
				t.Fatalf("S1=%d S2=%d S3=%d S4=%d inner=%d: wire %d still matches a handshake",
					d.paddings.init.Load(), d.paddings.response.Load(), d.paddings.cookie.Load(), junk, inner, wire)
			}
		}
	}
}

func TestSizeDodgeAllPaddings(t *testing.T) {
	step := 1
	if testing.Short() {
		step = 7
	}
	for s4 := 0; s4 <= 64; s4 += step {
		for s := 0; s <= 64; s += step {
			// One of S1..S3 runs over the range, the other two stay at
			// values of their own, so every pair of sizes meets.
			checkDodge(t, newDodgeDevice(uint32(s), 17, 33, uint32(s4)), 1420)
			checkDodge(t, newDodgeDevice(5, uint32(s), 33, uint32(s4)), 1420)
			checkDodge(t, newDodgeDevice(5, 17, uint32(s), uint32(s4)), 1420)
		}
	}
	// All three sizes in a row, 16 apart, need three steps.
	checkDodge(t, newDodgeDevice(16, 88, 132, 0), 1420)
	// No mtu, the message buffer is the only limit.
	checkDodge(t, newDodgeDevice(19, 19, 19, 15), 0)
}

func TestSizeDodgeOffAndTrailers(t *testing.T) {
	d := newDodgeDevice(0, 19, 0, 15)
	if got := d.dodgeHandshakeSizes(15, 49, 15, 1420); got != 31 {
		t.Fatalf("on: padding %d, want 31", got)
	}
	d.SetSizeDodge(false)
	if got := d.dodgeHandshakeSizes(15, 49, 15, 1420); got != 15 {
		t.Fatalf("off: padding %d, want 15", got)
	}
	d.SetSizeDodge(true)
	d.randomTrailers.Store(true)
	if got := d.dodgeHandshakeSizes(15, 49, 15, 1420); got != 15 {
		t.Fatalf("random trailers: padding %d, want 15", got)
	}
}

// The case of 30 September: S2=19, S4=15, an inner packet of 49 bytes. Before
// the dodge the packet is 111 bytes and, with the receiver index in the H2
// range, a receiver without pack 94 takes it for a response. After the dodge
// it is 127 bytes and only reads as transport.
func TestSizeDodgeClassifier(t *testing.T) {
	d := newDodgeDevice(0, 19, 0, 15)
	var r UintRange
	r.FromUint32(100, 200)
	d.headers.init.Store(r)
	r.FromUint32(1514070810, 1786185381)
	d.headers.response.Store(r)
	r.FromUint32(300, 400)
	d.headers.cookie.Store(r)
	r.FromUint32(500, 600)
	d.headers.transport.Store(r)

	build := func(pad int) []byte {
		p := make([]byte, 15+MinMessageSize+49+pad)
		binary.LittleEndian.PutUint32(p[15:], 550)        // H4 at offset S4
		binary.LittleEndian.PutUint32(p[19:], 1600000000) // receiver index, falls into H2 at offset S2
		return p
	}
	typeHash := make([]byte, 16)

	pad := calculatePaddingSize(49, 1420)
	if _, typ, _ := d.DeterminePacketTypeAndPadding(build(pad), typeHash); typ != MessageResponseType {
		t.Fatalf("without the dodge the 111 byte packet reads as type %d, the test setup is wrong", typ)
	}
	pad = d.dodgeHandshakeSizes(15, 49, pad, 1420)
	if _, typ, _ := d.DeterminePacketTypeAndPadding(build(pad), typeHash); typ != MessageTransportType {
		t.Fatalf("with the dodge the packet reads as type %d, want transport", typ)
	}
}
