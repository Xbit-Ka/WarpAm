/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 WarpAm. All Rights Reserved.
 */

package tunnel

// WarpAm pack 100: the address swap.
//
// Every account of WARP gets 172.16.0.2, and Windows does not let two
// adapters hold one address, so a second tunnel with the same address did
// not come up at all. Now, and only when the real address already sits on
// another adapter that is up, the adapter of this tunnel gets its own
// address for Windows, and the swap below changes it back on the fly: the
// source of every packet that leaves Windows becomes the real address, the
// destination of every packet that comes in becomes the Windows address.
// The server never sees the Windows address.
//
// The engine talks to the adapter only through Read and Write
// (amneziawg-go/tun/tun.go), so the swap is a wrapper around the adapter
// and does not touch the encryption or the masking. Wintun gives one packet
// per call and Read and Write each run on one goroutine, so the packets are
// changed right in their buffers and no lock is needed. The firewall and
// the watcher keep the real adapter.
//
// The checksums are changed by the difference (RFC 1624): IP, TCP and UDP,
// a UDP sum of zero stays zero, TCP and UDP only in the first fragment. An
// ICMP error (3, 11, 12) carries the header of the packet it is about, and
// that header is swapped too, otherwise the MTU of the path cannot be
// found. ICMP echo has no address inside and is left alone.
//
// Pack 101: IPv6 is swapped the same way, because accounts of WARP with
// different keys turned out to share one IPv6 address too. The Windows
// address is the real one plus one in the last byte, then the spare range
// fd57:6172:7041:6d00::/64. IPv6 has no sum in its header, but the sums of
// TCP, UDP and ICMPv6 all carry the addresses, so they are mended. The
// extension headers are walked to reach them, and an ICMPv6 error (1 to 4)
// gets the packet inside it swapped and its whole sum counted again.

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// One service runs one tunnel, so the plan of the swap is kept here. Both
// are nil while there is no swap.
var (
	chainSwapReal  net.IP
	chainSwapShown net.IP

	chainSwapReal6  net.IP
	chainSwapShown6 net.IP
)

// chainSwapFreeRoute is the shortest mask of a route that makes an address
// taken. The default routes and the halves of the internet that tunnels
// put on their adapters cover everything and say nothing about one
// address.
const chainSwapFreeRoute = 16

type chainSwapLook struct {
	addrs  []net.IP
	nets   []net.IPNet
	routes []net.IPNet
}

func (look *chainSwapLook) free(ip net.IP) bool {
	for _, a := range look.addrs {
		if a.Equal(ip) {
			return false
		}
	}
	for _, n := range look.nets {
		if n.Contains(ip) {
			return false
		}
	}
	for _, n := range look.routes {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// chainAddrSwapPlan decides whether this tunnel needs the swap and which
// address Windows gets. It writes one line into the log only when there
// is something to say.
func chainAddrSwapPlan(c *conf.Config) {
	chainAddrSwapPlan4(c)
	chainAddrSwapPlan6(c)
}

func chainAddrSwapPlan4(c *conf.Config) {
	chainSwapReal, chainSwapShown = nil, nil
	var real net.IP
	for i := range c.Interface.Addresses {
		if c.Interface.Addresses[i].Bits() == 32 {
			real = c.Interface.Addresses[i].IP.To4()
			break
		}
	}
	if real == nil {
		return
	}
	ifaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		log.Printf("[WarpAm] The address swap could not read the adapters: %v. %s keeps %s", err, c.Name, real)
		return
	}
	look := chainSwapLook{}
	owner := ""
	for _, iface := range ifaces {
		name := iface.FriendlyName()
		mine := strings.EqualFold(name, c.Name)
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP().To4()
			if ip == nil {
				continue
			}
			if mine {
				continue
			}
			look.addrs = append(look.addrs, ip)
			if address.OnLinkPrefixLength > 0 && address.OnLinkPrefixLength < 32 {
				look.nets = append(look.nets, net.IPNet{IP: ip.Mask(net.CIDRMask(int(address.OnLinkPrefixLength), 32)), Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 32)})
			}
			if ip.Equal(real) && iface.OperStatus == winipcfg.IfOperStatusUp && len(owner) == 0 {
				owner = name
			}
		}
	}
	if len(owner) == 0 {
		return
	}
	if routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET); err == nil {
		for i := range routes {
			n := routes[i].DestinationPrefix.IPNet()
			if ones, _ := n.Mask.Size(); ones >= chainSwapFreeRoute && ones < 32 {
				look.routes = append(look.routes, n)
			} else if ones == 32 {
				look.addrs = append(look.addrs, n.IP)
			}
		}
	}
	shown := chainSwapPick(real, &look)
	if shown == nil {
		log.Printf("[WarpAm] The address %s is already taken by %s, and no free address was found for Windows, so %s cannot come up next to it", real, owner, c.Name)
		return
	}
	chainSwapReal, chainSwapShown = real, shown
	log.Printf("[WarpAm] The address %s is already taken by %s, so in Windows %s has %s/32 and WarpAm swaps it for %s on the fly", real, owner, c.Name, shown, real)
}

// chainSwapPick is the real address plus one, then plus two and so on in
// the same /24 without .0, .1 and .255, and then the spare range
// 10.200.0.0/16.
func chainSwapPick(real net.IP, look *chainSwapLook) net.IP {
	for k := 1; k < 256; k++ {
		last := (int(real[3]) + k) % 256
		if last == 0 || last == 1 || last == 255 || last == int(real[3]) {
			continue
		}
		ip := net.IPv4(real[0], real[1], real[2], byte(last)).To4()
		if look.free(ip) {
			return ip
		}
	}
	for third := 0; third < 256; third++ {
		for last := 2; last < 255; last++ {
			ip := net.IPv4(10, 200, byte(third), byte(last)).To4()
			if look.free(ip) {
				return ip
			}
		}
	}
	return nil
}

// chainAddrSwapPlan6 is chainAddrSwapPlan4 for the IPv6 address of the
// tunnel, an address with a /128 mask.
func chainAddrSwapPlan6(c *conf.Config) {
	chainSwapReal6, chainSwapShown6 = nil, nil
	var real net.IP
	for i := range c.Interface.Addresses {
		a := c.Interface.Addresses[i]
		if a.Bits() == 128 && a.IP.To4() == nil {
			real = a.IP.To16()
			break
		}
	}
	if real == nil {
		return
	}
	ifaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET6, winipcfg.GAAFlagDefault)
	if err != nil {
		log.Printf("[WarpAm] The address swap could not read the IPv6 adapters: %v. %s keeps %s", err, c.Name, real)
		return
	}
	look := chainSwapLook{}
	owner := ""
	for _, iface := range ifaces {
		name := iface.FriendlyName()
		if strings.EqualFold(name, c.Name) {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			if ip == nil || ip.To4() != nil {
				continue
			}
			ip = ip.To16()
			look.addrs = append(look.addrs, ip)
			if address.OnLinkPrefixLength > 0 && address.OnLinkPrefixLength < 128 {
				m := net.CIDRMask(int(address.OnLinkPrefixLength), 128)
				look.nets = append(look.nets, net.IPNet{IP: ip.Mask(m), Mask: m})
			}
			if ip.Equal(real) && iface.OperStatus == winipcfg.IfOperStatusUp && len(owner) == 0 {
				owner = name
			}
		}
	}
	if len(owner) == 0 {
		return
	}
	// The halves of the internet (::/1 and 8000::/1) and the default route
	// are shorter than /48 and say nothing about one address.
	if routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET6); err == nil {
		for i := range routes {
			n := routes[i].DestinationPrefix.IPNet()
			if ones, _ := n.Mask.Size(); ones >= 48 && ones < 128 {
				look.routes = append(look.routes, n)
			} else if ones == 128 {
				look.addrs = append(look.addrs, n.IP)
			}
		}
	}
	shown := chainSwapPick6(real, &look)
	if shown == nil {
		log.Printf("[WarpAm] The address %s is already taken by %s, and no free IPv6 address was found for Windows, so %s cannot come up next to it", real, owner, c.Name)
		return
	}
	chainSwapReal6, chainSwapShown6 = real, shown
	log.Printf("[WarpAm] The address %s is already taken by %s, so in Windows %s has %s/128 and WarpAm swaps it for %s on the fly", real, owner, c.Name, shown, real)
}

// chainSwapPick6 is the real address plus one, plus two and so on in the
// last byte without zero, and then the spare unique local range
// fd57:6172:7041:6d00::/64 ("WarpAm" in hex).
func chainSwapPick6(real net.IP, look *chainSwapLook) net.IP {
	for k := 1; k < 256; k++ {
		last := (int(real[15]) + k) % 256
		if last == 0 {
			continue
		}
		ip := make(net.IP, 16)
		copy(ip, real)
		ip[15] = byte(last)
		if look.free(ip) {
			return ip
		}
	}
	spare := net.ParseIP("fd57:6172:7041:6d00::").To16()
	for k := 2; k < 0x10000; k++ {
		ip := make(net.IP, 16)
		copy(ip, spare)
		ip[14], ip[15] = byte(k>>8), byte(k)
		if look.free(ip) {
			return ip
		}
	}
	return nil
}

// chainAddrSwapAddress is the address Windows puts on the adapter in place
// of the real one, or the real one when there is no swap.
func chainAddrSwapAddress(a net.IPNet) net.IPNet {
	if chainSwapShown != nil && a.IP.Equal(chainSwapReal) {
		return net.IPNet{IP: chainSwapShown, Mask: net.CIDRMask(32, 32)}
	}
	if chainSwapShown6 != nil && a.IP.Equal(chainSwapReal6) {
		return net.IPNet{IP: chainSwapShown6, Mask: net.CIDRMask(128, 128)}
	}
	return a
}

// chainAddrSwapWrap puts the swap around the adapter the engine gets.
func chainAddrSwapWrap(d tun.Device) tun.Device {
	if chainSwapShown == nil && chainSwapShown6 == nil {
		return d
	}
	t := &chainSwapTun{Device: d}
	if chainSwapShown != nil {
		t.has4 = true
		copy(t.real[:], chainSwapReal)
		copy(t.shown[:], chainSwapShown)
	}
	if chainSwapShown6 != nil {
		t.has6 = true
		copy(t.real6[:], chainSwapReal6.To16())
		copy(t.shown6[:], chainSwapShown6.To16())
	}
	return t
}

type chainSwapTun struct {
	tun.Device
	has4   bool
	has6   bool
	real   [4]byte
	shown  [4]byte
	real6  [16]byte
	shown6 [16]byte
}

// Read gives the engine what Windows sends: the source becomes real.
func (t *chainSwapTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		t.swap(bufs[i][offset:offset+sizes[i]], true)
	}
	return n, err
}

// Write gives Windows what came from the server: the destination becomes
// the Windows address.
func (t *chainSwapTun) Write(bufs [][]byte, offset int) (int, error) {
	for i := range bufs {
		if len(bufs[i]) > offset {
			t.swap(bufs[i][offset:], false)
		}
	}
	return t.Device.Write(bufs, offset)
}

// swap sends one packet to the swap of its family, if that family has one.
func (t *chainSwapTun) swap(p []byte, out bool) {
	if len(p) == 0 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		if !t.has4 {
			return
		}
		if out {
			chainSwapPacket(p, t.shown, t.real, true)
		} else {
			chainSwapPacket(p, t.real, t.shown, false)
		}
	case 6:
		if !t.has6 {
			return
		}
		if out {
			chainSwapPacket6(p, t.shown6, t.real6, true)
		} else {
			chainSwapPacket6(p, t.real6, t.shown6, false)
		}
	}
}

// chainSwapPacket swaps from for to in the source (out) or the destination
// of one IPv4 packet and mends the sums.
func chainSwapPacket(p []byte, from, to [4]byte, out bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || total < ihl || total > len(p) {
		return
	}
	p = p[:total]
	at := 16
	if out {
		at = 12
	}
	if !chainSwapSame(p[at:at+4], from) {
		return
	}
	copy(p[at:at+4], to[:])
	chainSwapSum(p[10:12], from, to)
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return
	}
	l4 := p[ihl:]
	switch p[9] {
	case 6, 17:
		chainSwapL4(p[9], l4, from, to)
	case 1:
		if len(l4) < 8+20 || (l4[0] != 3 && l4[0] != 11 && l4[0] != 12) {
			return
		}
		if chainSwapInner(l4[8:], from, to, out) {
			l4[2], l4[3] = 0, 0
			binary.BigEndian.PutUint16(l4[2:4], chainSwapFull(l4))
		}
	}
}

// chainSwapInner swaps the header inside an ICMP error. An error Windows
// sends is about a packet that came in, so its destination is swapped; an
// error that comes in is about a packet Windows sent, so its source is.
func chainSwapInner(q []byte, from, to [4]byte, out bool) bool {
	if q[0]>>4 != 4 {
		return false
	}
	ihl := int(q[0]&0x0f) * 4
	if ihl < 20 || ihl > len(q) {
		return false
	}
	at := 12
	if out {
		at = 16
	}
	if !chainSwapSame(q[at:at+4], from) {
		return false
	}
	copy(q[at:at+4], to[:])
	chainSwapSum(q[10:12], from, to)
	if binary.BigEndian.Uint16(q[6:8])&0x1fff == 0 {
		chainSwapL4(q[9], q[ihl:], from, to)
	}
	return true
}

// chainSwapL4 mends the sum of TCP or UDP, whose pseudo header carries the
// addresses. A part that is cut off is left alone.
func chainSwapL4(proto byte, l4 []byte, from, to [4]byte) {
	switch proto {
	case 6:
		if len(l4) >= 18 {
			chainSwapSum(l4[16:18], from, to)
		}
	case 17:
		if len(l4) >= 8 && (l4[6] != 0 || l4[7] != 0) {
			chainSwapSum(l4[6:8], from, to)
			if l4[6] == 0 && l4[7] == 0 {
				l4[6], l4[7] = 0xff, 0xff
			}
		}
	}
}

func chainSwapSame(b []byte, a [4]byte) bool {
	return b[0] == a[0] && b[1] == a[1] && b[2] == a[2] && b[3] == a[3]
}

// chainSwapSum is RFC 1624, equation 3: HC' = ~(~HC + ~m + m').
func chainSwapSum(sum []byte, from, to [4]byte) {
	s := uint32(^binary.BigEndian.Uint16(sum))
	for k := 0; k < 4; k += 2 {
		s += uint32(^binary.BigEndian.Uint16(from[k : k+2]))
		s += uint32(binary.BigEndian.Uint16(to[k : k+2]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	binary.BigEndian.PutUint16(sum, ^uint16(s))
}

// chainSwapFull is the whole sum of an ICMP message, whose sum field is
// zero while it is counted.
func chainSwapFull(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// chainSwapPacket6 swaps from for to in the source (out) or the destination
// of one IPv6 packet and mends the sums of the upper layer.
func chainSwapPacket6(p []byte, from, to [16]byte, out bool) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return
	}
	total := 40 + int(binary.BigEndian.Uint16(p[4:6]))
	if total > len(p) {
		return
	}
	p = p[:total]
	at := 24
	if out {
		at = 8
	}
	if !bytes.Equal(p[at:at+16], from[:]) {
		return
	}
	copy(p[at:at+16], to[:])
	proto, off, frag, ok := chainSwapNext6(p)
	if !ok {
		return
	}
	l4 := p[off:]
	switch proto {
	case 6, 17:
		chainSwapL46(proto, l4, from, to)
	case 58:
		if len(l4) < 4 {
			return
		}
		// An error carries the packet it is about; once that is swapped the
		// sum is counted again. A fragment holds only a part of the message,
		// so there only the change of the address is applied.
		if !frag && len(l4) >= 8+40 && l4[0] >= 1 && l4[0] <= 4 && chainSwapInner6(l4[8:], from, to, out) {
			l4[2], l4[3] = 0, 0
			binary.BigEndian.PutUint16(l4[2:4], chainSwapFull6(p[8:24], p[24:40], l4))
			return
		}
		chainSwapSum6(l4[2:4], from, to)
	}
}

// chainSwapNext6 walks the extension headers up to the upper layer. ok is
// false when the upper header is not in this packet: a later fragment or a
// header that is cut off. frag says the packet is the first fragment.
func chainSwapNext6(p []byte) (proto byte, off int, frag bool, ok bool) {
	proto, off = p[6], 40
	for i := 0; i < 8; i++ {
		switch proto {
		case 0, 43, 60:
			if off+8 > len(p) {
				return proto, off, frag, false
			}
			proto, off = p[off], off+(int(p[off+1])+1)*8
		case 44:
			if off+8 > len(p) {
				return proto, off, frag, false
			}
			if binary.BigEndian.Uint16(p[off+2:off+4])&0xfff8 != 0 {
				return proto, off, true, false
			}
			frag = true
			proto, off = p[off], off+8
		case 51:
			if off+8 > len(p) {
				return proto, off, frag, false
			}
			proto, off = p[off], off+(int(p[off+1])+2)*4
		default:
			return proto, off, frag, off <= len(p)
		}
	}
	return proto, off, frag, false
}

// chainSwapInner6 swaps the header inside an ICMPv6 error, the same way as
// chainSwapInner does for IPv4.
func chainSwapInner6(q []byte, from, to [16]byte, out bool) bool {
	if len(q) < 40 || q[0]>>4 != 6 {
		return false
	}
	at := 8
	if out {
		at = 24
	}
	if !bytes.Equal(q[at:at+16], from[:]) {
		return false
	}
	copy(q[at:at+16], to[:])
	if proto, off, _, ok := chainSwapNext6(q); ok {
		switch proto {
		case 6, 17:
			chainSwapL46(proto, q[off:], from, to)
		case 58:
			if len(q)-off >= 4 {
				chainSwapSum6(q[off+2:off+4], from, to)
			}
		}
	}
	return true
}

// chainSwapL46 mends the sum of TCP or UDP over IPv6. A part that is cut
// off is left alone. UDP over IPv6 always has a sum, so a sum that comes
// out as zero is written as 0xffff.
func chainSwapL46(proto byte, l4 []byte, from, to [16]byte) {
	switch proto {
	case 6:
		if len(l4) >= 18 {
			chainSwapSum6(l4[16:18], from, to)
		}
	case 17:
		if len(l4) >= 8 {
			chainSwapSum6(l4[6:8], from, to)
			if l4[6] == 0 && l4[7] == 0 {
				l4[6], l4[7] = 0xff, 0xff
			}
		}
	}
}

// chainSwapSum6 is chainSwapSum for an address of sixteen bytes.
func chainSwapSum6(sum []byte, from, to [16]byte) {
	s := uint32(^binary.BigEndian.Uint16(sum))
	for k := 0; k < 16; k += 2 {
		s += uint32(^binary.BigEndian.Uint16(from[k : k+2]))
		s += uint32(binary.BigEndian.Uint16(to[k : k+2]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	binary.BigEndian.PutUint16(sum, ^uint16(s))
}

// chainSwapFull6 is the whole sum of an ICMPv6 message with its pseudo
// header (RFC 8200, 8.1). The sum field is zero while it is counted.
func chainSwapFull6(src, dst, b []byte) uint16 {
	var s uint32
	for i := 0; i < 16; i += 2 {
		s += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		s += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	s += uint32(len(b)>>16) + uint32(len(b)&0xffff)
	s += 58
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
