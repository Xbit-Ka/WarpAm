//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the ping that must not be cut.
 *
 * An echo request is sent with fragmentation forbidden: IP_DONTFRAGMENT for
 * IPv4, IPV6_DONTFRAG for IPv6. A packet bigger than some link on the way
 * is then dropped instead of being cut in two, and the router either says
 * so (ICMP "fragmentation needed", ICMPv6 "packet too big", both with the
 * size it can carry) or says nothing. Either way the reply does not come,
 * and that is the answer.
 *
 * Raw sockets are used and not IcmpSendEcho2: Windows cannot forbid
 * fragmentation of an IPv6 echo through that call, so a check of a server
 * with an IPv6 address would have been a guess. The socket is bound to an
 * address of the adapter it has to leave through and nailed to that adapter
 * with IP_UNICAST_IF, so a check of a server outside never wanders into a
 * tunnel that is up, and a check inside never leaves its tunnel.
 *
 * The sizes below are whole IP packets: 1500 is a packet of 1500 bytes on
 * the wire, IP header included. The search runs from 1280 to 1500 with a
 * step of 8, which is about five tries, each tried twice with half a second
 * to answer, so one lost packet does not lower the result. A router that
 * names the size it can carry saves the rest of the search.
 */

package chainmtu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pathLow   = 1280
	pathHigh  = 1500
	pathStep  = 8
	tries     = 2
	waitOuter = 500 * time.Millisecond
	waitInner = time.Second

	ipprotoICMP   = 1
	ipprotoICMPv6 = 58
	ipDontFrag    = 14 // IP_DONTFRAGMENT, IPPROTO_IP
	ipv6DontFrag  = 14 // IPV6_DONTFRAG, IPPROTO_IPV6
	ipUnicastIf   = 31 // IP_UNICAST_IF and IPV6_UNICAST_IF
	soRcvTimeo    = 0x1006
	wsaeMsgSize   = windows.Errno(10040)
)

// The spare addresses, asked when the server itself does not answer a
// ping. Most of the time the narrow place is the own line of the machine,
// and that one is the same for every address in the world.
var (
	Spare4 = net.IPv4(1, 1, 1, 1).To4()
	Spare6 = net.ParseIP("2606:4700:4700::1111")
)

var (
	wsaOnce sync.Once
	seqMu   sync.Mutex
	seqNext uint16
)

func nextSeq() uint16 {
	seqMu.Lock()
	defer seqMu.Unlock()
	seqNext++
	return seqNext
}

// sock is one raw ICMP socket.
type sock struct {
	h  windows.Handle
	v6 bool
	id uint16
}

func open(local net.IP, index uint32, wait time.Duration) (*sock, error) {
	wsaOnce.Do(func() {
		var data windows.WSAData
		windows.WSAStartup(uint32(0x202), &data)
	})
	v6 := local.To4() == nil
	s := &sock{v6: v6, id: uint16(os.Getpid())}
	var err error
	if v6 {
		s.h, err = windows.Socket(windows.AF_INET6, windows.SOCK_RAW, ipprotoICMPv6)
	} else {
		s.h, err = windows.Socket(windows.AF_INET, windows.SOCK_RAW, ipprotoICMP)
	}
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	fail := func(what string, err error) (*sock, error) {
		windows.Closesocket(s.h)
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if v6 {
		var sa windows.SockaddrInet6
		copy(sa.Addr[:], local.To16())
		if err = windows.Bind(s.h, &sa); err != nil {
			return fail("bind", err)
		}
		if err = windows.SetsockoptInt(s.h, windows.IPPROTO_IPV6, ipv6DontFrag, 1); err != nil {
			return fail("IPV6_DONTFRAG", err)
		}
		if index != 0 {
			windows.SetsockoptInt(s.h, windows.IPPROTO_IPV6, ipUnicastIf, int(index))
		}
	} else {
		var sa windows.SockaddrInet4
		copy(sa.Addr[:], local.To4())
		if err = windows.Bind(s.h, &sa); err != nil {
			return fail("bind", err)
		}
		if err = windows.SetsockoptInt(s.h, windows.IPPROTO_IP, ipDontFrag, 1); err != nil {
			return fail("IP_DONTFRAGMENT", err)
		}
		if index != 0 {
			// The index goes in network byte order for IPv4, the same
			// dance as chainProxyPinSocket in the manager.
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], index)
			windows.SetsockoptInt(s.h, windows.IPPROTO_IP, ipUnicastIf, int(*(*uint32)(unsafe.Pointer(&raw[0]))))
		}
	}
	if err = windows.SetsockoptInt(s.h, windows.SOL_SOCKET, soRcvTimeo, int(wait/time.Millisecond)); err != nil {
		return fail("SO_RCVTIMEO", err)
	}
	return s, nil
}

func (s *sock) close() { windows.Closesocket(s.h) }

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// echo sends one request of size bytes (the whole IP packet) and waits for
// its reply. tooBig is the size a router said it can carry, zero if none.
func (s *sock) echo(dst net.IP, size int, wait time.Duration) (ok bool, tooBig int, err error) {
	header := 28
	if s.v6 {
		header = 48
	}
	if size < header+8 {
		size = header + 8
	}
	seq := nextSeq()
	pkt := make([]byte, size-header+8)
	if s.v6 {
		pkt[0] = 128
	} else {
		pkt[0] = 8
	}
	binary.BigEndian.PutUint16(pkt[4:], s.id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	for i := 8; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	if !s.v6 {
		// The stack fills in the checksum of ICMPv6 itself, because it
		// covers the addresses; for IPv4 it is ours to write.
		binary.BigEndian.PutUint16(pkt[2:], checksum(pkt))
	}
	if s.v6 {
		var sa windows.SockaddrInet6
		copy(sa.Addr[:], dst.To16())
		err = windows.Sendto(s.h, pkt, 0, &sa)
	} else {
		var sa windows.SockaddrInet4
		copy(sa.Addr[:], dst.To4())
		err = windows.Sendto(s.h, pkt, 0, &sa)
	}
	if err != nil {
		if errors.Is(err, wsaeMsgSize) {
			// Bigger than the adapter itself: the same as no reply.
			return false, 0, nil
		}
		return false, 0, err
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		n, _, rerr := windows.Recvfrom(s.h, buf, 0)
		if rerr != nil {
			if errors.Is(rerr, wsaeMsgSize) {
				continue
			}
			// The timeout of SO_RCVTIMEO, or the socket is gone.
			return false, tooBig, nil
		}
		icmp := buf[:n]
		if !s.v6 {
			if n < 20 {
				continue
			}
			ihl := int(buf[0]&0x0f) * 4
			if n < ihl+8 {
				continue
			}
			icmp = buf[ihl:n]
		}
		if len(icmp) < 8 {
			continue
		}
		kind := icmp[0]
		switch {
		case !s.v6 && kind == 0, s.v6 && kind == 129:
			if binary.BigEndian.Uint16(icmp[4:]) == s.id && binary.BigEndian.Uint16(icmp[6:]) == seq {
				return true, 0, nil
			}
		case !s.v6 && kind == 3 && icmp[1] == 4:
			// Fragmentation needed: the original header follows.
			inner := icmp[8:]
			if len(inner) < 28 {
				continue
			}
			ihl := int(inner[0]&0x0f) * 4
			if len(inner) < ihl+8 {
				continue
			}
			orig := inner[ihl:]
			if binary.BigEndian.Uint16(orig[4:]) == s.id && binary.BigEndian.Uint16(orig[6:]) == seq {
				tooBig = int(binary.BigEndian.Uint16(icmp[6:]))
			}
		case s.v6 && kind == 2:
			// Packet too big: the MTU, then the original packet.
			if len(icmp) < 8+40+8 {
				continue
			}
			orig := icmp[48:]
			if binary.BigEndian.Uint16(orig[4:]) == s.id && binary.BigEndian.Uint16(orig[6:]) == seq {
				tooBig = int(binary.BigEndian.Uint32(icmp[4:]))
			}
		}
	}
	return false, tooBig, nil
}

// passes tries one size twice.
func (s *sock) passes(dst net.IP, size int, wait time.Duration) (bool, int, error) {
	hint := 0
	for i := 0; i < tries; i++ {
		ok, tooBig, err := s.echo(dst, size, wait)
		if err != nil {
			return false, 0, err
		}
		if ok {
			return true, 0, nil
		}
		if tooBig > 0 {
			hint = tooBig
			// A router has spoken, a second try changes nothing.
			break
		}
	}
	return false, hint, nil
}

// Result is what a check found outside.
type Result struct {
	Path   int
	Target net.IP
	Took   time.Duration
	Probes int
}

// PathMTU finds the largest packet that reaches server from the adapter of
// the network here, or from the spare address of the same family when the
// server does not answer a ping.
func PathMTU(here Here, server net.IP) (Result, error) {
	began := time.Now()
	res := Result{}
	if server == nil {
		return res, errors.New("the server has no address")
	}
	local, spare := here.Local4, Spare4
	if server.To4() == nil {
		local, spare = here.Local6, Spare6
	}
	if local == nil {
		if server.To4() == nil {
			return res, errors.New("the adapter of this network has no IPv6 address")
		}
		return res, errors.New("the adapter of this network has no IPv4 address")
	}
	s, err := open(local, here.Index, waitOuter)
	if err != nil {
		return res, err
	}
	defer s.close()

	target := server
	ok, _, err := s.passes(target, pathLow, waitOuter)
	res.Probes++
	if err != nil {
		return res, err
	}
	if !ok {
		target = spare
		ok, _, err = s.passes(target, pathLow, waitOuter)
		res.Probes++
		if err != nil {
			return res, err
		}
		if !ok {
			res.Took = time.Since(began)
			return res, fmt.Errorf("neither %s nor %s answers a ping of %d bytes", server, spare, pathLow)
		}
	}
	res.Target = target

	low, high := pathLow, pathHigh+pathStep
	ok, hint, err := s.passes(target, pathHigh, waitOuter)
	res.Probes++
	if err != nil {
		return res, err
	}
	if ok {
		low = pathHigh
	} else {
		high = pathHigh
		if hint > low && hint < high {
			// The router named its size: that one is tried first.
			ok, _, err = s.passes(target, hint, waitOuter)
			res.Probes++
			if err != nil {
				return res, err
			}
			if ok {
				low = hint
				ok, _, _ = s.passes(target, hint+1, waitOuter)
				res.Probes++
				if !ok {
					high = hint + 1
				}
			} else {
				high = hint
			}
		}
		for high-low > pathStep {
			mid := low + (high-low)/(2*pathStep)*pathStep
			if mid <= low {
				mid = low + pathStep
			}
			ok, hint, err = s.passes(target, mid, waitOuter)
			res.Probes++
			if err != nil {
				return res, err
			}
			if ok {
				low = mid
			} else {
				high = mid
				if hint > low && hint < high {
					high = hint + 1
				}
			}
		}
	}
	res.Path = low
	res.Took = time.Since(began)
	return res, nil
}

// Inner is what the check inside a raised tunnel found.
type Inner struct {
	// Answered is false when not even a small ping came back: the
	// address inside does not answer pings, and nothing can be said.
	Answered bool
	// Fits is the MTU that got through, zero when none of the tries did.
	Fits  int
	Tried []int
}

// InnerCheck pings target through the adapter index from local, first a
// small packet, then a packet as big as the MTU, then 16, 32 and 48 bytes
// less. The small ping is tried for a few seconds, because the first
// handshake of a tunnel that has just come up may still be on its way.
//
// WarpAm pack 113: when a smaller size gets through, the exact border
// between it and the size 16 bytes above, which did not, is found by
// halving. On 8.10 both tunnels of a stack failed at the counted MTU and
// passed 16 bytes lower, so up to 15 bytes were given away every time.
func InnerCheck(local net.IP, index uint32, target net.IP, mtu int) (Inner, error) {
	out := Inner{}
	s, err := open(local, index, waitInner)
	if err != nil {
		return out, err
	}
	defer s.close()
	for i := 0; i < 5 && !out.Answered; i++ {
		ok, _, err := s.echo(target, 100, waitInner)
		if err != nil {
			return out, err
		}
		out.Answered = ok
	}
	if !out.Answered {
		return out, nil
	}
	for step := 0; step <= 3; step++ {
		size := mtu - 16*step
		out.Tried = append(out.Tried, size)
		ok, _, err := s.passes(target, size, waitInner)
		if err != nil {
			return out, err
		}
		if ok {
			out.Fits = size
			break
		}
	}
	if out.Fits == 0 || out.Fits == mtu {
		return out, nil
	}
	low, high := out.Fits, out.Fits+16
	for high-low > 1 {
		mid := low + (high-low)/2
		out.Tried = append(out.Tried, mid)
		ok, _, err := s.passes(target, mid, waitInner)
		if err != nil {
			return out, err
		}
		if ok {
			low = mid
		} else {
			high = mid
		}
	}
	out.Fits = low
	return out, nil
}
