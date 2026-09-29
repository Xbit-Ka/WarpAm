//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 74: the wires of the local proxy.
 *
 * Everything the proxy sends has to leave through the adapter of one tunnel
 * and through nothing else. On Windows that is not a question of routes: a
 * socket can be nailed to an interface with IP_UNICAST_IF, and then the
 * routing table has no say in the matter. The chain already uses that trick
 * to pin the endpoint of a hop (core/tunnel/pinendpoint.go), and the proxy
 * uses the same one.
 *
 * This is what makes the "separate" mode safe. The tunnel there installs no
 * default route at all, so a socket that is not pinned would simply go out
 * through the provider. A pinned socket cannot: with the adapter gone the
 * connection fails, and a failed connection is exactly what we want instead
 * of a leak.
 */

package manager

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	// IP_UNICAST_IF and IPV6_UNICAST_IF, both option 31 of their level.
	chainProxyUnicastIf = 31

	// chainProxyDialTimeout is how long one outgoing connection may take
	// to come up. Through two hops a second is not enough, ten is plenty.
	chainProxyDialTimeout = 10 * time.Second
	// chainProxyDNSTimeout is the same for a single DNS query.
	chainProxyDNSTimeout = 5 * time.Second

	// chainProxyErrAccess is WSAEACCES. Windows answers with it when the
	// packet filter refuses the socket, which is what a missing door in
	// the kill switch looks like from inside the proxy. Pack 84 tells it
	// apart from a timeout, because the two need opposite answers: one is
	// our own rule set, the other is the way out.
	chainProxyErrAccess = syscall.Errno(10013)
)

// chainProxyWhy says in plain words why a socket failed, so that the log
// and the SOCKS answer carry the reason instead of a bare code.
func chainProxyWhy(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == chainProxyErrAccess {
		return "the packet filter refused the socket (WSAEACCES 10013), so the kill switch has no door for it"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "nothing answered in time, so the packets are being dropped on the way"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "nothing answered in time, so the packets are being dropped on the way"
	}
	// Pack 87: a DNS error of the standard library carries the resolver it
	// read from the settings of the machine, not the one the packets went
	// to. Ours go to the resolvers of the tunnel, through the tunnel, so
	// that address made the line contradict itself: "asked 1.1.1.1,
	// 1.0.0.1" and then "on 8.8.8.8:53: no such host" in the same
	// sentence. Only the reason is kept, and a name that simply has no
	// address of the kind that was asked for is said plainly, because that
	// is not a failure of the tunnel at all.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "the resolvers of the tunnel answered that the name has no address of the kind that was asked for"
		}
		if dnsErr.IsTimeout {
			return "nothing answered in time, so the packets are being dropped on the way"
		}
		if len(dnsErr.Err) != 0 {
			return dnsErr.Err
		}
	}
	return err.Error()
}

// chainProxyIfaceIndex gives the interface index of a tunnel adapter, which
// is what IP_UNICAST_IF wants. A tunnel that is not up has no index, and the
// error is the honest answer to "send this through the tunnel".
func chainProxyIfaceIndex(name string) (uint32, error) {
	luid, ok := chainAdapterLUID(name)
	if !ok {
		return 0, fmt.Errorf("the adapter of %q is not there", name)
	}
	row, err := luid.Interface()
	if err != nil {
		return 0, err
	}
	if row.InterfaceIndex == 0 {
		return 0, fmt.Errorf("the adapter of %q has no interface index", name)
	}
	return row.InterfaceIndex, nil
}

// chainProxyPinSocket nails one socket to the interface. It is written for
// the Control hook of net.Dialer and net.ListenConfig, which hands over the
// raw handle before the socket is used.
func chainProxyPinSocket(index uint32, network string, c syscall.RawConn) error {
	if index == 0 {
		return errors.New("the tunnel interface is not known")
	}
	var inner error
	err := c.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		switch network {
		case "tcp6", "udp6", "ip6":
			inner = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, chainProxyUnicastIf, int(index))
		default:
			// MSDN: for IPv4 the index goes in network byte order, so
			// that it looks like an address with leading zeros. This is
			// the same dance as bindSocketToInterface4 in amneziawg-go.
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], index)
			value := *(*uint32)(unsafe.Pointer(&raw[0]))
			inner = windows.SetsockoptInt(handle, windows.IPPROTO_IP, chainProxyUnicastIf, int(value))
		}
	})
	if err != nil {
		return err
	}
	return inner
}

// chainProxyDialer builds a dialer whose every socket leaves through the
// given interface.
func chainProxyDialer(index uint32) *net.Dialer {
	return &net.Dialer{
		Timeout: chainProxyDialTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return chainProxyPinSocket(index, network, c)
		},
	}
}

// chainProxyDialTCP opens one outgoing connection through the tunnel.
func chainProxyDialTCP(ctx context.Context, index uint32, host string, port uint16) (net.Conn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	return chainProxyDialer(index).DialContext(ctx, "tcp4", address)
}

// chainProxyListenUDP opens a UDP socket that can only speak through the
// tunnel. It is used for one UDP session of a SOCKS5 client.
func chainProxyListenUDP(index uint32) (*net.UDPConn, error) {
	config := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return chainProxyPinSocket(index, network, c)
		},
	}
	packet, err := config.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return nil, err
	}
	conn, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, errors.New("the UDP socket of the proxy came back as something else")
	}
	return conn, nil
}

// chainProxyDNSServers lists the resolvers of the tunnel the proxy belongs
// to. They are the only ones the proxy is allowed to ask: a name resolved by
// the system resolver would be seen by the provider, which is exactly the
// leak the separate mode exists to avoid.
func chainProxyDNSServers(leaf string) []net.IP {
	c, err := conf.LoadFromName(leaf)
	if err != nil {
		return nil
	}
	servers := make([]net.IP, 0, len(c.Interface.DNS))
	for _, server := range c.Interface.DNS {
		if server.To4() != nil {
			servers = append(servers, server)
		}
	}
	return servers
}

// chainProxyResolve turns a host name into an address, asking only the DNS
// of the tunnel and only through the tunnel. An address is returned as it
// is, without asking anybody.
func chainProxyResolve(ctx context.Context, index uint32, servers []net.IP, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if four := ip.To4(); four != nil {
			return four, nil
		}
		return ip, nil
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("the tunnel has no DNS server, so %q cannot be resolved without leaking the name", host)
	}

	dialer := chainProxyDialer(index)
	var lastErr error
	for _, server := range servers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// The network the resolver asks for is honoured, so a
				// truncated answer is retried over TCP through the same
				// tunnel.
				use := "udp4"
				if network == "tcp" || network == "tcp4" || network == "tcp6" {
					use = "tcp4"
				}
				return dialer.DialContext(ctx, use, net.JoinHostPort(server.String(), "53"))
			},
		}
		lookupCtx, cancel := context.WithTimeout(ctx, chainProxyDNSTimeout)
		addresses, err := resolver.LookupIP(lookupCtx, "ip4", host)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		for _, address := range addresses {
			if four := address.To4(); four != nil {
				return four, nil
			}
		}
		lastErr = fmt.Errorf("%q has no IPv4 address", host)
	}
	if lastErr == nil {
		return nil, fmt.Errorf("%q could not be resolved through the tunnel", host)
	}
	// Pack 84: the caller writes this line into the log, so it says which
	// resolvers were asked and what came back instead of an answer.
	return nil, fmt.Errorf("%q could not be resolved through the tunnel (asked %s): %s", host, chainProxyDNSLine(servers), chainProxyWhy(lastErr))
}

// chainProxyDNSLine writes the resolvers that were asked, for the log.
func chainProxyDNSLine(servers []net.IP) string {
	if len(servers) == 0 {
		return "nobody"
	}
	parts := make([]string, 0, len(servers))
	for _, server := range servers {
		if server == nil {
			continue
		}
		parts = append(parts, server.String())
	}
	return strings.Join(parts, ", ")
}
