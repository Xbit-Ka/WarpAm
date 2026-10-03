//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 74: SOCKS5 for the local proxy.
 *
 * One port carries both protocols. The first byte of a connection decides:
 * 0x05 is SOCKS5, anything else is read as HTTP. Nothing is guessed twice,
 * the byte is only peeked at and stays in the stream.
 *
 * What is supported: CONNECT over TCP and UDP ASSOCIATE, with and without a
 * login. BIND is not supported and is refused honestly, as almost nothing
 * uses it.
 */

package manager

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	chainSocksVersion = 0x05
	chainSocksAuthVer = 0x01

	chainSocksNoAuth   = 0x00
	chainSocksUserPass = 0x02
	chainSocksNoneOk   = 0xFF

	chainSocksConnect = 0x01
	chainSocksUDP     = 0x03

	chainSocksIPv4   = 0x01
	chainSocksDomain = 0x03
	chainSocksIPv6   = 0x04

	chainSocksOK          = 0x00
	chainSocksFailure     = 0x01
	chainSocksNotAllowed  = 0x02
	chainSocksHostUnreach = 0x04
	chainSocksCmdUnsup    = 0x07

	// chainProxyHandshakeWait is how long the client has to say what it
	// wants before it is dropped.
	chainProxyHandshakeWait = 30 * time.Second
)

// needAuth says whether a login is asked for. It is set together with the
// "listen on the local network" mode and cannot be switched off there.
func (p *chainProxy) needAuth() bool {
	return len(p.passHash) > 0 && len(p.user) > 0
}

// serve reads the first byte and hands the connection to the right protocol.
func (p *chainProxy) serve(c net.Conn) {
	p.track(c)
	defer func() {
		p.forget(c)
		c.Close()
	}()

	c.SetDeadline(time.Now().Add(chainProxyHandshakeWait))
	reader := bufio.NewReader(c)
	head, err := reader.Peek(1)
	if err != nil {
		return
	}

	socks := head[0] == chainSocksVersion
	switch {
	case socks && p.protocol != ChainProxyProtoHTTP:
		p.serveSocks(c, reader)
	case !socks && p.protocol != ChainProxyProtoSocks5:
		p.serveHTTP(c, reader)
	case socks:
		// Pack 97: these two refusals used to leave no trace at all.
		p.refused(c, "it spoke SOCKS5 to a proxy set to HTTP only")
		p.socksReply(c, chainSocksNotAllowed, net.IPv4zero, 0)
	default:
		p.refused(c, "it spoke HTTP to a proxy set to SOCKS5 only")
		const text = "WarpAm: this proxy speaks SOCKS5 only"
		c.Write([]byte("HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(text)) + "\r\nConnection: close\r\n\r\n" + text))
	}
}

// socksReply writes one answer of the request stage.
func (p *chainProxy) socksReply(c net.Conn, code byte, ip net.IP, port uint16) error {
	four := ip.To4()
	if four == nil {
		four = net.IPv4zero.To4()
	}
	answer := []byte{chainSocksVersion, code, 0x00, chainSocksIPv4, four[0], four[1], four[2], four[3], 0, 0}
	binary.BigEndian.PutUint16(answer[8:], port)
	_, err := c.Write(answer)
	return err
}

// serveSocks walks one client through the SOCKS5 conversation.
func (p *chainProxy) serveSocks(c net.Conn, reader *bufio.Reader) {
	// Greeting: version, how many methods, the methods themselves.
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	want := byte(chainSocksNoAuth)
	if p.needAuth() {
		want = chainSocksUserPass
	}
	offered := false
	for _, method := range methods {
		if method == want {
			offered = true
			break
		}
	}
	if !offered {
		// Pack 98: only a guess, a browser is the usual suspect.
		if want == chainSocksUserPass {
			p.refused(c, "the program offered no login, and this proxy asks for one (perhaps a browser: many of them do not send a SOCKS5 login, HTTP may help)")
		} else {
			p.refused(c, "the program offered only a login, and this proxy has none")
		}
		c.Write([]byte{chainSocksVersion, chainSocksNoneOk})
		return
	}
	if _, err := c.Write([]byte{chainSocksVersion, want}); err != nil {
		return
	}
	if want == chainSocksUserPass && !p.socksLogin(c, reader) {
		return
	}

	// The request itself.
	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil {
		return
	}
	host, port, err := chainSocksAddress(reader, request[3])
	if err != nil {
		p.socksReply(c, chainSocksFailure, net.IPv4zero, 0)
		return
	}

	switch request[1] {
	case chainSocksConnect:
		p.socksConnect(c, host, port)
	case chainSocksUDP:
		p.socksUDP(c, reader)
	default:
		p.socksReply(c, chainSocksCmdUnsup, net.IPv4zero, 0)
	}
}

// socksLogin runs the user and password sub-negotiation of RFC 1929.
func (p *chainProxy) socksLogin(c net.Conn, reader *bufio.Reader) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(reader, head); err != nil {
		return false
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(reader, user); err != nil {
		return false
	}
	size := make([]byte, 1)
	if _, err := io.ReadFull(reader, size); err != nil {
		return false
	}
	password := make([]byte, int(size[0]))
	if _, err := io.ReadFull(reader, password); err != nil {
		return false
	}

	if !p.loginOk(string(user), string(password)) {
		c.Write([]byte{chainSocksAuthVer, 0x01})
		p.loginRefused(c, "wrong login or password (SOCKS5)")
		return false
	}
	_, err := c.Write([]byte{chainSocksAuthVer, 0x00})
	return err == nil
}

// chainSocksAddress reads one address out of a request or a datagram header.
func chainSocksAddress(reader io.Reader, kind byte) (string, uint16, error) {
	var host string
	switch kind {
	case chainSocksIPv4:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", 0, err
		}
		host = net.IP(raw).String()
	case chainSocksIPv6:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", 0, err
		}
		host = net.IP(raw).String()
	case chainSocksDomain:
		size := make([]byte, 1)
		if _, err := io.ReadFull(reader, size); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		return "", 0, errors.New("an address of a kind the proxy does not know")
	}
	raw := make([]byte, 2)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(raw), nil
}

// chainSocksCodeFor picks the answer the client deserves. Pack 84: a
// refusal that came from our own packet filter is "not allowed by the rule
// set", which is the truth and is what a curl or a browser prints as such.
// Everything else stays "host unreachable".
func chainSocksCodeFor(err error) byte {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == chainProxyErrAccess {
		return chainSocksNotAllowed
	}
	return chainSocksHostUnreach
}

// socksConnect is the ordinary "give me a TCP connection to this address".
func (p *chainProxy) socksConnect(c net.Conn, host string, port uint16) {
	index, dns, alive := p.current()
	if !alive {
		p.socksReply(c, chainSocksHostUnreach, net.IPv4zero, 0)
		chainLogChanged("proxy-down-"+p.leaf, "[WarpAm] The proxy of %s refuses connections: the tunnel is not there", p.leaf)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), chainProxyDialTimeout)
	address, err := chainProxyResolve(ctx, index, dns, host)
	if err != nil {
		cancel()
		// Pack 84: the client used to get nothing but code 0x04 here, and
		// the log said nothing at all, so a closed DNS door looked exactly
		// like a dead site. Now the name, the resolvers and the reason are
		// written down once per kind of failure.
		if chainSocksCodeFor(err) == chainSocksNotAllowed {
			p.setNote(chainProxyNoteDNSBlocked)
		}
		chainLogChanged("proxy-resolve-"+p.leaf, "[WarpAm] The proxy of %s could not resolve %q: %v", p.leaf, host, err)
		p.socksReply(c, chainSocksCodeFor(err), net.IPv4zero, 0)
		return
	}
	remote, err := chainProxyDialTCP(ctx, index, address.String(), port)
	cancel()
	if err != nil {
		// Pack 89: counted instead of repeated. A tunnel that stops
		// receiving produces one of these lines per address the browser
		// wanted, and thirty three of them in a row say no more than the
		// first one does.
		ChainProxyDialFailed(p.leaf, address.String(), port, chainProxyWhy(err))
		p.socksReply(c, chainSocksCodeFor(err), net.IPv4zero, 0)
		return
	}
	ChainProxyDialWorked(p.leaf)

	local := net.IPv4zero
	if bound, ok := remote.LocalAddr().(*net.TCPAddr); ok {
		local = bound.IP
	}
	if err := p.socksReply(c, chainSocksOK, local, port); err != nil {
		remote.Close()
		return
	}
	p.relay(c, remote)
}

// relay is the two way copy. Either side closing ends both.
func (p *chainProxy) relay(client, remote net.Conn) {
	p.track(remote)
	defer func() {
		p.forget(remote)
		remote.Close()
	}()

	// The handshake deadline has done its job; from here the connection
	// lives as long as the traffic does, and the cut of a dying tunnel is
	// what closes it.
	client.SetDeadline(time.Time{})
	remote.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, client)
		remote.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, remote)
		client.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// socksUDP is UDP ASSOCIATE. A socket is opened for the client to send its
// datagrams to, and a second one, nailed to the tunnel, carries them out.
// The TCP connection stays open for as long as the association lives, which
// is how the client says it is done.
func (p *chainProxy) socksUDP(c net.Conn, reader *bufio.Reader) {
	index, dns, alive := p.current()
	if !alive {
		p.socksReply(c, chainSocksHostUnreach, net.IPv4zero, 0)
		return
	}

	bind := "127.0.0.1:0"
	if strings.HasPrefix(p.address, "0.0.0.0:") {
		bind = "0.0.0.0:0"
	}
	clientSide, err := net.ListenPacket("udp4", bind)
	if err != nil {
		p.socksReply(c, chainSocksFailure, net.IPv4zero, 0)
		return
	}
	defer clientSide.Close()

	tunnelSide, err := chainProxyListenUDP(index)
	if err != nil {
		p.socksReply(c, chainSocksFailure, net.IPv4zero, 0)
		return
	}
	defer tunnelSide.Close()

	bound, _ := clientSide.LocalAddr().(*net.UDPAddr)
	if bound == nil {
		p.socksReply(c, chainSocksFailure, net.IPv4zero, 0)
		return
	}
	shown := bound.IP
	if shown == nil || shown.IsUnspecified() {
		shown = net.IPv4(127, 0, 0, 1)
	}
	if err := p.socksReply(c, chainSocksOK, shown, uint16(bound.Port)); err != nil {
		return
	}

	session := &chainProxyUDP{
		proxy:      p,
		clientSide: clientSide,
		tunnelSide: tunnelSide,
		index:      index,
		dns:        dns,
	}
	go session.fromClient()
	go session.fromTunnel()

	// The association ends when the control connection does, and it also
	// ends when the tunnel dies, because the cut closes this very socket.
	c.SetDeadline(time.Time{})
	io.Copy(io.Discard, reader)
}

// chainProxyUDP is one UDP association.
type chainProxyUDP struct {
	proxy      *chainProxy
	clientSide net.PacketConn
	tunnelSide *net.UDPConn
	index      uint32
	dns        []net.IP

	mu     sync.Mutex
	client net.Addr
}

// fromClient reads the datagrams of the program and sends them out through
// the tunnel.
func (s *chainProxyUDP) fromClient() {
	buffer := make([]byte, 65535)
	for {
		s.clientSide.SetReadDeadline(time.Now().Add(chainProxyIdleUDP))
		n, from, err := s.clientSide.ReadFrom(buffer)
		if err != nil {
			s.clientSide.Close()
			s.tunnelSide.Close()
			return
		}
		s.mu.Lock()
		s.client = from
		s.mu.Unlock()

		if n < 10 || buffer[2] != 0x00 {
			// A fragmented datagram. RFC 1928 allows it, no client of
			// this century sends one, and passing it on would be wrong.
			continue
		}
		reader := bufio.NewReader(strings.NewReader(string(buffer[4:n])))
		host, port, err := chainSocksAddress(reader, buffer[3])
		if err != nil {
			continue
		}
		payload, err := io.ReadAll(reader)
		if err != nil || len(payload) == 0 {
			continue
		}
		if _, _, alive := s.proxy.current(); !alive {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), chainProxyDNSTimeout)
		address, err := chainProxyResolve(ctx, s.index, s.dns, host)
		cancel()
		if err != nil {
			// Pack 84: a datagram that cannot be addressed is dropped as
			// before, but the reason is no longer a secret.
			if chainSocksCodeFor(err) == chainSocksNotAllowed {
				s.proxy.setNote(chainProxyNoteDNSBlocked)
			}
			chainLogChanged("proxy-resolve-udp-"+s.proxy.leaf, "[WarpAm] The proxy of %s could not resolve %q for a UDP datagram: %v", s.proxy.leaf, host, err)
			continue
		}
		s.tunnelSide.WriteToUDP(payload, &net.UDPAddr{IP: address, Port: int(port)})
	}
}

// fromTunnel wraps the answers back into SOCKS5 datagrams.
func (s *chainProxyUDP) fromTunnel() {
	buffer := make([]byte, 65535)
	for {
		s.tunnelSide.SetReadDeadline(time.Now().Add(chainProxyIdleUDP))
		n, from, err := s.tunnelSide.ReadFromUDP(buffer)
		if err != nil {
			s.clientSide.Close()
			s.tunnelSide.Close()
			return
		}
		s.mu.Lock()
		client := s.client
		s.mu.Unlock()
		if client == nil {
			continue
		}

		four := from.IP.To4()
		if four == nil {
			continue
		}
		answer := make([]byte, 0, n+10)
		answer = append(answer, 0x00, 0x00, 0x00, chainSocksIPv4)
		answer = append(answer, four...)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(from.Port))
		answer = append(answer, port...)
		answer = append(answer, buffer[:n]...)
		s.clientSide.WriteTo(answer, client)
	}
}
