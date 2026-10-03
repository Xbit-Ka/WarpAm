//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 74: the HTTP side of the local proxy.
 *
 * Some programs cannot speak SOCKS and only offer a box for an HTTP proxy.
 * Both live on the same port; the first byte of the connection decides which
 * one is used, so nothing has to be chosen twice.
 *
 * CONNECT gives a tunnel for anything, including TLS. A plain request with a
 * full address in the request line is passed on as well, because that is how
 * an ordinary http:// page is fetched through a proxy. UDP does not exist in
 * this protocol; whoever needs it uses SOCKS5.
 */

package manager

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// serveHTTP answers one connection that did not start with the SOCKS byte.
func (p *chainProxy) serveHTTP(c net.Conn, reader *bufio.Reader) {
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if ok, tried := p.httpLoginOk(request); !ok {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"WarpAm\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		// Pack 97: a browser asks first without a login and only then
		// with one, so a 407 without the header is not a failure.
		if tried {
			p.loginRefused(c, "wrong login or password (HTTP)")
		}
		return
	}

	index, dns, alive := p.current()
	if !alive {
		c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		chainLogChanged("proxy-down-"+p.leaf, "[WarpAm] The proxy of %s refuses connections: the tunnel is not there", p.leaf)
		return
	}

	host, port, err := chainHTTPTarget(request)
	if err != nil {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), chainProxyDialTimeout)
	address, err := chainProxyResolve(ctx, index, dns, host)
	if err != nil {
		cancel()
		// Pack 84: the same silence as in SOCKS lived here. A name that
		// cannot be resolved because our own filter shuts port 53 is not a
		// bad gateway, it is a refusal of the proxy itself, so it answers
		// 403 and says why in the log and in the window.
		if chainSocksCodeFor(err) == chainSocksNotAllowed {
			p.setNote(chainProxyNoteDNSBlocked)
			c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		} else {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		}
		chainLogChanged("proxy-resolve-"+p.leaf, "[WarpAm] The proxy of %s could not resolve %q: %v", p.leaf, host, err)
		return
	}
	remote, err := chainProxyDialTCP(ctx, index, address.String(), port)
	cancel()
	if err != nil {
		// Pack 89: the same counting as in the socks proxy. One line for
		// the first failure, then a count, then a line when the
		// connections go through again.
		ChainProxyDialFailed(p.leaf, address.String(), port, chainProxyWhy(err))
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	ChainProxyDialWorked(p.leaf)

	if strings.EqualFold(request.Method, "CONNECT") {
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			remote.Close()
			return
		}
		p.relay(c, remote)
		return
	}

	// An ordinary request. The proxy headers are dropped and the request
	// is written to the server the way the server expects it.
	request.RequestURI = ""
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	if err := request.Write(remote); err != nil {
		remote.Close()
		return
	}
	p.relay(c, remote)
}

// httpLoginOk checks Proxy-Authorization when a login is asked for. The
// second answer says whether a login was sent at all. Pack 97.
func (p *chainProxy) httpLoginOk(request *http.Request) (bool, bool) {
	if !p.needAuth() {
		return true, false
	}
	header := request.Header.Get("Proxy-Authorization")
	if len(strings.TrimSpace(header)) == 0 {
		return false, false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return false, true
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return false, true
	}
	user, password, found := strings.Cut(string(raw), ":")
	if !found {
		return false, true
	}
	return p.loginOk(user, password), true
}

// chainHTTPTarget works out where the request wants to go.
func chainHTTPTarget(request *http.Request) (string, uint16, error) {
	target := request.Host
	if strings.EqualFold(request.Method, "CONNECT") && len(request.URL.Host) > 0 {
		target = request.URL.Host
	} else if len(request.URL.Host) > 0 {
		target = request.URL.Host
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portText = "80"
		if strings.EqualFold(request.Method, "CONNECT") {
			portText = "443"
		}
		if strings.EqualFold(request.URL.Scheme, "https") {
			portText = "443"
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, io.ErrUnexpectedEOF
	}
	return strings.Trim(host, "[]"), uint16(port), nil
}
