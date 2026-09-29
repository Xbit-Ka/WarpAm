//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 74: the local proxy.
 *
 * A tunnel can be asked to carry a local proxy. While the tunnel is up the
 * manager listens on 127.0.0.1 (or on the local network, if that is what the
 * settings say) and sends everything that arrives there into that tunnel and
 * into nothing else. One port, two protocols: the first byte of a connection
 * says whether it is SOCKS5 or HTTP.
 *
 * Two ways of working, chosen per tunnel:
 *
 *   together  the tunnel is raised as always and takes the default route;
 *             the proxy is just a local door into it.
 *   separate  the tunnel installs no routes and no system DNS, the address
 *             of the machine on the internet does not change, and only the
 *             programs that speak to the proxy go through the tunnel. This
 *             is the "ssh -D" way of working.
 *
 * In the separate mode there is no kill switch, and there must not be one:
 * the machine is meant to keep its ordinary connection. What protects the
 * proxied traffic instead:
 *
 *   1. every socket is nailed to the adapter of the tunnel, so it physically
 *      cannot go out through the provider (chainproxynet.go);
 *   2. a connection is only accepted while the tunnel is alive, otherwise
 *      the answer is an honest refusal;
 *   3. when the tunnel dies every open connection is cut;
 *   4. names are resolved only through the DNS of the tunnel;
 *   5. the port itself can be taken down with the tunnel, if that is what
 *      the settings ask for.
 */

package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// chainProxyPollInterval is how often the proxy asks whether its
	// tunnel is still there.
	chainProxyPollInterval = 2 * time.Second
	// chainProxyIdleUDP is how long a UDP session is kept without traffic.
	chainProxyIdleUDP = 60 * time.Second

	// Pack 84: a proxy started together with its tunnel used to sit blind
	// for a whole poll interval, refusing everything the program sent in
	// that time. While the tunnel is not up yet the watch looks again four
	// times a second, and only for the first half minute, after which the
	// ordinary interval is enough.
	chainProxyFastPoll   = 250 * time.Millisecond
	chainProxyFastRounds = 120
)

// Pack 84: what the proxy has to say about itself. The window turns these
// into a line of its own language, so the codes are kept short and never
// shown as they are.
const (
	chainProxyNoteTunnelDown = "tunnel-down"
	chainProxyNoteNoDNS      = "dns-none"
	chainProxyNoteDNSBlocked = "dns-blocked"
)

// ChainProxyInfo is what the window is told about one proxy.
type ChainProxyInfo struct {
	Leaf     string
	Address  string
	Protocol string
	Split    bool
	Alive    bool
	Conns    int
	Note     string
}

// chainProxy is one running proxy, belonging to one tunnel.
type chainProxy struct {
	leaf     string
	address  string
	protocol string
	split    bool
	onDown   string
	grace    time.Duration
	user     string
	passHash string

	mu        sync.Mutex
	listener  net.Listener
	conns     map[net.Conn]struct{}
	index     uint32
	dns       []net.IP
	alive     bool
	lostAt    time.Time
	cut       bool
	note      string
	stopped   bool
	stop      chan struct{}
	totalUsed int
}

var (
	chainProxyMu   sync.Mutex
	chainProxyLive = make(map[string]*chainProxy)
)

// ChainProxyPassHash is how the password of the local network mode is
// written down. The password itself is never stored: the settings file
// keeps this hash, and the proxy compares hashes.
func ChainProxyPassHash(user, password string) string {
	if len(strings.TrimSpace(user)) == 0 || len(password) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(user) + ":" + password))
	return hex.EncodeToString(sum[:])
}

// chainProxyWanted answers whether this tunnel asks for a proxy.
func chainProxyWanted(name string) bool {
	return ChainSettingsFor(name).Proxy
}

// chainProxyBindAddress is where the listener of this tunnel sits. Pack 79:
// the port is simply the number written for this tunnel, 1080 by default,
// and the two modes of pack 74 with their counting are gone. Two tunnels may
// carry the same number: the first one up takes it, the second says in the
// log that the port is busy.
func chainProxyBindAddress(settings ChainTunnelSettings) string {
	port := strconv.Itoa(settings.Port())
	if settings.Bind() == ChainProxyBindLAN {
		return net.JoinHostPort("0.0.0.0", port)
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// chainProxyAliveNow says whether the whole chain behind this tunnel has its
// adapters. It is the question the proxy asks before every connection.
func chainProxyAliveNow(leaf string) bool {
	hops := chainHopOrder(leaf)
	if len(hops) == 0 {
		return false
	}
	for _, hop := range hops {
		if _, ok := chainAdapterLUID(hop); !ok {
			return false
		}
	}
	return true
}

// chainProxyFollow is called when a tunnel comes up. A tunnel that does not
// ask for a proxy is left alone.
func chainProxyFollow(leaf string) {
	leaf = strings.TrimSpace(leaf)
	if len(leaf) == 0 || ChainIsHiddenHop(leaf) {
		return
	}
	if !chainProxyWanted(leaf) {
		chainProxyStop(leaf, "the tunnel does not ask for a proxy any more")
		return
	}

	chainProxyMu.Lock()
	if _, running := chainProxyLive[leaf]; running {
		chainProxyMu.Unlock()
		return
	}
	// Pack 79: everything the proxy needs is written for this tunnel, and
	// ChainSettingsFor gives it already normalised, so a combination that
	// the window cannot show cannot arrive here either.
	settings := ChainSettingsFor(leaf)
	p := &chainProxy{
		leaf:     leaf,
		address:  chainProxyBindAddress(settings),
		protocol: settings.Protocol(),
		split:    settings.ProxySplit,
		onDown:   settings.OnDown(),
		grace:    time.Duration(settings.ProxyGrace) * time.Second,
		user:     strings.TrimSpace(settings.ProxyUser),
		passHash: strings.TrimSpace(settings.ProxyPassHash),
		conns:    make(map[net.Conn]struct{}, 16),
		stop:     make(chan struct{}),
	}
	// Pack 86: the numbers that were really read are written down before
	// anything is opened. A report of "the proxy does not work" could not be
	// answered until now, because nothing in the log said which port the
	// manager had taken from the settings of this tunnel, which address it
	// was about to bind, or whether the split mode was on.
	log.Printf("[AwgChain] The proxy of %s is being started: port %d taken from %s, address %s, protocol %s, split %v, grace %d seconds, login %v",
		leaf, settings.Port(), chainProxyPortSource(), p.address, p.protocol, p.split, settings.ProxyGrace, len(p.user) != 0)
	if settings.Bind() == ChainProxyBindLAN && (len(p.user) == 0 || len(p.passHash) == 0) {
		chainProxyMu.Unlock()
		log.Printf("[AwgChain] The proxy of %s is NOT started: it is set to listen on the local network but no login and password are set", leaf)
		return
	}
	chainProxyLive[leaf] = p
	chainProxyMu.Unlock()

	if err := p.open(); err != nil {
		chainProxyMu.Lock()
		delete(chainProxyLive, leaf)
		chainProxyMu.Unlock()
		// Pack 86: who holds the address is said here as well, because this
		// is the line that is read when the port is busy. WARPv2_84 sat with
		// no listener on 1081 for a whole evening and the log never named
		// the other holder.
		if holder := chainProxyHolderOf(p.address, leaf); len(holder) != 0 {
			log.Printf("[AwgChain] The proxy of %s could not take %s (%v). That address is already held by the proxy of %s", leaf, p.address, err, holder)
		} else {
			log.Printf("[AwgChain] The proxy of %s could not take %s (%v). No proxy of ours holds that address, so it belongs to another program", leaf, p.address, err)
		}
		return
	}

	kind := "together with the tunnel"
	if p.split {
		kind = "separately: the address of the machine does not change, only the proxy goes through the tunnel"
	}
	log.Printf("[AwgChain] The proxy of %s is listening on %s (%s), %s", leaf, p.address, p.protocol, kind)
	go p.watch()
}

// chainProxyPortSource says which saving of the settings the port was read
// from. Pack 86.
//
// On 27 September at 19:37 the settings of a tunnel were saved twice, the
// window showed port 1081, and the refusal spoke of port 1080. The log could
// not settle the question, because nothing in it said when the settings the
// manager had used were written. Now it does, and a port on screen that
// differs from the port in this line means the saving came later than the
// reading.
func chainProxyPortSource() string {
	path := chainSettingsPath()
	if len(path) == 0 {
		return "the settings of this tunnel"
	}
	info, err := os.Stat(path)
	if err != nil {
		return "the settings of this tunnel"
	}
	return fmt.Sprintf("the settings saved at %s", info.ModTime().Format("15:04:05"))
}

// chainProxyHolderOf names the tunnel whose proxy holds this address, if it
// is one of ours. Pack 86.
func chainProxyHolderOf(address, except string) string {
	for _, proxy := range ChainProxyState() {
		if strings.EqualFold(proxy.Leaf, except) {
			continue
		}
		if strings.EqualFold(proxy.Address, address) {
			return proxy.Leaf
		}
	}
	return ""
}

// chainProxyStop takes one proxy down.
func chainProxyStop(leaf string, why string) {
	chainProxyMu.Lock()
	p := chainProxyLive[strings.TrimSpace(leaf)]
	delete(chainProxyLive, strings.TrimSpace(leaf))
	chainProxyMu.Unlock()
	if p == nil {
		return
	}
	p.shutdown()
	log.Printf("[AwgChain] The proxy of %s is stopped: %s", leaf, why)
}

// ChainProxyTunnelGone is called when the service of a tunnel has ended
// without anybody asking it to. Until pack 92 the proxy was taken down in
// one place only, chainBeforeStop, which runs when a tunnel is switched off
// by hand. A service that died by itself therefore left its proxy sitting
// on the port, refusing every connection for as long as the program ran,
// and the log said nothing about it.
//
// The log of 28 September shows the whole thing in five milliseconds: the
// proxy of Elena took 127.0.0.1:1080, the service of Elena shut down on its
// first line because its configuration file was not there, and 1080 stayed
// taken until the program was closed.
func ChainProxyTunnelGone(tunnelName string) {
	tunnelName = strings.TrimSpace(tunnelName)
	if len(tunnelName) == 0 {
		return
	}
	for _, info := range ChainProxyState() {
		for _, hop := range chainHopOrder(info.Leaf) {
			if !strings.EqualFold(hop, tunnelName) {
				continue
			}
			log.Printf("[AwgChain] The service of %s ended on its own, so the proxy on %s has no tunnel behind it any more", tunnelName, info.Address)
			chainProxyStop(info.Leaf, "the service of "+tunnelName+" ended on its own")
			break
		}
	}
}

// chainProxyStopAll is used when the manager itself is going away.
func chainProxyStopAll(why string) {
	chainProxyMu.Lock()
	names := make([]string, 0, len(chainProxyLive))
	for name := range chainProxyLive {
		names = append(names, name)
	}
	chainProxyMu.Unlock()
	for _, name := range names {
		chainProxyStop(name, why)
	}
}

// ChainProxyState is what the window asks for.
func ChainProxyState() []ChainProxyInfo {
	chainProxyMu.Lock()
	running := make([]*chainProxy, 0, len(chainProxyLive))
	for _, p := range chainProxyLive {
		running = append(running, p)
	}
	chainProxyMu.Unlock()

	out := make([]ChainProxyInfo, 0, len(running))
	for _, p := range running {
		p.mu.Lock()
		out = append(out, ChainProxyInfo{
			Leaf:     p.leaf,
			Address:  p.address,
			Protocol: p.protocol,
			Split:    p.split,
			Alive:    p.alive && p.listener != nil,
			Conns:    len(p.conns),
			Note:     p.note,
		})
		p.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Leaf) < strings.ToLower(out[j].Leaf)
	})
	return out
}

// open puts the listener up and starts accepting.
func (p *chainProxy) open() error {
	listener, err := net.Listen("tcp", p.address)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.listener = listener
	p.cut = false
	p.mu.Unlock()
	go p.accept(listener)
	return nil
}

// closeListener takes the port down without touching the open connections.
func (p *chainProxy) closeListener() {
	p.mu.Lock()
	listener := p.listener
	p.listener = nil
	p.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
}

// shutdown ends everything: the port, the watch and every connection.
func (p *chainProxy) shutdown() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.stop)
	p.mu.Unlock()
	p.closeListener()
	p.cutConnections("the proxy is stopping")
}

// track remembers a connection so that it can be cut when the tunnel dies.
func (p *chainProxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.totalUsed++
	p.mu.Unlock()
}

func (p *chainProxy) forget(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// cutConnections closes everything that is open right now.
func (p *chainProxy) cutConnections(why string) {
	p.mu.Lock()
	open := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		open = append(open, c)
	}
	p.conns = make(map[net.Conn]struct{}, 16)
	p.mu.Unlock()
	if len(open) == 0 {
		return
	}
	for _, c := range open {
		c.Close()
	}
	log.Printf("[AwgChain] The proxy of %s cut %d connections: %s", p.leaf, len(open), why)
}

// alive answers whether traffic may be sent right now, and with which
// interface index.
func (p *chainProxy) current() (uint32, []net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.index, p.dns, p.alive
}

func (p *chainProxy) accept(listener net.Listener) {
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		go p.serve(c)
	}
}

// setNote writes the short word the window shows under this proxy.
func (p *chainProxy) setNote(text string) {
	p.mu.Lock()
	if p.note != text {
		p.note = text
	}
	p.mu.Unlock()
}

// checkDNSDoor knocks on the resolvers of the tunnel through the adapter of
// the tunnel, the same way a name lookup would. Nothing is asked and no
// name is sent: the answer we are after is whether the packet filter lets
// port 53 out at all. A refusal with WSAEACCES is our own kill switch
// missing a door, which is exactly the fault pack 84 repairs, and it is
// worth saying out loud instead of letting every later lookup fail.
func (p *chainProxy) checkDNSDoor(index uint32, servers []net.IP) {
	if index == 0 {
		return
	}
	if len(servers) == 0 {
		p.setNote(chainProxyNoteNoDNS)
		chainLogChanged("proxy-dns-"+p.leaf, "[AwgChain] The tunnel %s has no IPv4 DNS server of its own, so its proxy can open addresses but not names", p.leaf)
		return
	}
	dialer := chainProxyDialer(index)
	blocked := false
	for _, server := range servers {
		if server == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), chainProxyDNSTimeout)
		conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(server.String(), "53"))
		cancel()
		if err == nil {
			conn.Close()
			p.setNote("")
			return
		}
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == chainProxyErrAccess {
			blocked = true
		}
	}
	if !blocked {
		// The resolvers did not answer on TCP, which many of them never
		// do. That is not a closed door, so nothing is claimed.
		return
	}
	p.setNote(chainProxyNoteDNSBlocked)
	chainLogChanged("proxy-dns-"+p.leaf, "[AwgChain] The packet filter refuses port 53 on the adapter of %s (%s), so the proxy of that tunnel can open addresses but not names. Restart the tunnel that holds the kill switch to have the door cut again", p.leaf, chainProxyDNSLine(servers))
}

// watch keeps the picture of the tunnel fresh and applies the rules of the
// lock: cut the connections when the tunnel is gone, and, if the settings
// ask for it, take the port down as well.
func (p *chainProxy) watch() {
	rounds := 0
	for {
		alive := chainProxyAliveNow(p.leaf)
		var index uint32
		var dns []net.IP
		if alive {
			if i, err := chainProxyIfaceIndex(p.leaf); err == nil {
				index = i
				dns = chainProxyDNSServers(p.leaf)
			} else {
				alive = false
			}
		}

		p.mu.Lock()
		was := p.alive
		p.alive = alive
		if alive {
			p.index = index
			p.dns = dns
			p.lostAt = time.Time{}
			p.note = ""
		} else if was {
			p.lostAt = time.Now()
			p.note = chainProxyNoteTunnelDown
		}
		lostAt := p.lostAt
		cut := p.cut
		rose := alive && !was
		p.mu.Unlock()

		// Pack 84: the tunnel has just come up, so the proxy knocks on its
		// own DNS door before a program does. A door that is not there is
		// written down once, in the log and in the window, instead of
		// turning into a nameless refusal later on.
		if rose {
			go p.checkDNSDoor(index, dns)
		}

		if !alive && !cut && !lostAt.IsZero() && time.Since(lostAt) >= p.grace {
			p.mu.Lock()
			p.cut = true
			p.mu.Unlock()
			p.cutConnections(fmt.Sprintf("the tunnel %s is gone", p.leaf))
			if p.onDown == ChainProxyDownClose {
				p.closeListener()
				log.Printf("[AwgChain] The proxy port of %s is closed while the tunnel is down", p.leaf)
			}
		}

		if alive {
			p.mu.Lock()
			listening := p.listener != nil
			stopped := p.stopped
			p.mu.Unlock()
			if !listening && !stopped {
				if err := p.open(); err != nil {
					log.Printf("[AwgChain] The proxy of %s could not take %s again (%v)", p.leaf, p.address, err)
				} else {
					log.Printf("[AwgChain] The proxy of %s is listening again on %s", p.leaf, p.address)
				}
			}
		}

		// Pack 84: quick rounds until the tunnel is up for the first time.
		wait := chainProxyPollInterval
		if !alive && rounds < chainProxyFastRounds {
			wait = chainProxyFastPoll
			rounds++
		}
		select {
		case <-p.stop:
			return
		case <-time.After(wait):
		}
	}
}
