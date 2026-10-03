//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 97: the local network side of the proxy.
 *
 * Everything here exists because the "local network" mode of pack 74 was
 * hard to use from another machine:
 *
 *   1. nobody told the user which address to type on the other machine;
 *   2. the password was hashed together with the login, so changing the
 *      login alone broke every password;
 *   3. Windows Firewall dropped the incoming connections and the user had
 *      to write a rule by hand;
 *   4. a program that asked in the wrong protocol, or offered no login, was
 *      turned away without a single line in the log;
 *   5. a program with a wrong password retrying in a loop wrote hundreds of
 *      identical lines a minute.
 */

package manager

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// ---------------------------------------------------------------------
// 1. The password.
// ---------------------------------------------------------------------

// chainProxyPassV2 marks a password hash of pack 97: a random salt and the
// SHA-256 of "salt:password". The login is not part of it any more, so the
// login can be changed without touching the password.
const chainProxyPassV2 = "v2:"

// ChainProxyPassHash is how the password of the local network mode is
// written down. The password itself is never stored. The user argument is
// kept so that the callers of pack 96 compile unchanged; it is not used.
func ChainProxyPassHash(user, password string) string {
	if len(password) == 0 {
		return ""
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return ""
	}
	text := hex.EncodeToString(salt)
	return chainProxyPassV2 + text + ":" + chainProxyHashV2(text, password)
}

func chainProxyHashV2(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

// chainProxyHashV1 is the hash of packs 74 to 96, kept so that a password
// saved by them still opens the door until it is typed again.
func chainProxyHashV1(user, password string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(user) + ":" + password))
	return hex.EncodeToString(sum[:])
}

// ChainProxyPassIsOld says that the saved hash still has the login inside,
// so a new login needs the password typed again.
func ChainProxyPassIsOld(stored string) bool {
	stored = strings.TrimSpace(stored)
	return len(stored) != 0 && !strings.HasPrefix(stored, chainProxyPassV2)
}

// ChainProxyPassMatches checks a password against the saved hash of either
// format. The comparison takes the same time whatever the answer.
func ChainProxyPassMatches(stored, user, password string) bool {
	stored = strings.TrimSpace(stored)
	if len(stored) == 0 || len(password) == 0 {
		return false
	}
	if strings.HasPrefix(stored, chainProxyPassV2) {
		salt, hash, found := strings.Cut(stored[len(chainProxyPassV2):], ":")
		if !found {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(chainProxyHashV2(salt, password)), []byte(hash)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(chainProxyHashV1(user, password)), []byte(stored)) == 1
}

// loginOk is the one check used by SOCKS5 and by HTTP.
func (p *chainProxy) loginOk(user, password string) bool {
	return strings.EqualFold(strings.TrimSpace(user), p.user) &&
		ChainProxyPassMatches(p.passHash, p.user, password)
}

// ---------------------------------------------------------------------
// 2. The address the other machines should type.
// ---------------------------------------------------------------------

// chainProxyNotLAN names the adapters that are never the local network,
// whatever type they report: our own tunnels, WARP, the internal switches
// of Hyper-V and the host-only network of VirtualBox.
var chainProxyNotLAN = []string{
	"warpam", "awgchain", "amnezia", "wireguard", "wintun", "cloudflare",
	"warp", "virtualbox", "vmware", "tap-windows", "default switch",
}

// ChainProxyLANAddresses lists the IPv4 addresses of the real Ethernet and
// Wi-Fi adapters that are up. An adapter has to have a default gateway:
// that is what tells the network of the house from the internal switches of
// Hyper-V and VirtualBox. The external switch of Hyper-V on the host does
// have one, and it is right to show it, because on such a host the address
// of the house really lives on that vEthernet adapter.
func ChainProxyLANAddresses() []string {
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_INET), winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return nil
	}
	out := make([]string, 0, 2)
	for _, adapter := range adapters {
		if adapter.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if adapter.IfType != winipcfg.IfTypeEthernetCSMACD && adapter.IfType != winipcfg.IfTypeIEEE80211 {
			continue
		}
		if adapter.FirstGatewayAddress == nil {
			continue
		}
		names := strings.ToLower(adapter.FriendlyName() + " " + adapter.Description())
		skip := false
		for _, word := range chainProxyNotLAN {
			if strings.Contains(names, word) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP().To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	sort.Strings(out)
	return out
}

// chainProxyLogLANAddress writes the line the user is going to look for
// when setting up the other machine.
func chainProxyLogLANAddress(leaf string, port int) {
	addresses := ChainProxyLANAddresses()
	if len(addresses) == 0 {
		log.Printf("[WarpAm] The proxy of %s listens on the local network, but no Ethernet or Wi-Fi adapter with a gateway was found to name an address", leaf)
		return
	}
	with := make([]string, len(addresses))
	for i := range addresses {
		with[i] = net.JoinHostPort(addresses[i], strconv.Itoa(port))
	}
	log.Printf("[WarpAm] The proxy of %s: the other machines of the local network use %s", leaf, strings.Join(with, ", "))
}

// ---------------------------------------------------------------------
// 3. The rule of Windows Firewall.
// ---------------------------------------------------------------------

// chainProxyRuleName is shared by every rule we make. netsh deletes rules
// by name, so one name lets the installer and the start of the manager take
// all of them away in one command; the port tells them apart otherwise.
const chainProxyRuleName = "WarpAm LAN proxy"

var (
	chainProxyRuleMu    sync.Mutex
	chainProxyRuleSwept bool
	chainProxyRulePorts = make(map[int]string)
)

func chainProxyNetsh(args ...string) (string, error) {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(filepath.Join(system32, "netsh.exe"), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// chainProxySweepRules takes away the rules a previous run left behind,
// once per start of the manager, before the first rule of this run.
func chainProxySweepRulesLocked() {
	if chainProxyRuleSwept {
		return
	}
	chainProxyRuleSwept = true
	if _, err := chainProxyNetsh("advfirewall", "firewall", "delete", "rule", "name="+chainProxyRuleName); err == nil {
		log.Printf("[WarpAm] Firewall rules %q left by an earlier run were removed", chainProxyRuleName)
	}
}

// chainProxyFirewallOpen lets the machines of the local network reach the
// port: inbound, every profile, remote addresses of the local subnets only.
// UDP is opened for the program, because SOCKS5 UDP ASSOCIATE answers on a
// port that is chosen at the moment.
func chainProxyFirewallOpen(leaf string, port int) {
	chainProxyRuleMu.Lock()
	defer chainProxyRuleMu.Unlock()
	chainProxySweepRulesLocked()

	chainProxyNetsh("advfirewall", "firewall", "delete", "rule", "name="+chainProxyRuleName, "protocol=tcp", "localport="+strconv.Itoa(port))
	description := "description=Proxy of the tunnel " + leaf + ", made by WarpAm"
	output, err := chainProxyNetsh("advfirewall", "firewall", "add", "rule", "name="+chainProxyRuleName,
		"dir=in", "action=allow", "protocol=tcp", "localport="+strconv.Itoa(port),
		"remoteip=localsubnet", "profile=any", description)
	if err != nil {
		log.Printf("[WarpAm] The firewall rule for the proxy of %s on TCP %d could not be made (%v: %s). The other machines will not get through until it exists", leaf, port, err, output)
		return
	}
	chainProxyRulePorts[port] = leaf
	log.Printf("[WarpAm] Firewall rule %q made for the proxy of %s: inbound TCP %d, every profile, local subnets only", chainProxyRuleName, leaf, port)

	if exe, err := os.Executable(); err == nil {
		chainProxyNetsh("advfirewall", "firewall", "delete", "rule", "name="+chainProxyRuleName, "protocol=udp")
		if output, err := chainProxyNetsh("advfirewall", "firewall", "add", "rule", "name="+chainProxyRuleName,
			"dir=in", "action=allow", "protocol=udp", "program="+exe,
			"remoteip=localsubnet", "profile=any", "description=SOCKS5 UDP of the proxies of WarpAm"); err != nil {
			log.Printf("[WarpAm] The firewall rule for SOCKS5 UDP could not be made (%v: %s)", err, output)
		}
	}
}

// chainProxyFirewallClose takes the rule of one port away, and the UDP rule
// with the last of them.
func chainProxyFirewallClose(port int) {
	chainProxyRuleMu.Lock()
	defer chainProxyRuleMu.Unlock()
	leaf, ours := chainProxyRulePorts[port]
	if !ours {
		return
	}
	delete(chainProxyRulePorts, port)
	chainProxyNetsh("advfirewall", "firewall", "delete", "rule", "name="+chainProxyRuleName, "protocol=tcp", "localport="+strconv.Itoa(port))
	log.Printf("[WarpAm] Firewall rule %q for TCP %d (proxy of %s) removed", chainProxyRuleName, port, leaf)
	if len(chainProxyRulePorts) == 0 {
		chainProxyNetsh("advfirewall", "firewall", "delete", "rule", "name="+chainProxyRuleName, "protocol=udp")
	}
}

// chainProxyPortOf reads the port back out of a listening address.
func chainProxyPortOf(address string) int {
	_, text, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(text)
	return port
}

// ---------------------------------------------------------------------
// 4 and 5. Refusals, written once, and the flood of wrong logins.
// ---------------------------------------------------------------------

const (
	chainProxyFailLimit  = 10
	chainProxyFailWindow = time.Minute
	chainProxyBlockTime  = 60 * time.Second
	chainProxyFailKeep   = 5 * time.Minute
)

// chainProxyFailCount is what is known about one address of one proxy.
type chainProxyFailCount struct {
	first   time.Time
	last    time.Time
	count   int
	quiet   int
	until   time.Time
	dropped int
}

// chainProxyRefusal is one kind of refusal of one address, for the lines
// that are written once a minute at most.
type chainProxyRefusal struct {
	first time.Time
	quiet int
}

var (
	chainProxyLoginMu    sync.Mutex
	chainProxyLoginFails     = make(map[string]*chainProxyFailCount)
	chainProxyRefusals  = make(map[string]*chainProxyRefusal)
)

func chainProxyHost(c net.Conn) string {
	text := c.RemoteAddr().String()
	host, _, err := net.SplitHostPort(text)
	if err != nil {
		return text
	}
	return host
}

// chainProxyTidyLocked forgets what is older than five minutes.
func chainProxyTidyLocked(now time.Time) {
	for key, f := range chainProxyLoginFails {
		if now.Sub(f.last) > chainProxyFailKeep && now.After(f.until) {
			delete(chainProxyLoginFails, key)
		}
	}
	for key, r := range chainProxyRefusals {
		if now.Sub(r.first) > chainProxyFailKeep {
			delete(chainProxyRefusals, key)
		}
	}
}

// loginBlocked says that this address has been refused for a while after
// too many wrong logins. The connection is closed without a word.
func (p *chainProxy) loginBlocked(c net.Conn) bool {
	host := chainProxyHost(c)
	key := p.leaf + "|" + host
	now := time.Now()
	chainProxyLoginMu.Lock()
	defer chainProxyLoginMu.Unlock()
	f := chainProxyLoginFails[key]
	if f == nil || f.until.IsZero() {
		return false
	}
	if now.Before(f.until) {
		f.dropped++
		return true
	}
	log.Printf("[WarpAm] The proxy of %s accepts %s again; %d connections were closed while it was refused", p.leaf, host, f.dropped)
	delete(chainProxyLoginFails, key)
	return false
}

// loginRefused counts one wrong login. The first one of a minute is written
// at once, the rest are counted, and the tenth one shuts the door on that
// address for sixty seconds. This machine itself is never shut out: a loop
// on 127.0.0.1 is a program of the user, not somebody guessing.
func (p *chainProxy) loginRefused(c net.Conn, why string) {
	host := chainProxyHost(c)
	key := p.leaf + "|" + host
	now := time.Now()
	chainProxyLoginMu.Lock()
	defer chainProxyLoginMu.Unlock()
	chainProxyTidyLocked(now)

	f := chainProxyLoginFails[key]
	if f == nil || (f.until.IsZero() && now.Sub(f.first) > chainProxyFailWindow) {
		if f != nil && f.quiet > 0 {
			log.Printf("[WarpAm] The proxy of %s refused %d more logins from %s in that minute", p.leaf, f.quiet, host)
		}
		f = &chainProxyFailCount{first: now}
		chainProxyLoginFails[key] = f
	}
	f.count++
	f.last = now

	ip := net.ParseIP(host)
	local := ip != nil && ip.IsLoopback()
	switch {
	case f.count == 1:
		log.Printf("[WarpAm] The proxy of %s refused a login from %s: %s", p.leaf, host, why)
	case f.count >= chainProxyFailLimit && f.until.IsZero() && !local:
		f.until = now.Add(chainProxyBlockTime)
		log.Printf("[WarpAm] The proxy of %s refuses %s for %d seconds: %d wrong logins within a minute. Check the login and password on that machine", p.leaf, host, int(chainProxyBlockTime/time.Second), f.count)
		f.quiet = 0
	default:
		f.quiet++
	}
}

// refused writes a refusal that is not about the password: the wrong
// protocol, or a program that did not offer a login. One line per tunnel,
// address and reason a minute.
func (p *chainProxy) refused(c net.Conn, why string) {
	host := chainProxyHost(c)
	key := p.leaf + "|" + host + "|" + why
	now := time.Now()
	chainProxyLoginMu.Lock()
	defer chainProxyLoginMu.Unlock()
	chainProxyTidyLocked(now)
	r := chainProxyRefusals[key]
	if r != nil && now.Sub(r.first) <= chainProxyFailWindow {
		r.quiet++
		return
	}
	more := ""
	if r != nil && r.quiet > 0 {
		more = fmt.Sprintf(" (%d more times in the minute before)", r.quiet)
	}
	chainProxyRefusals[key] = &chainProxyRefusal{first: now}
	log.Printf("[WarpAm] The proxy of %s turned away %s: %s%s", p.leaf, host, why, more)
}

// chainProxyLoginTrouble is what the window shows: the address that keeps
// failing the login in the last five minutes, and how many times.
func chainProxyLoginTrouble(leaf string) (string, int) {
	now := time.Now()
	chainProxyLoginMu.Lock()
	defer chainProxyLoginMu.Unlock()
	worst, count := "", 0
	for key, f := range chainProxyLoginFails {
		name, host, found := strings.Cut(key, "|")
		if !found || !strings.EqualFold(name, leaf) || now.Sub(f.last) > chainProxyFailKeep {
			continue
		}
		if f.count > count {
			worst, count = host, f.count
		}
	}
	return worst, count
}
