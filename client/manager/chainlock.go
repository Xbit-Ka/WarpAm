/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 51: the chain kill switch lives inside the manager service.
 *
 * Until now the WFP filters were installed by a separate process,
 * awgchain-guard.exe. That worked, but it cost us three problems:
 *
 *   1. The lock appears only after the guard process has started, so there
 *      is a window at raise time with no protection at all.
 *   2. When the manager goes away the guard has to guess whether this was a
 *      deliberate shutdown, so it waits out -orphangrace (120 seconds).
 *      That is the "the internet comes back after two minutes" complaint.
 *   3. It dragged a stop event, a death counter and -mgrpid behind it.
 *
 * The filters belong to a dynamic WFP session, so they live exactly as long
 * as the process that installed them. Installing them from the manager
 * service is therefore both simpler and safer: a manager that crashes frees
 * the machine immediately, and a manager that is alive can lift the lock the
 * moment the tunnel is stopped on purpose.
 *
 * Pack 68: there is no fallback any more. The guard process is gone and
 * the no-inproc-lock file is not read; the choice is Global.LockEngine in
 * settings.json, either "service" (this code) or "off" (nothing). An
 * existing no-inproc-lock file is carried over once and then deleted, and
 * because it asked for a kill switch it lands on "service".
 */

package manager

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
)

var (
	chainLockMu    sync.Mutex
	chainLockOn    bool
	chainLockLeaf  string
	chainLockStop  chan struct{}
	// Pack 81: the holes the armed lock was built with, written as one
	// line. The filters cannot be edited once the session is up, so the
	// only way to follow a proxy tunnel that comes or goes is to notice
	// that this line has moved and build the lock again.
	chainLockHolesSig string
)

func chainLockIsOn() bool {
	chainLockMu.Lock()
	defer chainLockMu.Unlock()
	return chainLockOn
}

func chainParseEndpoint(value string) (net.IP, uint16, bool) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, 0, false
	}
	return ip, uint16(port), true
}

func chainLockApps() []string {
	apps := make([]string, 0, 2)
	self, err := os.Executable()
	if err != nil {
		return apps
	}
	// WarpAm pack 94: only the program itself. The neighbour awgchain.exe
	// this used to allow as well has not existed since the early packs.
	apps = append(apps, self)
	return apps
}

func chainLockDNS(top string) []net.IP {
	servers := make([]net.IP, 0, 4)
	for _, text := range strings.Split(chainDNSOf(top), ",") {
		ip := net.ParseIP(strings.TrimSpace(text))
		if ip != nil {
			servers = append(servers, ip)
		}
	}
	return servers
}

func chainLockLANs(root string) []net.IPNet {
	via := ""
	if c, err := conf.LoadFromName(root); err == nil {
		via = strings.TrimSpace(c.Interface.PinEndpointVia)
	}
	networks := make([]net.IPNet, 0, 4)
	for _, text := range chainLocalNetworks(via) {
		_, network, err := net.ParseCIDR(text)
		if err == nil && network != nil {
			networks = append(networks, *network)
		}
	}
	return networks
}

// chainArmLockInProc installs the kill switch in this very process. It
// answers true when the machine is taken care of, either because the
// filters are up or because the settings say no kill switch is wanted,
// and false when the chain is not ready to be locked yet.
func chainArmLockInProc(leaf string) bool {
	return chainArmLock(leaf, false)
}

// chainRearmLockInProc builds the rule set of leaf again even when nothing in
// the holes has changed, as the repair after new adapters needs. WarpAm pack
// 94: the old rules stand until the new ones are up.
func chainRearmLockInProc(leaf string) bool {
	return chainArmLock(leaf, true)
}

// chainArmLock is the one place where the lock is put up or rebuilt.
//
// WarpAm pack 94: a rebuild no longer lifts the lock first. The old way,
// disarm and arm again, left the machine without rules for about eight
// milliseconds every time a proxy tunnel was raised or stopped beside the
// chain. Now the new rule set is installed while the old one still stands
// (firewall.ReplaceChainFirewall), and a rebuild that cannot finish keeps the
// old rules instead of leaving the machine open.
func chainArmLock(leaf string, force bool) bool {
	if !ChainSettingsFor(leaf).KillSwitch {
		chainLogChanged("killswitch-off", "[WarpAm] The kill switch is switched off in the settings of %s", leaf)
		chainApplyIPv6For(leaf)
		return true
	}

	// Pack 68 (I3): the engine is read from the settings instead of from
	// a file in ProgramData nobody could see.
	if chainLockEngineOff() {
		return false
	}
	// Pack 81, variant A: the proxy only tunnels standing beside this chain
	// keep their way out. Everything else the lock blocks, it goes on
	// blocking.
	holes := chainLockProxyTunnels(leaf)
	holesSig := chainLockHolesSignature(holes)

	replacing := false
	if chainLockIsOn() {
		chainLockMu.Lock()
		sameChain := strings.EqualFold(chainLockLeaf, leaf)
		sameHoles := chainLockHolesSig == holesSig
		chainLockMu.Unlock()
		if !sameChain || (sameHoles && !force) {
			return true
		}
		// A proxy tunnel was raised or stopped while the chain was up. The
		// watch comes here every five seconds, so this is where it is
		// noticed, and rebuilding the filters takes a fraction of a second.
		if !sameHoles {
			log.Printf("[WarpAm] The proxy tunnels beside the chain have changed (%s), so the kill switch is built again with the new holes while the old rules still stand", chainLockHolesLine(holes))
		}
		replacing = true
	}
	// notReady is the answer when the rule set cannot be built right now.
	// During a rebuild the old rules are still up, so the machine is taken
	// care of for the watch; the repair, which asked for the rebuild, is
	// told the truth and tries again.
	notReady := func() bool {
		if replacing {
			chainLogChanged("lock-rebuild-wait-"+leaf, "[WarpAm] The kill switch of %s cannot be rebuilt yet, so the old rules stay in place", leaf)
			return !force
		}
		return false
	}

	hops := chainHopOrder(leaf)
	if len(hops) < 2 {
		return notReady()
	}
	root := hops[0]
	top := hops[len(hops)-1]

	rootEndpointText, err := chainEndpointOf(root)
	if err != nil {
		log.Printf("[WarpAm] The kill switch cannot read the endpoint of %s: %v", root, err)
		return notReady()
	}
	topEndpointText, err := chainEndpointOf(top)
	if err != nil {
		log.Printf("[WarpAm] The kill switch cannot read the endpoint of %s: %v", top, err)
		return notReady()
	}
	rootIP, rootPort, ok := chainParseEndpoint(rootEndpointText)
	if !ok {
		log.Printf("[WarpAm] The kill switch does not understand the endpoint %q", rootEndpointText)
		return notReady()
	}
	topIP, topPort, ok := chainParseEndpoint(topEndpointText)
	if !ok {
		log.Printf("[WarpAm] The kill switch does not understand the endpoint %q", topEndpointText)
		return notReady()
	}

	rootLUID, ok := chainAdapterLUID(root)
	if !ok {
		log.Printf("[WarpAm] The kill switch waits: the %s adapter is not here yet", root)
		return notReady()
	}
	topLUID, ok := chainAdapterLUID(top)
	if !ok {
		log.Printf("[WarpAm] The kill switch waits: the %s adapter is not here yet", top)
		return notReady()
	}

	apps := chainLockApps()
	if len(apps) == 0 {
		log.Printf("[WarpAm] The kill switch cannot tell which executable to allow")
		return notReady()
	}

	cfg := &firewall.ChainFirewallConfig{
		Hop1LUID:     uint64(rootLUID),
		Hop2LUID:     uint64(topLUID),
		Hop1Endpoint: rootIP,
		Hop1Port:     rootPort,
		Hop2Endpoint: topIP,
		Hop2Port:     topPort,
		DNSServers:   chainLockDNS(top),
		AllowedApps:  apps,
		AllowedLANs:  chainSettingsLANs(root, leaf),
		ProxyTunnels: holes,
	}

	if replacing {
		err = firewall.ReplaceChainFirewall(cfg)
		if err != nil {
			chainLogChanged("lock-rebuild-fail-"+leaf, "[WarpAm] The new kill switch rules for %s could not be installed (%v), so the old ones stay in place. The watch tries again.", leaf, err)
			return !force
		}
		chainLockMu.Lock()
		chainLockHolesSig = holesSig
		chainLockMu.Unlock()
		log.Printf("[WarpAm] Kill switch rebuilt for %s -> %s without a gap: the new rules stood before the old ones were removed", root, top)
		if len(holes) != 0 {
			log.Printf("[WarpAm] The proxy tunnels %s keep their way out: their own packets to their own servers, and nothing else", chainLockHolesLine(holes))
		}
		return true
	}

	err = firewall.EnableChainFirewall(cfg)
	if err != nil {
		// A leftover session from an earlier raise is not a reason to start a
		// second guard: close it and try once more.
		// Pack 70: the first failure is written down. Two failures in a row
		// used to leave one line in the log, so a permanent problem read
		// exactly like a leftover session being cleared.
		log.Printf("[WarpAm] The kill switch could not be installed at the first attempt (%v), the leftover filters are cleared and it is tried once more", err)
		firewall.DisableChainFirewall()
		err = firewall.EnableChainFirewall(cfg)
	}
	if err != nil {
		log.Printf("[WarpAm] The kill switch could not be installed (%v), so the chain runs without one. The watch tries again.", err)
		return false
	}

	stop := make(chan struct{})
	chainLockMu.Lock()
	chainLockOn = true
	chainLockLeaf = leaf
	chainLockStop = stop
	chainLockHolesSig = holesSig
	chainLockMu.Unlock()

	log.Printf("[WarpAm] Kill switch armed inside the manager for %s -> %s, no separate guard process", root, top)
	if len(holes) != 0 {
		log.Printf("[WarpAm] The proxy tunnels %s keep their way out: their own packets to their own servers, and nothing else", chainLockHolesLine(holes))
	}
	// Pack 71: the real kill switch stands now, so the coarse lock of the
	// paranoid start is taken down - in this order, so the machine is
	// never open for even a moment in between.
	chainDropBootLock("the kill switch of the chain has taken over")
	chainApplyIPv6For(leaf)
	// Pack 86: the lock is really closed now, and only now is a routable
	// IPv6 address of the machine provably useless. It is taken off the
	// adapter and put back when the lock is lifted, which is what turns the
	// warning of pack 84 into something the user does not have to act on.
	if ChainSettingsFor(leaf).BlockIPv6 {
		ChainDropRoutableIPv6()
	}
	go chainLockWatchStopEvent(stop)
	return true
}

// chainDisarmLockInProc lifts the lock. It answers true when there was one.
func chainDisarmLockInProc() bool {
	// Pack 71 took the lock of the paranoid start down here without asking
	// anything, and every disarm went through this place: leaving the
	// program, rebuilding the filters after a settings change, the repair
	// that swaps rule sets. A paranoid machine was opened by simply
	// closing the window.
	//
	// Pack 72: it is dropped only when the machine was asked to be open by
	// hand. That wish is written down by chainLockSuppress just before
	// ChainLiftLockNow and the stop event get here.
	if chainLockSuppressedNow() {
		chainDropBootLock("the machine was asked to be open")
	}
	chainLockMu.Lock()
	on := chainLockOn
	stop := chainLockStop
	chainLockOn = false
	chainLockLeaf = ""
	chainLockStop = nil
	chainLockHolesSig = ""
	chainLockMu.Unlock()
	if !on {
		return false
	}
	if stop != nil {
		close(stop)
	}
	firewall.DisableChainFirewall()
	log.Printf("[WarpAm] Kill switch lifted, the machine is open again")
	chainDropIPv6Block()
	// Pack 86: the machine is left exactly as it was found.
	ChainRestoreRoutableIPv6()
	return true
}

// chainLockWatchStopEvent keeps "awgchain.bat ks off" working: the console
// signals the same event the guard used to listen to.
func chainLockWatchStopEvent(stop chan struct{}) {
	name, err := windows.UTF16PtrFromString(chainGuardStopEventName)
	if err != nil {
		return
	}
	handle, err := windows.CreateEvent(chainStopEventSecurity(), 1, 0, name)
	if handle == 0 {
		if err != nil {
			log.Printf("[WarpAm] The kill switch cannot listen for the stop signal: %v", err)
		}
		return
	}
	defer windows.CloseHandle(handle)
	// A previous run may have left the manual reset event signalled.
	windows.ResetEvent(handle)

	for {
		select {
		case <-stop:
			return
		default:
		}
		state, err := windows.WaitForSingleObject(handle, 1000)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if state == windows.WAIT_OBJECT_0 {
			windows.ResetEvent(handle)
			log.Printf("[WarpAm] The kill switch was asked to stand down")
			// Pack 70: the same "stay down" the button in the window sets.
			// Without it the watch armed the lock again a few seconds
			// later and "awgchain.bat ks off" looked like it did nothing.
			chainLockSuppress(true)
			chainDisarmLockInProc()
			return
		}
	}
}
