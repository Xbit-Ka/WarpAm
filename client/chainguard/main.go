/* SPDX-License-Identifier: MIT
 *
 * awgchain-guard installs the AwgChain kill switch and stays alive for as long
 * as the kill switch must hold. The WFP filters belong to a dynamic session,
 * so they vanish automatically when this process exits for any reason.
 *
 * Pack 42: the guard no longer outlives the thing it was protecting.
 *
 * Until now the guard held the kill switch forever. That is right while the
 * manager is alive, because then somebody is still repairing the chain. But
 * when the manager is gone - the user closed the program, the service was
 * stopped, the manager crashed - nobody will ever rebuild the chain, and the
 * machine was left with no way out except killing awgchain-guard.exe by hand.
 *
 * So the manager now tells the guard its own process id with -mgrpid. When
 * that process disappears the guard starts a grace timer:
 *
 *   - the chain is still intact  -> keep holding, traffic still goes through
 *     the tunnel, so there is nothing to protect against; say so in the log
 *     once every heartbeat
 *   - a hop is missing           -> after -orphangrace seconds remove the kill
 *     switch and exit, because there is no chain left to protect and holding
 *     on only bricks the machine
 *
 * Without -mgrpid the old behaviour is kept exactly: hold until stopped.
 *
 * Usage:
 *   awgchain-guard.exe -hop1ep 162.159.192.6:880 -hop2ep 95.182.86.131:44458 \
 *       -hop1if hop1-warp -hop2if hop2-amnezia -dns 1.1.1.1,1.0.0.1 \
 *       -lan 192.168.0.0/24 -allowapp "C:\Program Files\AwgChain\bin\awgchain.exe" \
 *       -mgrpid 1234 -orphangrace 120 -logfile C:\...\guard-log.txt
 *   awgchain-guard.exe -dryrun ...   resolve and print everything, install nothing
 *   awgchain-guard.exe -stop
 */

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const stopEventName = `Global\AwgChainGuardStop`

// WAIT_TIMEOUT from winbase.h.
const waitTimeout = uint32(0x00000102)

var (
	out     io.Writer = os.Stdout
	logFile *os.File
)

func say(format string, args ...interface{}) {
	fmt.Fprintf(out, format+"\n", args...)
	if logFile != nil {
		logFile.Sync()
	}
}

func main() {
	stop := flag.Bool("stop", false, "tell a running guard to remove the kill switch and exit")
	dryRun := flag.Bool("dryrun", false, "resolve everything and print it, but install no filters")
	hop1If := flag.String("hop1if", "hop1-warp", "friendly name of the hop 1 interface")
	hop2If := flag.String("hop2if", "hop2-amnezia", "friendly name of the hop 2 interface")
	hop1Ep := flag.String("hop1ep", "", "hop 1 endpoint as ip:port")
	hop2Ep := flag.String("hop2ep", "", "hop 2 endpoint as ip:port")
	dnsList := flag.String("dns", "1.1.1.1,1.0.0.1", "comma separated DNS servers reachable through hop 2")
	lanList := flag.String("lan", "", "comma separated local networks to keep reachable, e.g. 192.168.0.0/24")
	appList := flag.String("allowapp", "", "semicolon separated executables allowed to reach the endpoints")
	timeout := flag.Int("timeout", 0, "seconds to hold the kill switch, 0 means until stopped")
	mgrPid := flag.Int("mgrpid", 0, "process id of the manager that armed the kill switch, 0 means nobody is watched")
	orphanGrace := flag.Int("orphangrace", 120, "seconds to keep a broken chain shut in after the manager is gone")
	logPath := flag.String("logfile", "", "write everything to this file as well as to stdout")
	flag.Parse()

	if *logPath != "" {
		file, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			logFile = file
			out = io.MultiWriter(os.Stdout, file)
			defer file.Close()
		} else {
			fmt.Printf("warning: cannot open %s: %v\n", *logPath, err)
		}
	}

	say("guard start %s", time.Now().Format("2006-01-02 15:04:05"))

	if *stop {
		err := signalStop()
		if err != nil {
			say("GUARD=STOPFAILED")
			say("error: %v", err)
			os.Exit(1)
		}
		say("GUARD=STOPSIGNALED")
		return
	}

	if *hop1Ep == "" || *hop2Ep == "" {
		fail("both -hop1ep and -hop2ep are required")
	}

	hop1IP, hop1Port, err := parseEndpoint(*hop1Ep)
	if err != nil {
		fail("bad -hop1ep: %v", err)
	}
	hop2IP, hop2Port, err := parseEndpoint(*hop2Ep)
	if err != nil {
		fail("bad -hop2ep: %v", err)
	}

	hop1LUID, err := luidForAlias(*hop1If)
	if err != nil {
		fail("%v", err)
	}
	hop2LUID, err := luidForAlias(*hop2If)
	if err != nil {
		fail("%v", err)
	}

	apps := splitList(*appList, ";")
	if len(apps) == 0 {
		self, err := os.Executable()
		if err != nil {
			fail("cannot determine my own path: %v", err)
		}
		apps = []string{filepath.Join(filepath.Dir(self), "awgchain.exe")}
	}
	for _, app := range apps {
		_, statErr := os.Stat(app)
		if statErr != nil {
			fail("allowed app %q is not reachable: %v", app, statErr)
		}
	}

	dnsServers := parseIPs(splitList(*dnsList, ","))
	lans := parseCIDRs(splitList(*lanList, ","))

	say("hop1  : %s (luid %d) endpoint %s:%d", *hop1If, hop1LUID, hop1IP, hop1Port)
	say("hop2  : %s (luid %d) endpoint %s:%d, only through hop 1", *hop2If, hop2LUID, hop2IP, hop2Port)
	say("dns   : %s (only through hop 2, 53 and 853 blocked elsewhere)", joinIPs(dnsServers))
	say("lan   : %s", joinNets(lans))
	say("apps  : %s", strings.Join(apps, "; "))
	if *mgrPid > 0 {
		say("mgr   : pid %s is watched, a broken chain is released %d seconds after it goes away", strconv.Itoa(*mgrPid), *orphanGrace)
	} else {
		say("mgr   : nobody is watched, the kill switch holds until it is stopped")
	}

	cfg := &firewall.ChainFirewallConfig{
		Hop1LUID:     hop1LUID,
		Hop2LUID:     hop2LUID,
		Hop1Endpoint: hop1IP,
		Hop1Port:     hop1Port,
		Hop2Endpoint: hop2IP,
		Hop2Port:     hop2Port,
		DNSServers:   dnsServers,
		AllowedApps:  apps,
		AllowedLANs:  lans,
	}

	if *dryRun {
		say("KILLSWITCH=DRYRUN nothing was installed")
		return
	}

	stopEvent, err := createStopEvent()
	if err != nil {
		fail("cannot create the stop event: %v", err)
	}
	// A previous guard may have left the manual-reset event signalled, which
	// would make this one exit immediately.
	err = windows.ResetEvent(stopEvent)
	if err != nil {
		say("warning: cannot reset the stop event: %v", err)
	}

	err = firewall.EnableChainFirewall(cfg)
	if err != nil {
		fail("cannot install the kill switch: %v", err)
	}

	say("KILLSWITCH=OK")
	holdKillSwitch(stopEvent, cfg, *hop1If, *hop2If, *timeout, *mgrPid, *orphanGrace)
}

func fail(format string, args ...interface{}) {
	say("KILLSWITCH=FAIL")
	say("error: "+format, args...)
	if logFile != nil {
		logFile.Sync()
		logFile.Close()
	}
	os.Exit(1)
}

func createStopEvent() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(stopEventName)
	if err != nil {
		return 0, err
	}
	// Manual reset, initially not signalled. Opens the existing event when a
	// guard is already running.
	h, err := windows.CreateEvent(stopEventSecurity(), 1, 0, name)
	if h != 0 && err == windows.ERROR_ALREADY_EXISTS {
		// Somebody created the event first, which is the normal case: -stop only
		// needs to open the event and set it, not to own it. CreateEvent still
		// hands back a usable handle here, so this is success, not a failure.
		return h, nil
	}
	return h, err
}

func signalStop() error {
	handle, err := createStopEvent()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.SetEvent(handle)
}

// processAlive answers whether a process id still belongs to a living process.
// A handle that cannot be opened at all is treated as gone, which is the safe
// reading here: the manager runs as a service under the same account as the
// guard, so a living manager can always be opened.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	err = windows.GetExitCodeProcess(handle, &code)
	if err != nil {
		return true
	}
	// STILL_ACTIVE
	return code == 259
}

func parseEndpoint(value string) (net.IP, uint16, error) {
	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return nil, 0, fmt.Errorf("%q is not an IPv4 address", host)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, 0, err
	}
	return ip, uint16(port), nil
}

func luidForAlias(alias string) (uint64, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, err
	}
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.FriendlyName(), alias) {
			return uint64(adapter.LUID), nil
		}
	}
	return 0, fmt.Errorf("interface %q was not found, is the chain up?", alias)
}

func splitList(value, separator string) []string {
	items := make([]string, 0)
	for _, item := range strings.Split(value, separator) {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func parseIPs(values []string) []net.IP {
	ips := make([]net.IP, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func parseCIDRs(values []string) []net.IPNet {
	networks := make([]net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil || network == nil {
			continue
		}
		networks = append(networks, *network)
	}
	return networks
}

func joinIPs(ips []net.IP) string {
	if len(ips) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

func joinNets(networks []net.IPNet) string {
	if len(networks) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(networks))
	for i := range networks {
		parts = append(parts, networks[i].String())
	}
	return strings.Join(parts, ", ")
}

// --------------------------------------------------------------------------
// Holding the kill switch across a rebuild of the chain (patch 11)
//
// The hop 2 endpoint is permitted only through the hop 1 interface, which is
// pinned by LUID. Wintun hands out a fresh LUID whenever an adapter is
// recreated, so after the chain repairs itself the old filters point at an
// interface that no longer exists and hop 2 can never handshake again.
//
// So the guard now keeps watch over the two interfaces. When a LUID changes
// it rebuilds its own filters around the new ones. While a hop is missing
// nothing is touched at all, which keeps the machine shut in - unless the
// manager is gone too, see the orphan handling of pack 42.
// --------------------------------------------------------------------------

const (
	chainReloadPoll   = 3 * time.Second
	chainHeartbeatGap = 5 * time.Minute
)

func holdKillSwitch(stopEvent windows.Handle, cfg *firewall.ChainFirewallConfig, hop1If, hop2If string, timeout int, mgrPid int, orphanGrace int) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(time.Duration(timeout) * time.Second)
		say("hold  : %d seconds, then the kill switch is removed automatically", timeout)
	} else {
		say("hold  : until stopped, and the filters follow the chain if it is rebuilt")
	}

	armed := true
	reloads := 0
	lastBeat := time.Now()
	poll := uint32(chainReloadPoll / time.Millisecond)
	var mgrGoneAt time.Time
	graceSpan := time.Duration(orphanGrace) * time.Second

	for {
		event, waitErr := windows.WaitForSingleObject(stopEvent, poll)
		if waitErr != nil {
			firewall.DisableChainFirewall()
			say("KILLSWITCH=REMOVED reason=waiterror error=%v", waitErr)
			return
		}
		if event != waitTimeout {
			firewall.DisableChainFirewall()
			say("KILLSWITCH=REMOVED reason=stopped")
			return
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			firewall.DisableChainFirewall()
			say("KILLSWITCH=REMOVED reason=timeout")
			return
		}

		// Is there still somebody who could repair the chain?
		if mgrPid > 0 {
			if processAlive(mgrPid) {
				if !mgrGoneAt.IsZero() {
					mgrGoneAt = time.Time{}
					say("KILLSWITCH=HOLD state=managerback pid=%d", mgrPid)
				}
			} else if mgrGoneAt.IsZero() {
				mgrGoneAt = time.Now()
				say("The manager (pid %d) is gone, so a broken chain is released in %d seconds", mgrPid, orphanGrace)
			}
		}

		// A failed reload leaves nothing installed, so try again at once.
		if !armed {
			err := firewall.EnableChainFirewall(cfg)
			if err != nil {
				say("KILLSWITCH=FAIL reason=reload error=%v", err)
				continue
			}
			armed = true
			reloads++
			lastBeat = time.Now()
			say("KILLSWITCH=RELOAD hop1=%d hop2=%d reloads=%d", cfg.Hop1LUID, cfg.Hop2LUID, reloads)
			continue
		}

		hop1LUID, err1 := luidForAlias(hop1If)
		hop2LUID, err2 := luidForAlias(hop2If)
		if err1 != nil || err2 != nil {
			// A hop is down. The filters stay exactly as they are, so the
			// machine keeps everything but its LAN shut off until the chain
			// is back - as long as somebody is still working on it.
			if !mgrGoneAt.IsZero() && time.Since(mgrGoneAt) >= graceSpan {
				firewall.DisableChainFirewall()
				say("KILLSWITCH=REMOVED reason=orphan hop1err=%v hop2err=%v", err1, err2)
				say("The chain is down and the manager is gone, so there is nothing left to protect.")
				return
			}
			if time.Since(lastBeat) >= chainHeartbeatGap {
				lastBeat = time.Now()
				say("KILLSWITCH=HOLD state=hopdown hop1err=%v hop2err=%v", err1, err2)
			}
			continue
		}

		if hop1LUID == cfg.Hop1LUID && hop2LUID == cfg.Hop2LUID {
			if time.Since(lastBeat) >= chainHeartbeatGap {
				lastBeat = time.Now()
				if mgrGoneAt.IsZero() {
					say("KILLSWITCH=HOLD hop1=%d hop2=%d reloads=%d", cfg.Hop1LUID, cfg.Hop2LUID, reloads)
				} else {
					// The chain still carries the traffic, so holding on hurts
					// nobody. awgchain-guard.exe -stop lets go on demand.
					say("KILLSWITCH=HOLD state=orphanbutup hop1=%d hop2=%d", cfg.Hop1LUID, cfg.Hop2LUID)
				}
			}
			continue
		}

		say("The chain was rebuilt: hop1 luid %d -> %d, hop2 luid %d -> %d", cfg.Hop1LUID, hop1LUID, cfg.Hop2LUID, hop2LUID)
		cfg.Hop1LUID = hop1LUID
		cfg.Hop2LUID = hop2LUID
		firewall.DisableChainFirewall()
		armed = false
		err := firewall.EnableChainFirewall(cfg)
		if err != nil {
			say("KILLSWITCH=FAIL reason=reload error=%v", err)
			continue
		}
		armed = true
		reloads++
		lastBeat = time.Now()
		say("KILLSWITCH=RELOAD hop1=%d hop2=%d reloads=%d", hop1LUID, hop2LUID, reloads)
	}
}

// --------------------------------------------------------------------------
// Pack 44: "awgchain-guard.exe -stop" used to fail with "Access is denied".
//
// The guard is started by the manager service, so the stop event is created
// by LocalSystem, and the default security of that object lets nobody else
// signal it. The event is now created with an explicit descriptor: SYSTEM and
// the administrators get full access, everyone else gets just the right to
// set it, which is all that -stop needs.
// --------------------------------------------------------------------------

func stopEventSecurity() *windows.SecurityAttributes {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;0x001F0003;;;SY)(A;;0x001F0003;;;BA)(A;;0x00100002;;;WD)")
	if err != nil {
		return nil
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa
}
