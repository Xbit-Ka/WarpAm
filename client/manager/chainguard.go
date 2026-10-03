//go:build windows

/* AwgChain - patch 10: the chain looks after itself.
 *
 * Everything worked from the interface after patches 8 and 9, but two jobs
 * were still done by hand from awgchain.bat:
 *
 *   awgchain.bat kson    arm the kill switch
 *   awgchain-watch.bat   keep a watchdog running
 *
 * Both now happen inside the manager, which is the one component that always
 * knows when a hop comes up and when it goes down:
 *
 *   the top hop handshakes  -> awgchain-guard.exe is started with arguments
 *                              worked out from the configs themselves
 *   the top hop handshakes  -> a watch goroutine starts
 *   any hop is stopped      -> watch stops, kill switch stands down
 *
 * The watch reads last_handshake_time_sec of every hop over UAPI. When a hop
 * is gone or silent for too long it rebuilds the chain from the bottom up,
 * exactly as the PowerShell watchdog did, but without leaving the kill switch
 * unarmed in between.
 *
 * Pack 68: the no-autoguard file is not read any more. The lock engine
 * is a setting now, Global.LockEngine in settings.json, and an existing
 * no-autoguard file is carried over into it once and then deleted. See
 * chainlock68.go.
 */

package manager

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/brand"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const (
	chainGuardStopEventName = brand.LegacyGuardStopEvent
	chainGuardExeName       = "awgchain-guard.exe"
	chainWatchInterval      = 5 * time.Second
	chainHandshakeMaxAge    = 180 * time.Second
	chainRepairGrace        = 25 * time.Second
	chainMaxRepairs         = 20
	chainSlowRepairGrace    = 5 * time.Minute
	// How long a hop is given to reach the stopped state before the chain is
	// raised again. Starting a hop that is still shutting down is refused by
	// the manager with "please allow the tunnel to finish activating", which
	// used to cost a whole grace period.
	chainStopWait      = 20 * time.Second
	chainStopPoll      = 200 * time.Millisecond
	chainStartRetries  = 6
	chainStartRetryGap = 3 * time.Second
	// Pack 81: how long a repair waits for the leaf to handshake before it
	// says anything about the result. Start returns as soon as the adapter
	// exists, so the old line "the chain is back up" was written while the
	// leaf had not spoken to its server even once. Twenty seconds is short
	// enough not to hold the watch up and long enough for a handshake that
	// is going to happen at all.
	chainRepairHandshakeWait = 20 * time.Second
	// Pack 85: the gap between repairs grows instead of staying at 25
	// seconds. On the night of 26 September the chain was rebuilt every 46
	// seconds for hours against an error that no rebuild could cure
	// ("problem code: 0x1F"), which left 92 failed hop creations and a queue
	// of windows behind it.
	chainRepairBackoffStart = 5 * time.Second
	chainRepairBackoffMax   = 2 * time.Minute
	// How many rounds are tried before the watch says out loud that it
	// cannot fix this and stops. chainFastRepairs are the quick rounds,
	// chainSlowRepairs the ones after the gap has grown to its maximum.
	chainFastRepairs = 5
	chainSlowRepairs = 3
	// How long a hop may keep handshaking while receiving nothing at all
	// before it is called broken. A handshake only proves the server is
	// there; on 26 September both hops handshook and carried zero bytes.
	chainRxSilence = 60 * time.Second
)

var (
	chainGuardLock    sync.Mutex
	chainGuardArmedBy string
	chainGuardProcess *os.Process
	chainWatchCancel  chan struct{}
	// chainWatchLeaf is the leaf of the chain the watch follows, or "".
	// Pack 95: the proxy watch of pack 89 leaves the hops of that chain to
	// this guard.
	chainWatchLeaf string
)

// Pack 85: two small books. The first remembers since when a hop has been
// handshaking without receiving anything, the second remembers the chains the
// watch has given up on, so that it does not start over behind the user back.
var (
	chainRxMu           sync.Mutex
	chainRxSilentSince  = make(map[string]time.Time)
	chainGiveUpMu       sync.Mutex
	chainGiveUpReasons  = make(map[string]string)
)

// chainBackoff is the gap before the next repair round, doubling from five
// seconds up to two minutes.
func chainBackoff(failures int) time.Duration {
	gap := chainRepairBackoffStart
	for i := 0; i < failures; i++ {
		if gap >= chainRepairBackoffMax {
			return chainRepairBackoffMax
		}
		gap *= 2
	}
	if gap > chainRepairBackoffMax {
		return chainRepairBackoffMax
	}
	return gap
}

// chainNoteGiveUp writes down that this chain is not being tried any more.
func chainNoteGiveUp(leaf, why string) {
	chainGiveUpMu.Lock()
	chainGiveUpReasons[strings.ToLower(leaf)] = why
	chainGiveUpMu.Unlock()
}

// ChainGaveUp answers whether the watch has given up on this chain.
func ChainGaveUp(leaf string) (string, bool) {
	chainGiveUpMu.Lock()
	defer chainGiveUpMu.Unlock()
	why, found := chainGiveUpReasons[strings.ToLower(leaf)]
	return why, found
}

// ChainClearGiveUp forgets that mark, which is what a deliberate raise does.
func ChainClearGiveUp(leaf string) {
	chainGiveUpMu.Lock()
	delete(chainGiveUpReasons, strings.ToLower(leaf))
	chainGiveUpMu.Unlock()
}

// chainShutdownFlag is set when the service manager tells us Windows is
// going down. Pack 71: until then the watch kept trying to repair the chain
// during a shutdown and the log filled with "A system shutdown is in
// progress".
var chainShutdownFlag atomic.Bool

// ChainNoteShuttingDown is called from the service control handler.
func ChainNoteShuttingDown() {
	if chainShutdownFlag.Swap(true) {
		return
	}
	log.Printf("[WarpAm] Windows is shutting down: the watch and the repair stand down, the kill switch is left as it is")
}

func chainShuttingDown() bool {
	return chainShutdownFlag.Load()
}

// chainStateDir is where the log and the state files live.
// AwgChain pack 86: the state of the guard moves into the data folder of
// the program, next to the settings and the configurations. ProgramData is
// not used any more, so a folder carried on a stick carries its state with
// it and nothing is left behind on the machine.
func chainStateDir() string {
	dir, err := conf.ChainDataDir()
	if err != nil || len(dir) == 0 {
		return ""
	}
	dir = filepath.Clean(dir)
	os.MkdirAll(dir, 0o700)
	return dir
}

// chainHopOrder returns the hops of the chain that ends at leaf, bottom hop
// first. A tunnel that is not part of a chain answers with itself alone.
func chainHopOrder(leaf string) []string {
	order := []string{leaf}
	name := leaf
	for i := 0; i < chainMaxDepth; i++ {
		parent := chainParentName(name)
		if parent == "" {
			break
		}
		order = append([]string{parent}, order...)
		name = parent
	}
	return order
}

// chainEndpointOf gives the endpoint of a hop as ip:port, resolving a host
// name if the config carries one.
func chainEndpointOf(name string) (string, error) {
	c, err := conf.LoadFromName(name)
	if err != nil {
		return "", err
	}
	for i := range c.Peers {
		endpoint := c.Peers[i].Endpoint
		if endpoint.IsEmpty() {
			continue
		}
		host := strings.Trim(strings.TrimSpace(endpoint.Host), "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			resolved, err := net.LookupIP(host)
			if err != nil {
				continue
			}
			for _, candidate := range resolved {
				if candidate.To4() != nil {
					ip = candidate
					break
				}
			}
		}
		if ip == nil || ip.To4() == nil {
			continue
		}
		return fmt.Sprintf("%s:%d", ip.String(), endpoint.Port), nil
	}
	return "", fmt.Errorf("no usable IPv4 endpoint in the config of %q", name)
}

// chainDNSOf lists the resolvers of a hop, comma separated for the guard.
func chainDNSOf(name string) string {
	c, err := conf.LoadFromName(name)
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(c.Interface.DNS))
	for _, server := range c.Interface.DNS {
		parts = append(parts, fmt.Sprint(server))
	}
	return strings.Join(parts, ",")
}

func chainAdapterLUID(name string) (winipcfg.LUID, bool) {
	if strings.TrimSpace(name) == "" {
		return 0, false
	}
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, false
	}
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.FriendlyName(), strings.TrimSpace(name)) {
			return adapter.LUID, true
		}
	}
	return 0, false
}

// chainLocalNetworks finds the private networks that the given adapter is on,
// so that the kill switch never cuts the machine off from its own LAN. This
// is what keeps a remote desktop session alive while the chain is armed.
func chainLocalNetworks(adapter string) []string {
	result := make([]string, 0, 2)
	luid, ok := chainAdapterLUID(adapter)
	if !ok {
		return result
	}
	rows, err := winipcfg.GetIPForwardTable2(winipcfg.AddressFamily(windows.AF_INET))
	if err != nil {
		return result
	}
	seen := make(map[string]bool, 2)
	for i := range rows {
		if rows[i].InterfaceLUID != luid {
			continue
		}
		if hop := rows[i].NextHop.IP(); hop != nil && !hop.IsUnspecified() {
			continue
		}
		prefix := rows[i].DestinationPrefix.IPNet()
		if prefix.IP == nil || prefix.IP.To4() == nil {
			continue
		}
		ones, bits := prefix.Mask.Size()
		if bits != 32 || ones < 8 || ones > 30 {
			continue
		}
		if !prefix.IP.IsPrivate() {
			continue
		}
		text := prefix.String()
		if seen[text] {
			continue
		}
		seen[text] = true
		result = append(result, text)
	}
	return result
}

// chainArmGuard installs the kill switch for the chain ending at leaf.
//
// Pack 68 (I2): everything happens in the manager service. The branch
// that started awgchain-guard.exe is gone, and with it the -mgrpid and
// -orphangrace arguments, the death counter dance and the two minutes of
// closed machine after a crash. What is left is short enough to read:
// a lock that the user lifted stays lifted, an engine set to off arms
// nothing, and anything else installs the filters here and now.
func (s *ManagerService) chainArmGuard(leaf string) {
	// Pack 78: the chain carries the local proxy and nothing else. Its
	// hops install no routes of the machine, so a kill switch here closes
	// a machine that never went through the chain. Pack 75 refused the
	// lock at the first arm only, and the watch armed it again on its
	// first healthy round: the log of 24.09 shows the chain coming up at
	// 16:14:23 and the lock going on at 16:14:28, after which everything
	// but the proxy went quiet. The refusal belongs here, where every
	// caller passes: the first arm, the watch, the lock button and the
	// rebuild after a repair. The IPv6 filter is skipped for the same
	// reason - it cuts a machine that the chain does not carry.
	if chainLeafIsSeparate(leaf) {
		chainLogChanged("lock-separate", "[WarpAm] %s carries the local proxy only, so the machine stays open and the proxy answers for itself", leaf)
		return
	}
	// Pack 71: a tunnel that is not a chain of at least two hops has no
	// kill switch at all. The old code walked on and ended in "the chain
	// ending at X is not up yet, so the kill switch waits for it", which
	// promised something that was never going to happen.
	if len(chainHopOrder(leaf)) < 2 {
		chainLogChanged("lock-plain", "[WarpAm] %s is a plain tunnel, so no kill switch is installed for it: only the IPv6 filter applies", leaf)
		chainApplyIPv6For(leaf)
		return
	}
	if chainLockSuppressedNow() {
		chainLogChanged("lock-suppressed", "[WarpAm] The lock stays down: it was lifted by hand and no tunnel has been raised on purpose since")
		return
	}
	if chainLockEngineOff() {
		chainLogChanged("lock-engine-off", "[WarpAm] The lock engine is off in the settings, so no kill switch is installed for %s", leaf)
		// The IPv6 box is a separate wish and is still obeyed.
		chainApplyIPv6For(leaf)
		return
	}

	if chainArmLockInProc(leaf) {
		chainGuardLock.Lock()
		// Pack 70: "taken care of" is not "locked". chainArmLockInProc also
		// answers true when the kill switch box of this tunnel is off, and
		// chainGuardArmedBy then named a lock that did not exist: the
		// Settings tab said the lock was held while the machine was open.
		if chainLockIsOn() {
			chainGuardArmedBy = leaf
		} else {
			chainGuardArmedBy = ""
		}
		chainGuardLock.Unlock()
		chainLogForget("lock-not-up-yet")
		chainGuardNoteArm()
		return
	}

	// The chain is not ready: no adapters yet, or the endpoints cannot be
	// read. The watch calls this again every few seconds, so this is a
	// note, not a failure.
	//
	// Pack 72: while the chain is being built the lock of the paranoid
	// start is still standing, and it knows only what could be seen when
	// it was put up. It is rebuilt here, so the endpoint of the next hop
	// and the adapter of the one before it are let through as soon as
	// they appear. Without this the chain could never come up from behind
	// its own lock: the second hop had nowhere to send its handshake.
	if chainBootLockIsOn() {
		chainArmBootLock(leaf)
	}
	chainLogChanged("lock-not-up-yet", "[WarpAm] The chain ending at %s is not up yet, so the kill switch waits for it", leaf)
}

// chainArmLockOnDemand is the lock button pressed towards "closed". Pack 71.
//
// It forgets the hand-lift first: without that the arming below is refused
// by chainArmGuard, which is exactly what makes the lift survive a restart.
// When a chain is up the normal kill switch goes on; when nothing is up the
// coarse boot lock is used, so that "close the machine now" means what it
// says even with no tunnel running.
func (s *ManagerService) chainArmLockOnDemand() error {
	chainLockSuppress(false)

	leaf := chainLockedLeaf()
	if leaf == "" {
		leaf = strings.TrimSpace(ChainGlobal().Target())
	}
	if leaf == "" {
		leaf = strings.TrimSpace(ChainGlobal().LastTunnel)
	}

	if leaf != "" && len(chainHopOrder(leaf)) >= 2 {
		s.chainArmGuard(leaf)
		if chainLockIsOn() {
			return nil
		}
	}

	// No chain to wrap the filters around. Closing the machine outright is
	// still an honest answer to "put the lock up", and it is exactly what
	// the paranoid start does.
	chainArmBootLock(leaf)
	if chainBootLockIsOn() {
		return nil
	}
	// Pack 82: shown in a window behind "Замок не поставлен: ", so the
	// sentence starts small and adds only the reason. The log stays English.
	return errors.New("\u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u043d\u0435 \u043f\u043e\u0434\u043d\u044f\u0442\u0430, \u0430 \u0437\u0430\u043a\u0440\u044b\u0442\u044c \u043c\u0430\u0448\u0438\u043d\u0443 \u0446\u0435\u043b\u0438\u043a\u043e\u043c \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c")
}

func chainSignalGuardStop() error {
	name, err := windows.UTF16PtrFromString(chainGuardStopEventName)
	if err != nil {
		return err
	}
	// Manual reset event. Creating it by name opens the existing one when the
	// guard is already running, which is exactly what we want here.
	handle, err := windows.CreateEvent(chainStopEventSecurity(), 1, 0, name)
	if handle != 0 && err == windows.ERROR_ALREADY_EXISTS {
		// The event already exists and we got a working handle: that is fine.
		err = nil
	}
	if err != nil && handle == 0 {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.SetEvent(handle)
}

func chainDisarmGuard() {
	// Pack 51: an in-process lock is lifted here and now, with no grace timer.
	chainDisarmLockRespectingMode()
	chainGuardLock.Lock()
	process := chainGuardProcess
	chainGuardProcess = nil
	chainGuardArmedBy = ""
	chainGuardLock.Unlock()
	if process == nil {
		return
	}
	err := chainSignalGuardStop()
	if err != nil {
		log.Printf("[WarpAm] Could not ask the kill switch to stand down: %v", err)
	}
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if !chainProcessAlive(process.Pid) {
			log.Printf("[WarpAm] Kill switch disarmed")
			return
		}
	}
	log.Printf("[WarpAm] The kill switch did not stand down in time, ending it")
	process.Kill()
}

func chainProcessAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	err = windows.GetExitCodeProcess(handle, &code)
	if err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// chainHandshakeAge is the age of the freshest handshake of a running hop.
func chainHandshakeAge(c *conf.Config) (time.Duration, bool) {
	best := time.Duration(-1)
	for i := range c.Peers {
		stamp := c.Peers[i].LastHandshakeTime
		if stamp.IsEmpty() {
			continue
		}
		age := time.Since(time.Unix(0, 0).Add(time.Duration(stamp)))
		if best < 0 || age < best {
			best = age
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
}

// chainHopReceived counts the bytes a running hop has received from all of
// its peers. Pack 85.
func chainHopReceived(c *conf.Config) uint64 {
	var total uint64
	for i := range c.Peers {
		total += uint64(c.Peers[i].RxBytes)
	}
	return total
}

// chainRxTrouble watches for a hop that handshakes and carries nothing.
//
// Pack 85: this is the state the machine was in on 26 September. Both hops
// handshook every few seconds, so the watch called the chain healthy, while
// the received counters stood at zero and no packet of the user ever came
// back. Health is now measured by traffic, not by greetings alone.
func chainRxTrouble(name string, runtime *conf.Config) string {
	key := strings.ToLower(name)
	now := time.Now()

	chainRxMu.Lock()
	defer chainRxMu.Unlock()

	if chainHopReceived(runtime) != 0 {
		delete(chainRxSilentSince, key)
		return ""
	}
	since, seen := chainRxSilentSince[key]
	if !seen {
		chainRxSilentSince[key] = now
		return ""
	}
	silent := now.Sub(since)
	if silent < chainRxSilence {
		return ""
	}
	return fmt.Sprintf("%s handshakes but has received nothing for %d seconds", name, int(silent.Seconds()))
}

// chainTrouble names the first thing wrong with the chain, or "" when it is
// healthy.
func (s *ManagerService) chainTrouble(leaf string) string {
	reason, _ := s.chainTroubleHop(leaf)
	return reason
}

// chainTroubleHop also names the hop the trouble was found on, so that a
// repair can rebuild that level and the ones above it instead of the whole
// chain. Pack 85.
func (s *ManagerService) chainTroubleHop(leaf string) (string, string) {
	for _, name := range chainHopOrder(leaf) {
		state, err := s.State(name)
		if err != nil {
			return fmt.Sprintf("%s cannot be queried: %v", name, err), name
		}
		if state != TunnelStarted {
			return fmt.Sprintf("%s is not running", name), name
		}
		runtime, err := s.RuntimeConfig(name)
		if err != nil || runtime == nil {
			return fmt.Sprintf("%s does not answer on its pipe", name), name
		}
		age, ok := chainHandshakeAge(runtime)
		if !ok {
			return fmt.Sprintf("%s has never handshaken", name), name
		}
		if age > chainHandshakeMaxAge {
			return fmt.Sprintf("%s last handshook %d seconds ago", name, int(age.Seconds())), name
		}
		if reason := chainRxTrouble(name, runtime); len(reason) != 0 {
			return reason, name
		}
		// Pack 95: a hop that sends and hears almost nothing, see
		// chainzombie.go.
		if reason := chainZombieTrouble(name, runtime); len(reason) != 0 {
			return reason, name
		}
	}
	return "", ""
}

// chainRepair drops the chain and raises it again.
//
// Pack 85: the old comment here claimed the kill switch stays armed throughout
// and that nothing escapes while the tunnels are gone. That was only true for
// a chain that had already been up once: the rule set is armed by
// chainArmGuard, and chainArmGuard is only reached when the chain is healthy,
// so a chain that never came up left the way out wide open. The boot lock is
// put up by the watch when it gives up, which is what really holds the line
// in that case.
func (s *ManagerService) chainRepair(leaf string) {
	s.chainRepairFrom(leaf, "")
}

// chainRepairFrom rebuilds the chain from the broken level upwards. An empty
// broken name means the whole chain.
//
// Pack 85: tearing down every hop for a fault in the top one threw away a
// working outer hop and a handshake that had taken seconds to get, on every
// single round of the loop.
func (s *ManagerService) chainRepairFrom(leaf, broken string) {
	if chainShuttingDown() {
		log.Printf("[WarpAm] Repair: Windows is shutting down, so nothing is touched")
		return
	}
	started := time.Now()
	hops := chainHopOrder(leaf)
	from := 0
	if len(broken) != 0 {
		for i := range hops {
			if strings.EqualFold(hops[i], broken) {
				from = i
				break
			}
		}
	}
	hops = hops[from:]
	if from > 0 {
		log.Printf("[WarpAm] Repair: %s is the broken level, so only it and what rides on it are rebuilt", hops[0])
	}
	s.chainTearDown(hops)

	for attempt := 1; attempt <= chainStartRetries; attempt++ {
		err := s.Start(leaf)
		if err == nil {
			// Pack 81: an honest answer. The hops came up, which is not
			// the same thing as a working chain, and on 25 September the
			// log said "the chain is back up" three times while the leaf
			// had never handshaken. The kill switch is only moved onto
			// the new interfaces once the chain really carries traffic.
			if waitErr := s.chainWaitForHopTimeout(leaf, chainRepairHandshakeWait); waitErr != nil {
				log.Printf("[WarpAm] Repair: the hops came up but the chain is not whole yet (%v), so the kill switch stays where it is and the watch keeps trying", waitErr)
				return
			}
			log.Printf("[WarpAm] Repair: the chain is back up after %d seconds, re-arming the kill switch on the new interfaces", int(time.Since(started).Seconds()))
			s.chainRearmLockAfterRepair(leaf)
			return
		}
		log.Printf("[WarpAm] Repair: try %d of %d did not take: %v", attempt, chainStartRetries, err)
		if attempt == chainStartRetries {
			break
		}
		time.Sleep(chainStartRetryGap)
		// A half-raised hop has to be cleared away before the next try.
		s.chainTearDown(hops)
	}
	log.Printf("[WarpAm] Repair: gave up this round after %d seconds, the watch will try again", int(time.Since(started).Seconds()))
}

// chainTearDown stops every hop from the top down and waits until each one
// really is stopped, so the next Start is not refused.
func (s *ManagerService) chainTearDown(hops []string) {
	for i := len(hops) - 1; i >= 0; i-- {
		err := UninstallTunnel(hops[i])
		if err != nil && err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			log.Printf("[WarpAm] Repair: could not stop %s: %v", hops[i], err)
		}
	}
	for _, name := range hops {
		s.chainWaitStopped(name)
	}
}

func (s *ManagerService) chainWaitStopped(name string) {
	deadline := time.Now().Add(chainStopWait)
	for time.Now().Before(deadline) {
		state, err := s.State(name)
		if err != nil || state == TunnelStopped {
			return
		}
		time.Sleep(chainStopPoll)
	}
	log.Printf("[WarpAm] Repair: %s is taking its time to stop, carrying on anyway", name)
}

func (s *ManagerService) chainWatch(leaf string, stop chan struct{}) {
	// chainWatch v2 (patch 20): the counter below counts failures in a row.
	// It used to count every repair ever made by this manager, so twenty
	// repairs spread over days pushed the watch into its five minute mode for
	// good. A chain that went down after that waited minutes for help even
	// though each repair was finishing in seven seconds.
	log.Printf("[WarpAm] Watching the chain that ends at %s", leaf)
	failures := 0
	slow := false
	var lastRepair time.Time
	for {
		select {
		case <-stop:
			log.Printf("[WarpAm] No longer watching the chain")
			return
		case <-time.After(chainWatchInterval):
		}

		if chainShuttingDown() {
			// Pack 71: during a shutdown every Stop and Start is refused
			// with "A system shutdown is in progress", and the log filled
			// up with repairs that could not possibly work.
			log.Printf("[WarpAm] Windows is shutting down, so the chain is left alone")
			return
		}

		// Pack 81: the chain may no longer be the thing the user wants up.
		// Repairing it then is not protection, it is throwing the tunnel
		// the user raised afterwards off the machine, which is exactly
		// what happened three times on 25 September.
		if why := chainWatchGiveUp(leaf); len(why) != 0 {
			log.Printf("[WarpAm] The chain that ends at %s is not watched any more: %s", leaf, why)
			return
		}

		reason, broken := s.chainTroubleHop(leaf)
		if reason == "" {
			// A healthy chain is also the moment to arm a kill switch that is
			// not up yet, for instance because the first try ran before the
			// interfaces existed. Arming twice is harmless.
			if failures > 0 {
				log.Printf("[WarpAm] The chain is healthy again, the repair counter goes back to zero")
			}
			failures = 0
			slow = false
			// Pack 85: a chain that works again is no longer a chain that
			// was given up on.
			ChainClearGiveUp(leaf)
			s.chainArmGuard(leaf)
			// Pack 74: the same round of the watch puts the proxy back
			// if it is wanted and is not there, for instance because the
			// port was busy when the tunnel came up.
			chainProxyFollow(leaf)
			continue
		}
		// Pack 95: a dead hop first gets a new handshake, which is not a
		// repair and is not counted; see chainzombie.go.
		next, wait := s.chainZombieStep(leaf, broken)
		if wait {
			continue
		}
		broken = next
		// Pack 85: the gap grows with every failed round, 5, 10, 20, 40, 80
		// seconds and then two minutes, instead of a fixed 25 seconds. A
		// fault that no rebuild can cure no longer costs a rebuild every
		// half minute all night.
		grace := chainBackoff(failures)
		if !lastRepair.IsZero() && time.Since(lastRepair) < grace {
			continue
		}
		failures++
		log.Printf("[WarpAm] The chain needs repair: %s (round %d of %d, next gap %v)", reason, failures, chainFastRepairs+chainSlowRepairs, chainBackoff(failures))
		s.chainRepairFrom(leaf, broken)
		lastRepair = time.Now()
		if failures >= chainFastRepairs+chainSlowRepairs {
			// Pack 85: an honest end. The watch used to try for ever, and
			// the only trace of it was a modal window every round. It says
			// what is wrong, closes the way out with the boot lock so that
			// nothing leaks while the chain is down, and stops. Raising the
			// tunnel by hand clears the mark and starts over.
			chainNoteGiveUp(leaf, reason)
			log.Printf("[WarpAm] %d rounds did not fix the chain that ends at %s: %s. No more attempts are made. The way out stays closed by the boot lock; raise the tunnel again by hand once the cause is gone", failures, leaf, reason)
			chainArmBootLock(leaf)
			return
		}
		if failures >= chainFastRepairs && !slow {
			slow = true
			log.Printf("[WarpAm] %d rounds in a row did not help (%s), so the gap is at its longest now and only %d more rounds are tried", failures, reason, chainSlowRepairs)
		}
	}
}

func (s *ManagerService) chainStartWatch(leaf string) {
	// Pack 85: a chain the watch has given up on is not picked up again by
	// some other path; only a deliberate raise clears that mark.
	if why, gaveUp := ChainGaveUp(leaf); gaveUp {
		log.Printf("[WarpAm] No watch for the chain that ends at %s: it was given up on (%s)", leaf, why)
		return
	}
	chainGuardLock.Lock()
	if chainWatchCancel != nil {
		chainGuardLock.Unlock()
		return
	}
	stop := make(chan struct{})
	chainWatchCancel = stop
	chainWatchLeaf = leaf
	chainGuardLock.Unlock()
	go s.chainWatch(leaf, stop)
}

func chainStopWatch() {
	chainGuardLock.Lock()
	stop := chainWatchCancel
	chainWatchCancel = nil
	chainWatchLeaf = ""
	chainGuardLock.Unlock()
	if stop != nil {
		close(stop)
	}
}

// chainWatchedHop answers whether a tunnel is a hop of the chain the guard
// is watching right now. Pack 95.
func chainWatchedHop(name string) bool {
	chainGuardLock.Lock()
	leaf := chainWatchLeaf
	chainGuardLock.Unlock()
	if len(leaf) == 0 {
		return false
	}
	for _, hop := range chainHopOrder(leaf) {
		if strings.EqualFold(hop, name) {
			return true
		}
	}
	return false
}

// chainLeafIsSeparate answers whether the tunnel at the end of a chain
// carries the local proxy only. Pack 75.
func chainLeafIsSeparate(leaf string) bool {
	settings := ChainSettingsFor(leaf)
	return settings.Proxy && settings.ProxySplit
}

// chainInstallAndArm replaces the plain InstallTunnel call at the end of
// Start. The top hop of a chain also gets a kill switch and a watch.
func (s *ManagerService) chainInstallAndArm(tunnelName, path string) error {
	err := InstallTunnel(path)
	if err != nil {
		return err
	}
	// Pack 74: a tunnel that asks for a local proxy gets one here, before
	// anything else. The proxy takes its port at once and refuses every
	// connection until the adapter is really there, so a program that was
	// waiting for the port does not have to be restarted.
	chainProxyFollow(tunnelName)
	if !chainHopByName(tunnelName) {
		// Pack 64: a plain tunnel still obeys its own boxes.
		chainPlainTunnelUp(tunnelName)
		return nil
	}
	if len(chainChildNames(tunnelName)) != 0 {
		// Not the top hop: whoever rides on this one will arm the chain.
		return nil
	}
	if chainBootRaisingNow() {
		// Pack 68 (F3a): the start-up raise waits for the leaf itself and
		// arms the chain when the wait succeeds. Starting a second waiter
		// here gave two waits of 45 seconds on the same handshake, two
		// watches and two arms, and the attempt that was already being
		// given up on could still arm the lock behind the next one.
		return nil
	}
	go s.chainArmWhenReady(tunnelName)
	return nil
}

func (s *ManagerService) chainArmWhenReady(leaf string) {
	// Pack 85: this runs after a deliberate raise, which is exactly the
	// moment the watch is allowed to start hoping again.
	if why, gaveUp := ChainGaveUp(leaf); gaveUp {
		log.Printf("[WarpAm] The chain that ends at %s had been given up on (%s); this raise starts the count over", leaf, why)
		ChainClearGiveUp(leaf)
	}
	err := s.chainWaitForHop(leaf)
	if err != nil {
		// A chain that did not come up cleanly still gets a watch, because
		// the watch is the thing that repairs it.
		log.Printf("[WarpAm] %s did not come up cleanly (%v), so the watch takes over", leaf, err)
	} else {
		// Pack 78: the refusal for a proxy-only chain moved inside
		// chainArmGuard, so that the watch and the lock button obey it too.
		s.chainArmGuard(leaf)
	}
	// Pack 81: the wait above can last three quarters of a minute, and the
	// world moves while it runs. On 25 September another tunnel was raised
	// during exactly this wait, and the watch that started here spent the
	// next minute throwing it off the machine.
	if why := chainWatchGiveUp(leaf); len(why) != 0 {
		log.Printf("[WarpAm] No watch is started for the chain that ends at %s: %s", leaf, why)
		return
	}
	s.chainStartWatch(leaf)
}

// chainBeforeStop runs when a tunnel is stopped on purpose. A repair uses
// UninstallTunnel directly and therefore does not come through here, which is
// what keeps the kill switch armed while the chain is being rebuilt.
func (s *ManagerService) chainBeforeStop(tunnelName string) {
	// Pack 74: the proxy of this tunnel, or of the chain this hop belongs
	// to, goes away with it. This runs before everything else, so nothing
	// can be accepted on a port that is about to lose its tunnel.
	for _, info := range ChainProxyState() {
		for _, hop := range chainHopOrder(info.Leaf) {
			if strings.EqualFold(hop, tunnelName) {
				chainProxyStop(info.Leaf, tunnelName+" was asked to stop")
				break
			}
		}
	}

	chainGuardLock.Lock()
	armedBy := chainGuardArmedBy
	watching := chainWatchCancel != nil
	chainGuardLock.Unlock()
	if armedBy == "" && !watching {
		return
	}
	involved := false
	if armedBy != "" {
		for _, hop := range chainHopOrder(armedBy) {
			if strings.EqualFold(hop, tunnelName) {
				involved = true
				break
			}
		}
	} else {
		involved = chainHopByName(tunnelName)
	}
	if !involved {
		return
	}
	log.Printf("[WarpAm] %s was asked to stop, so the watch and the kill switch stand down", tunnelName)

	chainStopWatch()
	chainGuardResetDeaths()
	chainDisarmGuard()
}

// --------------------------------------------------------------------------
// Pack 44
//
// 1. The stop event is created with a security descriptor that lets an
//    ordinary elevated console signal it, so "awgchain.bat ks off" no longer
//    ends in "Access is denied" and a taskkill.
// 2. A guard that dies immediately after it was armed is counted. Three such
//    deaths in a row and the manager stops re-arming it: a kill switch that
//    cannot live is worse than no kill switch, because the endless
//    arm-and-die cycle tore the chain apart every five seconds. That was the
//    regression of patch 22, and it must never be able to repeat silently.
// --------------------------------------------------------------------------

const chainGuardMaxDeaths = 3
const chainGuardQuickDeath = 30 * time.Second

var (
	chainGuardDeaths  int
	chainGuardLastArm time.Time
)

func chainStopEventSecurity() *windows.SecurityAttributes {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;0x001F0003;;;SY)(A;;0x001F0003;;;BA)(A;;0x00100002;;;WD)")
	if err != nil {
		return nil
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa
}

func chainGuardGaveUp() bool {
	chainGuardLock.Lock()
	defer chainGuardLock.Unlock()
	return chainGuardDeaths >= chainGuardMaxDeaths
}

func chainGuardNoteArm() {
	chainGuardLock.Lock()
	chainGuardLastArm = time.Now()
	chainGuardLock.Unlock()
}

// chainGuardNoteDeath tells a crash from a normal stop: a guard that lived
// for a while was stopped on purpose, one that died at once is broken.
func chainGuardNoteDeath() (int, bool) {
	chainGuardLock.Lock()
	defer chainGuardLock.Unlock()
	if time.Since(chainGuardLastArm) < chainGuardQuickDeath {
		chainGuardDeaths++
		return chainGuardDeaths, true
	}
	chainGuardDeaths = 0
	return 0, false
}

func chainGuardResetDeaths() {
	chainGuardLock.Lock()
	chainGuardDeaths = 0
	chainGuardLock.Unlock()
}
