//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 67: one owner for the boot.
 *
 * Before this pack the machine woke up with two different bosses:
 *
 *   1. every AwgChainTunnel$<name> service was created with StartAutomatic,
 *      so Windows itself raised whatever tunnel ran last, no matter what the
 *      Settings tab said;
 *   2. chainAutoRaiseOnStart was started from IPCServerListen, that is once
 *      per window, five seconds after the window appeared, and it did a
 *      single Start with no waiting for the physical adapter.
 *
 * From pack 67 on there is exactly one owner: the manager service. It runs
 * chainBootOnce from Execute, before any window exists, and it obeys the
 * settings book:
 *
 *   raise nothing   -> nothing is raised, whatever is already running is
 *                      adopted (watch + kill switch), nothing else happens
 *   raise last      -> the tunnel written in LastTunnel
 *   raise selected  -> the tunnel written in RaiseTunnel
 *
 * The raise itself is staged instead of a single try:
 *
 *   stage 1   5 tries, 5 seconds apart, 15 seconds for the handshake
 *   stage 2   5 tries, 15 seconds apart, 25 seconds for the handshake
 *   stage 3   forever, 60 seconds apart, the normal 45 seconds
 *
 * and before the first try the physical adapter the root hop pins itself to
 * has to be really up, because at boot time it usually is not.
 */

package manager

import (
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainRaiseStage is one row of the table above.
type chainRaiseStage struct {
	tries     int // 0 means "for as long as it takes"
	gap       time.Duration
	handshake time.Duration
}

var chainRaiseStages = []chainRaiseStage{
	{tries: 5, gap: 5 * time.Second, handshake: 15 * time.Second},
	{tries: 5, gap: 15 * time.Second, handshake: 25 * time.Second},
	{tries: 0, gap: 60 * time.Second, handshake: chainHopUpTimeout},
}

const (
	// How long the boot raise waits for the physical adapter of the root hop.
	chainBaseAdapterWait = 90 * time.Second
	chainBaseAdapterPoll = 500 * time.Millisecond
	// While the boot raise is running a hop gets fewer inner tries, because
	// the outer loop is the one that keeps trying.
	chainBootHopStartTries = 2
)

var (
	// chainBootSvc is the manager instance the boot path works through. It
	// carries no elevated token, which is fine: Start, Stop and State do not
	// ask for one, and nothing here creates or deletes a config.
	chainBootSvc = &ManagerService{}

	chainBootRun     sync.Once
	chainBootMu      sync.Mutex
	chainBootRaising bool
	chainBootAdopted sync.Map
)

// chainBootOnce is called from the manager service. Calling it twice is
// harmless: the second call returns at once.
func chainBootOnce() {
	chainBootRun.Do(func() {
		chainMigrateLockEngine()
		// Pack 71: the paranoid lock goes up first, before the migrations,
		// before the sweep and before anything is raised. It used to be
		// put up after the autostart question and only when a tunnel was
		// chosen for the start, so the mode did nothing at all on a
		// machine set to "raise nothing".
		chainBootSvc.chainParanoidArmOnStart()
		chainMigrateTunnelStartTypes()
		// Pack 69 (J5): before anything is raised, the services left
		// behind by the last shutdown are cleared away.
		chainSweepLeftoverTunnels()
		chainBootSvc.chainApplyStartPolicy()
	})
}

// chainBootRaisingNow reports whether the boot raise is in progress.
func chainBootRaisingNow() bool {
	chainBootMu.Lock()
	defer chainBootMu.Unlock()
	return chainBootRaising
}

func chainBootSetRaising(on bool) {
	chainBootMu.Lock()
	chainBootRaising = on
	chainBootMu.Unlock()
}

// --------------------------------------------------------------------------
// The start policy
// --------------------------------------------------------------------------

// chainBootTarget reads the target out of the settings book and checks that
// the config is really there. A target that has been deleted falls back to
// the tunnel that ran last, which is better than a silent "nothing happens".
func chainBootTarget(global ChainGlobalSettings) string {
	target := strings.TrimSpace(global.Target())
	if len(target) == 0 {
		return ""
	}
	if _, err := conf.LoadFromName(target); err == nil {
		return target
	}
	fallback := strings.TrimSpace(global.LastTunnel)
	if !global.LastTunnelUp {
		// Pack 69 (J1): the tunnel that ran last was switched off by
		// hand, so it is not a fallback either.
		fallback = ""
	}
	if len(fallback) == 0 || strings.EqualFold(fallback, target) {
		log.Printf("[WarpAm] The tunnel %s is chosen for the start but its config is gone, so nothing is raised", target)
		return ""
	}
	if _, err := conf.LoadFromName(fallback); err != nil {
		log.Printf("[WarpAm] Neither %s nor %s can be read, so nothing is raised at start", target, fallback)
		return ""
	}
	log.Printf("[WarpAm] The tunnel %s is chosen for the start but its config is gone, falling back to %s", target, fallback)
	return fallback
}

// chainApplyStartPolicy is the whole of what happens at boot.
func (s *ManagerService) chainApplyStartPolicy() {
	// Pack 69 (J2): the box that says the program must not start with
	// Windows was read in exactly one place, the Exit path, and the
	// start-up raise never asked about it. The service can be running
	// after a reboot even with the box cleared, for instance because
	// the machine was switched off while it was running and Windows
	// brought the session back. It then raised a tunnel behind the
	// user's back. Nothing is raised now, and nothing is locked; what
	// is already running is still adopted, so a chain never runs
	// unwatched.
	if !chainAutoStartWanted() {
		log.Printf("[WarpAm] Nothing is raised at start: the program is set not to start with Windows")
		s.chainAdoptWhateverRuns()
		return
	}

	// Pack 71 put the paranoid lock up here as well as in chainBootOnce,
	// which ran the whole thing twice and wrote every line of it to the
	// log twice. chainBootOnce does it before this policy starts, so the
	// branches that raise nothing are covered too.

	global := ChainGlobal()
	mode := global.Mode()
	if mode == ChainRaiseNone {
		log.Printf("[WarpAm] Nothing is raised at start: the setting says so")
		s.chainAdoptWhateverRuns()
		return
	}

	target := chainBootTarget(global)
	if len(target) == 0 {
		s.chainAdoptWhateverRuns()
		return
	}

	if state, err := s.State(target); err == nil && state == TunnelStarted {
		// Pack 69 (J4): "the service is started" is not "the chain is
		// up". A leaf whose hops are gone reports TunnelStarted and
		// used to send the whole policy home.
		if err := s.chainChainReady(target); err == nil {
			log.Printf("[WarpAm] %s is already up, the start-up raise stands down", target)
			chainNoteBootTunnel(target)
			s.chainRaiseRemembered(target)
			return
		} else {
			log.Printf("[WarpAm] %s says it is started, but %v, so it is raised properly", target, err)
		}
	}

	log.Printf("[WarpAm] The start-up raise takes %s (%s mode)", target, mode)
	// Pack 72: the lock before the start was built when no target was
	// known yet. It is rebuilt here with the hops of the tunnel that is
	// about to be raised, otherwise the very first handshake dies in the
	// filters and the chain never comes up behind its own lock.
	if chainBootLockIsOn() {
		chainArmBootLock(target)
	}
	s.chainWaitForBaseAdapter(target, chainBaseAdapterWait)
	s.chainRaiseWithStages(target)
	s.chainRaiseRemembered(target)
}

// chainRaiseRemembered puts the rest of the machine back the way the user
// left it.
//
// Pack 80: several tunnels can be up at once, so the start-up raise cannot
// stop at one. The main tunnel is raised by the policy above, with all its
// stages and retries, because that is the one the user chose; the others
// are the tunnels that were up when the session ended, and they only carry
// their own proxies. Each of them is asked for once and given a second try,
// and a failure is written down and stepped over: one tunnel that cannot
// come up must not keep the others down.
func (s *ManagerService) chainRaiseRemembered(target string) {
	remembered := ChainUpTunnels()
	if len(remembered) == 0 {
		return
	}
	own := chainOwnBranch(target)
	for _, name := range remembered {
		if strings.EqualFold(name, target) || chainInOwnBranch(own, name) {
			continue
		}
		if !chainAutoStartWanted() {
			log.Printf("[WarpAm] The rest of the start-up raise stands down: the program is set not to start with Windows")
			return
		}
		if state, err := s.State(name); err == nil && state == TunnelStarted {
			chainNoteBootTunnel(name)
			continue
		}
		log.Printf("[WarpAm] The start-up raise also takes %s: it was up when the session ended", name)
		chainBootSetRaising(true)
		err := s.Start(name)
		if err != nil {
			time.Sleep(chainRememberedRetryGap)
			err = s.Start(name)
		}
		chainBootSetRaising(false)
		if err != nil {
			log.Printf("[WarpAm] %s did not come up at start: %v", name, err)
			continue
		}
		log.Printf("[WarpAm] %s is raised at start", name)
	}
}

// chainRememberedRetryGap is how long the second try of a remembered
// tunnel waits. Long enough for a hop that is still settling, short enough
// not to hold up the tunnels behind it.
const chainRememberedRetryGap = 5 * time.Second

// chainRaiseWithStages walks the table of stages until the chain is up.
func (s *ManagerService) chainRaiseWithStages(target string) {
	attempt := 0
	for stageIndex := range chainRaiseStages {
		stage := chainRaiseStages[stageIndex]
		for try := 1; stage.tries == 0 || try <= stage.tries; try++ {
			// The user may have changed the setting while we were waiting.
			if current := ChainGlobal(); current.Mode() == ChainRaiseNone || !strings.EqualFold(strings.TrimSpace(current.Target()), target) {
				log.Printf("[WarpAm] The start-up raise stands down: the setting changed")
				return
			}
			// Pack 70: the last stage never ends (tries == 0), so the box
			// "do not start with Windows" has to be read again here. It was
			// read once, before the first try, and a user who cleared it
			// during a long retry loop still got a tunnel raised hours later.
			if !chainAutoStartWanted() {
				log.Printf("[WarpAm] The start-up raise stands down: the program is set not to start with Windows")
				return
			}
			// Pack 69 (J4): the same question as above, asked about the
			// whole chain and not about one service.
			if state, err := s.State(target); err == nil && state == TunnelStarted && s.chainChainReady(target) == nil {
				log.Printf("[WarpAm] %s is already up, the start-up raise stands down", target)
				return
			}

			attempt++
			started := time.Now()
			err := s.chainRaiseOnce(target, stage.handshake)
			if err == nil {
				log.Printf("[WarpAm] The tunnel %s is raised at start (attempt %d)", target, attempt)
				return
			}
			log.Printf("[WarpAm] The tunnel %s did not come up at start (attempt %d, waited %v): %v", target, attempt, time.Since(started).Truncate(time.Second), err)

			// A half-raised chain has to be cleared away, otherwise the next
			// try is refused with "please allow the tunnel to finish
			// activating".
			s.Stop(target)
			s.chainWaitStopped(target)

			chainSleepOrNetworkChange(stage.gap)
		}
	}
}

// chainRaiseOnce is a single attempt: raise the chain and wait for the leaf
// to handshake within the time this stage allows.
func (s *ManagerService) chainRaiseOnce(target string, handshake time.Duration) error {
	chainBootSetRaising(true)
	defer chainBootSetRaising(false)

	// Pack 68 (I5): the start-up raise is deliberate too, so it clears a
	// lock that was lifted by hand in the previous session.
	chainLockSuppress(false)

	if err := s.Start(target); err != nil {
		return err
	}
	if err := s.chainWaitForHopTimeout(target, handshake); err != nil {
		return err
	}

	// Pack 69 (J4): the leaf has handshaken, but a leaf can handshake
	// on its own, straight out to its peer, with the hops underneath it
	// missing. That is not the chain the user asked for, and in
	// paranoid mode it is a leak, so the attempt fails and the next
	// stage tries again from a clean state.
	if err := s.chainChainReady(target); err != nil {
		return err
	}

	// Pack 68 (F3a): the chain is up and this attempt is the one that
	// got it there, so the kill switch and the watch are set up here,
	// once, instead of by a second waiter started inside Start.
	s.chainArmGuard(target)
	s.chainStartWatch(target)
	return nil
}

// chainSleepOrNetworkChange waits out the gap, but wakes early when the
// routing table changes, which is what happens the moment a cable is plugged
// in or Wi-Fi associates.
func chainSleepOrNetworkChange(gap time.Duration) {
	if gap <= 0 {
		return
	}
	woken := make(chan struct{}, 1)
	callback, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		select {
		case woken <- struct{}{}:
		default:
		}
	})
	if err != nil {
		time.Sleep(gap)
		return
	}
	defer callback.Unregister()

	select {
	case <-time.After(gap):
	case <-woken:
		// Give the new route a moment to settle before trying again.
		time.Sleep(2 * time.Second)
		log.Printf("[WarpAm] The network changed, so the next start-up try comes early")
	}
}

// --------------------------------------------------------------------------
// Waiting for the adapter the chain rides on
// --------------------------------------------------------------------------

// chainBaseAdapterOf is the name of the physical adapter the root hop pins
// its endpoint to, for example "Ethernet".
func chainBaseAdapterOf(target string) string {
	hops := chainHopOrder(target)
	if len(hops) == 0 {
		return ""
	}
	c, err := conf.LoadFromName(hops[0])
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Interface.PinEndpointVia)
}

// chainAdapterIsUp answers whether an adapter of this name exists and is up.
func chainAdapterIsUp(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagDefault)
	if err != nil {
		return false
	}
	for _, adapter := range adapters {
		if !strings.EqualFold(adapter.FriendlyName(), strings.TrimSpace(name)) {
			continue
		}
		return adapter.OperStatus == winipcfg.IfOperStatusUp
	}
	return false
}

// chainWaitForBaseAdapter holds the boot raise back until the network card is
// really up. At boot time the manager service is running long before that,
// and a Start against a dead card is a guaranteed failure.
func (s *ManagerService) chainWaitForBaseAdapter(target string, timeout time.Duration) {
	adapter := chainBaseAdapterOf(target)
	if adapter == "" {
		return
	}
	if chainAdapterIsUp(adapter) {
		return
	}
	log.Printf("[WarpAm] Waiting for the %s adapter before raising %s", adapter, target)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(chainBaseAdapterPoll)
		if chainAdapterIsUp(adapter) {
			log.Printf("[WarpAm] The %s adapter is up, raising %s now", adapter, target)
			return
		}
	}
	log.Printf("[WarpAm] The %s adapter is still not up after %v, trying to raise %s anyway", adapter, timeout, target)
}

// --------------------------------------------------------------------------
// Adopting what is already running
// --------------------------------------------------------------------------

// chainNoteBootTunnel gives a chain that is already running its watch and its
// kill switch. Windows may have started the tunnel service itself, or an
// earlier manager may have left it up; either way nobody is looking after it
// until this runs. Calling it twice for one tunnel does nothing.
func chainNoteBootTunnel(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	if conf.ChainIsHiddenHopName(name) || !chainHopByName(name) {
		return
	}
	if len(chainChildNames(name)) != 0 {
		// Not the leaf of the chain: whoever rides on this one is adopted.
		return
	}
	if state, err := chainBootSvc.State(name); err != nil || state != TunnelStarted {
		return
	}

	chainGuardLock.Lock()
	busy := chainGuardArmedBy != "" || chainWatchCancel != nil
	chainGuardLock.Unlock()
	if busy {
		return
	}
	if _, seen := chainBootAdopted.LoadOrStore(strings.ToLower(name), true); seen {
		return
	}

	log.Printf("[WarpAm] %s is already running, so the watch and the kill switch are taken over", name)
	// Pack 70: adopting is not a wish. ChainNoteLastTunnel also sets the
	// "is up" flag, so a tunnel the user had switched off by hand came back
	// at the next boot merely because the manager restarted while it was
	// still running.
	chainNoteAdoptedTunnel(name)
	go chainBootSvc.chainArmWhenReady(name)
}

// chainAdoptWhateverRuns looks for a running chain when nothing is to be
// raised. Without this a chain that survived a manager restart would run with
// no kill switch and no watch, which is the "the lock says it is off" bug.
func (s *ManagerService) chainAdoptWhateverRuns() {
	names, err := conf.ListConfigNames()
	if err != nil {
		return
	}
	for _, name := range names {
		chainNoteBootTunnel(name)
	}
}

// --------------------------------------------------------------------------
// Who owns the boot: the services themselves
// --------------------------------------------------------------------------

// chainMigrateTunnelStartTypes puts every tunnel service back on manual.
// Machines updated from an earlier pack still carry StartAutomatic from the
// day the tunnel was installed, and that is exactly what raised a tunnel at
// boot behind the settings' back.
func chainMigrateTunnelStartTypes() {
	names, err := conf.ListConfigNames()
	if err != nil {
		return
	}
	m, err := serviceManager()
	if err != nil {
		return
	}
	for _, name := range names {
		serviceName, err := services.ServiceNameOfTunnel(name)
		if err != nil {
			continue
		}
		service, err := m.OpenService(serviceName)
		if err != nil {
			continue
		}
		config, err := service.Config()
		if err != nil {
			service.Close()
			continue
		}
		if config.StartType != mgr.StartAutomatic {
			service.Close()
			continue
		}
		config.StartType = mgr.StartManual
		err = service.UpdateConfig(config)
		if err != nil {
			log.Printf("[WarpAm] The service of %s could not be moved off automatic start (%v)", name, err)
		} else {
			log.Printf("[WarpAm] The service of %s no longer starts on its own: the manager decides what is raised", name)
		}
		service.Close()
	}
}

// --------------------------------------------------------------------------
// Leaving the program
// --------------------------------------------------------------------------

// chainLockedLeaf is the chain the lock is holding, if any.
func chainLockedLeaf() string {
	chainLockMu.Lock()
	leaf := chainLockLeaf
	chainLockMu.Unlock()
	if leaf != "" {
		return leaf
	}
	chainGuardLock.Lock()
	leaf = chainGuardArmedBy
	chainGuardLock.Unlock()
	return leaf
}

// chainQuitMayStopTunnels answers whether Exit is allowed to take the tunnels
// down with it. In strict and paranoid mode it is not: those modes promise
// that traffic never leaves the tunnel, and the chain is kept running.
func chainQuitMayStopTunnels() bool {
	leaf := chainLockedLeaf()
	if leaf == "" {
		return true
	}
	if !chainLockSurvivesStop(leaf) {
		return true
	}
	log.Printf("[WarpAm] The window is closing but %s is in %s mode, so the chain is left running", leaf, ChainLockModeOf(leaf))
	return false
}

// chainQuitLiftLock is the lock lift asked for on the way out of the program.
// Unlike the button in the window it obeys the mode.
func chainQuitLiftLock() {
	leaf := chainLockedLeaf()
	if leaf == "" {
		chainDisarmLockRespectingMode()
		return
	}
	if chainLockSurvivesStop(leaf) {
		log.Printf("[WarpAm] The window is closing but the kill switch stays closed: %s is in %s mode", leaf, ChainLockModeOf(leaf))
		return
	}
	ChainLiftLockNow()
	log.Printf("[WarpAm] The kill switch is lifted because the program is closing")
}

// chainKeepManagerInstalled answers whether Exit may delete the manager
// service. It may not when the program is meant to start with Windows: a
// deleted service cannot start with anything.
func chainKeepManagerInstalled() bool {
	if !chainAutoStartWanted() {
		return false
	}
	log.Printf("[WarpAm] The manager service stays installed because the program is set to start with Windows")
	return true
}
