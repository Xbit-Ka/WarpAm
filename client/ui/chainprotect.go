/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 55: the honest "leak protection" line in the Interface box.
 *
 * The manager is asked every two seconds in the background, so drawing the
 * line never waits on the pipe.
 */

package ui

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

var (
	chainProtectMu    sync.Mutex
	chainProtectInfo  manager.ChainStatusInfo
	chainProtectFresh bool
	chainProtectOnce  sync.Once
)

// Pack 81: the marks in the tray used to be drawn only when a tunnel
// changed state, so they were missing until something happened and they
// never followed the "Proxy" tab at all. There is no new timer for them:
// the poll above already asks the manager every two seconds, and now it
// says so when the answer is different from the last one. Whoever draws
// marks asks to be told.
var (
	chainMarksMu        sync.Mutex
	chainMarksSig       string
	chainMarksSigKnown  bool
	chainMarksListeners []func()
)

// chainMarksSubscribe asks to be called whenever the marks move. The call
// comes from the background poll, so a listener that touches the window has
// to hop onto the interface thread itself.
func chainMarksSubscribe(listener func()) {
	if listener == nil {
		return
	}
	chainMarksMu.Lock()
	chainMarksListeners = append(chainMarksListeners, listener)
	chainMarksMu.Unlock()
	chainProtectStart()
}

// chainMarksSignature writes every mark down as one line, so that two
// answers can be compared without looking at them.
func chainMarksSignature(info manager.ChainStatusInfo, fresh bool) string {
	if !fresh || info.ProxyModes == nil {
		return ""
	}
	parts := make([]string, 0, len(info.ProxyModes))
	for name, mode := range info.ProxyModes {
		parts = append(parts, name+"="+mode)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// chainMarksNotify tells the listeners, and only when there is something to
// tell. The very first answer always counts as news: before it there were
// no marks at all.
func chainMarksNotify(signature string) {
	chainMarksMu.Lock()
	quiet := chainMarksSigKnown && chainMarksSig == signature
	chainMarksSig = signature
	chainMarksSigKnown = true
	listeners := append([]func(){}, chainMarksListeners...)
	chainMarksMu.Unlock()
	if quiet {
		return
	}
	for _, listener := range listeners {
		listener()
	}
}

// ChainMarksChangedNow is what the window calls after it has saved the proxy
// settings of a tunnel: the manager knows already, the next poll would find
// it in two seconds, and the menu has no reason to wait that long.
func ChainMarksChangedNow() {
	chainMarksMu.Lock()
	chainMarksSigKnown = false
	listeners := append([]func(){}, chainMarksListeners...)
	chainMarksMu.Unlock()
	for _, listener := range listeners {
		listener()
	}
}

// chainProtectStart makes sure the background poll is running.
func chainProtectStart() {
	chainProtectOnce.Do(func() {
		go func() {
			for {
				info, err := manager.IPCClientChainStatus()
				chainProtectMu.Lock()
				chainProtectInfo = info
				chainProtectFresh = err == nil
				chainProtectMu.Unlock()
				// Pack 81: the answer has arrived, so anybody who draws
				// marks hears about it. This is the signal that was
				// missing: the first answer comes a couple of seconds
				// after the window is built, when no tunnel event is
				// coming any more.
				chainMarksNotify(chainMarksSignature(info, err == nil))
				time.Sleep(2 * time.Second)
			}
		}()
	})
}

// chainProtectionText says what the line should read for this tunnel.
func chainProtectionText(name string) (string, bool) {
	chainProtectStart()

	chainProtectMu.Lock()
	info := chainProtectInfo
	fresh := chainProtectFresh
	chainProtectMu.Unlock()

	if !fresh {
		return chainProtectNoSvc, true
	}
	if !info.LockOn {
		return chainProtectOff, true
	}
	if !info.InProc {
		return chainProtectGuard, true
	}
	if info.LockLeaf == "" || strings.EqualFold(info.LockLeaf, name) {
		return chainProtectOn, true
	}
	return fmt.Sprintf(chainProtectOther, info.LockLeaf), true
}

// chainProxyMark is the pometka that stands behind the name of a tunnel in
// the list and in the tray menu: " + прокси" for a tunnel that works as
// usual and carries a proxy as well, " прокси" for one that carries nothing
// but its proxy, and nothing at all for a tunnel without a proxy.
//
// Pack 80: the answer comes from the same background poll as the leak
// protection line, so a row is never drawn at the speed of the pipe. Until
// the first answer arrives there are simply no marks, and two seconds later
// they appear.
func chainProxyMark(name string) string {
	chainProtectStart()

	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) == 0 {
		return ""
	}

	chainProtectMu.Lock()
	modes := chainProtectInfo.ProxyModes
	fresh := chainProtectFresh
	chainProtectMu.Unlock()

	if !fresh || modes == nil {
		return ""
	}
	switch modes[name] {
	case manager.ChainProxyModeOnly:
		return chainMarkProxyOnly
	case manager.ChainProxyModeWith:
		return chainMarkProxyWith
	}
	return ""
}

// chainNameWithMark is the name of a tunnel as the user should see it.
func chainNameWithMark(name string) string {
	return name + chainProxyMark(name)
}

// chainApplyProtection draws the line. It is called from setTunnel, which the
// view already runs once a second.
func (cv *ConfView) chainApplyProtection(name string) {
	if cv == nil || cv.interfaze == nil || cv.interfaze.chainProtection == nil {
		return
	}
	text, show := chainProtectionText(name)
	if !show {
		cv.interfaze.chainProtection.hide()
		return
	}
	cv.interfaze.chainProtection.show(text)
}

// chainLiftLockBeforeQuit is called on the way out of the program. When the
// Settings tab asks for it, the manager is told to open the machine up again
// before the program disappears from the tray.
func chainLiftLockBeforeQuit() {
	global, err := manager.IPCClientChainGlobal()
	if err != nil {
		return
	}
	if !global.LiftLockOnQuit {
		return
	}
	// Pack 67: the manager decides. In strict and paranoid mode the lock is
	// meant to outlive a click on Exit, so this call may leave it closed.
	//
	// Pack 70: a failure of that call used to fall back to the emergency
	// lift, which opens the machine whatever the mode says. A pipe that
	// broke on the way out was enough to undo strict and paranoid mode.
	if err := manager.IPCClientChainLiftLockOnQuit(); err != nil {
		log.Printf("[AwgChain] The lock could not be lifted on the way out (%v); it is left as it stands, the mode decides", err)
	}
}
