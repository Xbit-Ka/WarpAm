//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 87: the hold on a tunnel service that is being cleared away.
 *
 * The complaint was "after a reboot with the chain and a proxy the icon
 * looks busy and nothing comes up, as if it were stopping a tunnel that is
 * not there". The log of 28 September shows the three services of the last
 * session being removed at start, and the trackers of those same services
 * finishing three and a half seconds later.
 *
 * That is the whole of it. Windows does not remove a service while a handle
 * to it is open, it only marks it for deletion, and the handle that keeps
 * ours alive is our own: the watcher of the service database wakes on the
 * deletion, trackExistingTunnels opens the service again and a fresh
 * tracker holds it for another four seconds. Meanwhile InstallTunnel waits
 * for the old service to disappear in a loop with no end at all, so Start
 * never returns, the window keeps its "connecting" look, and the tracker
 * reports Stopping for a tunnel that no longer exists.
 *
 * This file is the small piece of shared bookkeeping the other patches of
 * the pack need: a name that is being cleared away right now is held here,
 * the tracker leaves held names alone, and the wait for a deletion has a
 * limit and an answer instead of running for ever.
 */

package manager

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// chainSweepWait is the longest anyone waits for a service that is marked
// for deletion to really go. Fifteen seconds is far beyond what a handle
// of ours needs to close and still short enough to answer the user.
const chainSweepWait = 15 * time.Second

// chainSweepStep is the gap between two questions to the service manager.
const chainSweepStep = time.Second / 4

var (
	chainSweepMu    sync.Mutex
	chainSweepNames = make(map[string]bool)
)

// ChainSweepHold says that the service of this tunnel is being removed
// right now, so nothing else should open it.
func ChainSweepHold(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) == 0 {
		return
	}
	chainSweepMu.Lock()
	chainSweepNames[name] = true
	chainSweepMu.Unlock()
}

// ChainSweepRelease lifts the hold.
func ChainSweepRelease(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) == 0 {
		return
	}
	chainSweepMu.Lock()
	delete(chainSweepNames, name)
	chainSweepMu.Unlock()
}

// ChainSweepHeld answers whether this tunnel is being cleared away.
func ChainSweepHeld(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) == 0 {
		return false
	}
	chainSweepMu.Lock()
	held := chainSweepNames[name]
	chainSweepMu.Unlock()
	return held
}

// ChainSweepGone waits until the service can no longer be opened, which is
// the only honest sign that Windows has really let go of it. It answers
// false when the wait runs out, and the caller says so out loud instead of
// waiting for ever.
//
// A service manager that answers "marked for delete" to OpenService gives
// no service back, so the handle is only closed when there is one. The old
// loop closed it either way and would have taken the manager down with a
// nil pointer the first time Windows chose that answer.
func ChainSweepGone(m *mgr.Mgr, serviceName string) bool {
	deadline := time.Now().Add(chainSweepWait)
	for {
		service, err := m.OpenService(serviceName)
		if err != nil {
			return true
		}
		service.Close()
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(chainSweepStep)
	}
}
