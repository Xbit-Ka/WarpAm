//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 69 (J4, J5): what "the chain is up" means, and what is left
 * over from the last shutdown.
 *
 * J4. Until this pack the start-up raise called a chain done as soon as the
 * leaf service reported TunnelStarted. That is a statement about a Windows
 * service, not about a chain: after the reboot in the log the leaf was
 * "started" while the hop underneath it did not even have a service, so the
 * policy stood down with "warpam is already up" over a chain that carried
 * nothing and a leaf that was talking to its peer directly. The question is
 * asked properly here: every hop running, every hop with a fresh handshake.
 * chainTrouble already answers exactly that for the watch.
 *
 * J5. A shutdown that catches a tunnel while it is still running leaves its
 * service object behind in the service manager: the log shows "could not stop
 * warpam: A system shutdown is in progress". After the reboot the tracker
 * picks that leftover up and the manager treats it as a tunnel of this
 * session. Together with J3 that was the whole of the "the tunnels take very
 * long to come up" complaint. Such a leftover is now removed before the
 * raise, and only a service that really is running is left alone, because
 * that one is adopted with its watch and its kill switch.
 */

package manager

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
)

// chainChainReady answers nil when every hop of the chain that ends at leaf
// is running and has handshaken recently enough.
func (s *ManagerService) chainChainReady(leaf string) error {
	if reason := s.chainTrouble(leaf); reason != "" {
		return fmt.Errorf("the chain ending at \u2018%s\u2019 is not really up: %s", leaf, reason)
	}
	return nil
}

// chainSweepLeftoverTunnels removes tunnel services that outlived the last
// session. It runs once, before the start-up raise.
func chainSweepLeftoverTunnels() {
	names, err := conf.ListConfigNames()
	if err != nil {
		return
	}
	m, err := serviceManager()
	if err != nil {
		return
	}
	// Pack 88: every name is held for the whole sweep instead of one at a
	// time. The hold keeps the watcher of the service database from opening
	// a service again, and while one name was held the watches of the other
	// tunnels were started and finished between the deletions, each of them
	// holding a handle of its own for up to four seconds. The log of the
	// reboot of 28 September shows the price of that: three leftover
	// services took twelve seconds to go. Held together they go in about
	// one, and the watches are picked up again at the end, once.
	for _, name := range names {
		ChainSweepHold(name)
	}
	defer func() {
		for _, name := range names {
			ChainSweepRelease(name)
		}
		trackExistingTunnels()
	}()
	for _, name := range names {
		serviceName, err := services.ServiceNameOfTunnel(name)
		if err != nil {
			continue
		}
		service, err := m.OpenService(serviceName)
		if err != nil {
			// No service at all, which is the normal state after a clean
			// shutdown. Nothing to clean up.
			continue
		}
		status, queryErr := service.Query()
		// Pack 70: a service that is still stopping is not a leftover. It
		// used to be uninstalled mid-stop, which is how a tunnel could be
		// left half torn down with its adapter still in place.
		for wait := 0; queryErr == nil && status.State == svc.StopPending && wait < 20; wait++ {
			time.Sleep(time.Second / 4)
			status, queryErr = service.Query()
		}
		service.Close()
		if queryErr == nil && (status.State == svc.Running || status.State == svc.StartPending) {
			log.Printf("[AwgChain] %s is running from before the manager started, so it is left alone and taken over", name)
			continue
		}
		if queryErr == nil && status.State == svc.StopPending {
			log.Printf("[AwgChain] %s is still stopping, so it is left alone instead of being uninstalled under its own feet", name)
			continue
		}
		state := "unreadable"
		if queryErr == nil {
			state = fmt.Sprintf("%d", status.State)
		}
		// Pack 87: the name is held while the service goes. Every deletion
		// wakes the watcher of the service database, the watcher opens the
		// service again, and an open handle is what keeps a deleted service
		// alive in Windows. That circle is what left the manager waiting for
		// its own handle after a reboot, with the icon busy and nothing up.
		err = UninstallTunnel(name)
		if err != nil {
			log.Printf("[AwgChain] The service %s was left over from the last session (state %s) and could not be removed: %v", serviceName, state, err)
			continue
		}
		gone := ChainSweepGone(m, serviceName)
		if !gone {
			log.Printf("[AwgChain] The service %s was left over from the last session (state %s) and is still marked for deletion after %v, so something outside this program is holding it", serviceName, state, chainSweepWait)
			continue
		}
		log.Printf("[AwgChain] The service %s was left over from the last session (state %s) and is removed, so nothing takes it for a tunnel that is up", serviceName, state)
	}
}
