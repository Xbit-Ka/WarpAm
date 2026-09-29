//go:build windows

/* AwgChain pack 64: plain tunnels get their boxes too.
 *
 * Until now every box was read on the chain path only: chainInstallAndArm
 * leaves at once when the tunnel is not a hop, so a single Warpam or
 * WireGuard tunnel never had its "block IPv6" box looked at.
 *
 * The two functions here are the entry point for those tunnels. They are
 * deliberately small and touch nothing that the chain owns: a hop still goes
 * through chainArmLockInProc as before.
 */

package manager

import (
	"log"
	"strings"
)

// chainPlainTunnelUp applies the IPv6 box of a tunnel that is not part of a
// chain. chainApplyIPv6For raises the filter when the box is ticked and drops
// it when it is not.
func chainPlainTunnelUp(name string) {
	if chainHopByName(name) {
		return
	}
	settings := ChainSettingsFor(name)
	if settings.Proxy && settings.ProxySplit {
		// Pack 75: a tunnel that only carries the local proxy promised to
		// leave the machine as it was. A machine-wide IPv6 block is exactly
		// the kind of change it promised not to make, and the traffic of the
		// proxy never leaves through IPv6 anyway: its sockets are nailed to
		// the interface of the tunnel.
		return
	}
	if !settings.BlockIPv6 {
		return
	}
	log.Printf("[AwgChain] %s is a plain tunnel and asks for the IPv6 filter", name)
	chainApplyIPv6For(name)
}

// chainPlainTunnelStopped drops the IPv6 filter once the plain tunnel that
// asked for it is gone and no other tunnel is still running.
func chainPlainTunnelStopped(name string) {
	if chainHopByName(name) {
		return
	}
	if chainOtherTunnelRunning(name) {
		return
	}
	chainDropIPv6Block()
}

// chainOtherTunnelRunning answers whether a tunnel other than this one is up
// or on its way up.
func chainOtherTunnelRunning(name string) bool {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	for tunnel, state := range trackedTunnels {
		if strings.EqualFold(tunnel, name) {
			continue
		}
		if state == TunnelStarted || state == TunnelStarting || state == TunnelUnknown {
			return true
		}
	}
	return false
}