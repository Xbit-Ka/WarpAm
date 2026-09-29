/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 53: the re-arm after a repair no longer opens a window.
 *
 * Pack 52 proved the re-arm works, but the log showed a two second hole:
 *
 *   03:28:15.737  Kill switch lifted, the machine is open again
 *   03:28:15.740  The kill switch waits: the warpam adapter is not here yet
 *   03:28:17.747  Kill switch armed inside the manager ...
 *
 * The lock was lifted the moment the repair reported success, while the top
 * adapter had not been created yet, so the first attempt was wasted and the
 * machine stayed open for a whole retry gap.
 *
 * The old filters point at dead LUIDs, but they still block everything that
 * is not the allowed application, so keeping them in place during the repair
 * is strictly safer than dropping them early. So now we wait for both fresh
 * adapters first, and only then swap the rule sets back to back. The gap is
 * whatever a single DisableChainFirewall plus EnableChainFirewall costs,
 * which is milliseconds.
 */

package manager

import (
	"log"
	"time"
)

const (
	chainRelockTries = 100
	chainRelockGap   = 200 * time.Millisecond
)

// chainRelockAdaptersReady answers true when both ends of the chain have a
// live adapter, which is the only moment a fresh lock can be installed.
func chainRelockAdaptersReady(leaf string) bool {
	hops := chainHopOrder(leaf)
	if len(hops) < 2 {
		return false
	}
	if _, ok := chainAdapterLUID(hops[0]); !ok {
		return false
	}
	if _, ok := chainAdapterLUID(hops[len(hops)-1]); !ok {
		return false
	}
	return true
}

// chainRearmLockAfterRepair reinstalls the kill switch on the adapters
// that exist after a repair. A chain that was never locked is armed by
// chainArmGuard as usual.
//
// Pack 68 (I5): a repair deliberately does not clear a lock the user
// lifted by hand, so a rebuild cannot bring the lock back behind them.
func (s *ManagerService) chainRearmLockAfterRepair(leaf string) {
	if chainLockEngineOff() || chainLockSuppressedNow() {
		return
	}
	if !chainLockIsOn() {
		return
	}

	// Hold the old rule set until the new adapters are really here.
	waited := 0
	for try := 1; try <= chainRelockTries; try++ {
		if chainRelockAdaptersReady(leaf) {
			break
		}
		if try == chainRelockTries {
			log.Printf("[AwgChain] Repair: the new adapters never showed up, so the kill switch keeps the old rule set and the machine stays closed")
			return
		}
		waited++
		time.Sleep(chainRelockGap)
	}
	if waited > 0 {
		log.Printf("[AwgChain] Repair: the new adapters are here after %d ms, the old rule set held the machine closed meanwhile", waited*int(chainRelockGap/time.Millisecond))
	}

	// Both adapters are up: swap the rule sets back to back. One dynamic WFP
	// session means the old set has to go first, so this is the only gap and
	// it is measured in milliseconds.
	started := time.Now()
	chainDisarmLockInProc()

	for try := 1; try <= chainRelockTries; try++ {
		if chainArmLockInProc(leaf) {
			log.Printf("[AwgChain] Repair: kill switch re-armed on the new interfaces on try %d, the machine was open for %d ms", try, int(time.Since(started).Milliseconds()))
			return
		}
		time.Sleep(chainRelockGap)
	}

	log.Printf("[AwgChain] Repair: the kill switch could NOT be re-armed after %d tries, so the machine is open right now. The watch keeps trying.", chainRelockTries)
}
