//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 68, block I: the lock has one engine and it can be seen.
 *
 * Until this pack the lock was steered by two files nobody could find:
 *
 *   C:\ProgramData\AwgChain\no-inproc-lock   go back to awgchain-guard.exe
 *   C:\ProgramData\AwgChain\no-autoguard     do not arm anything
 *
 * Nothing in the window showed them, nothing reported them, and the second
 * one silently turned the kill switch off for good. The separate guard
 * process is gone in this pack, so there are two engines left and they live
 * in settings.json, next to everything else:
 *
 *   service  the manager installs the WFP filters itself (the default)
 *   off      no kill switch
 *
 * This file also holds the suppression flag. "Lift the lock now" used to be
 * undone by the watch five seconds later, because the watch arms the lock on
 * every healthy round. The lift is remembered here and held until a tunnel
 * is raised on purpose, which is the only thing that clears it. A repair
 * does not clear it, so a chain that is being rebuilt cannot bring back a
 * lock the user has just taken off.
 */

package manager

import (
	"log"
	"os"
	"path/filepath"
	"sync"
)

// chainLockEngineNow reads the engine straight out of the settings book. It
// deliberately does not go through ChainGlobal, which also asks the service
// manager about the autostart box: this is called on every round of the
// watch, five seconds apart.
func chainLockEngineNow() string {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()
	return chainSettingsLoadLocked().Global.Engine()
}

// chainLockEngineOff answered whether the settings said "no kill switch".
// Pack 70: the setting is gone and this is always false. The function is
// kept so the call sites that ask "may I arm?" keep reading the way they
// did, and so a future engine has one place to come back to.
func chainLockEngineOff() bool {
	return false
}

var (
	chainLockSuppressMu     sync.Mutex
	chainLockSuppressed     bool
	chainLockSuppressLoaded bool
)

// chainLockSuppressFile is where the "lifted by hand" flag lives between
// runs of the manager. Pack 70: the flag used to be a variable in memory
// only, so a service restart - an update, a crash, Exit and back - armed the
// lock again behind the user, who had lifted it on purpose.
func chainLockSuppressFile() string {
	return filepath.Join(chainStateDir(), "lock-lifted-by-hand")
}

// chainLockSuppress remembers, or forgets, a lock that was lifted by hand.
func chainLockSuppress(on bool) {
	chainLockSuppressMu.Lock()
	chainLockSuppressLoaded = true
	changed := chainLockSuppressed != on
	chainLockSuppressed = on
	chainLockSuppressMu.Unlock()

	// Pack 70: written down, so the flag outlives the process.
	path := chainLockSuppressFile()
	if on {
		if err := os.WriteFile(path, []byte("lifted by hand\r\n"), 0o600); err != nil {
			log.Printf("[AwgChain] The lifted lock could not be written down (%v), so a restart of the manager may arm it again", err)
		}
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("[AwgChain] %s could not be deleted (%v), so the lock may stay down longer than asked", path, err)
	}
	if !changed {
		return
	}
	if on {
		log.Printf("[AwgChain] The lock was lifted by hand, so it stays down until a tunnel is raised on purpose")
		return
	}
	chainLogForget("lock-suppressed")
	log.Printf("[AwgChain] A tunnel is being raised on purpose, so the lock may arm again")
}

// chainLockSuppressedNow answers whether the lock is being held down. Pack
// 70: the first question after a start reads the flag off the disk, so a
// lock lifted by hand before a restart stays lifted.
func chainLockSuppressedNow() bool {
	chainLockSuppressMu.Lock()
	defer chainLockSuppressMu.Unlock()
	if !chainLockSuppressLoaded {
		chainLockSuppressLoaded = true
		if _, err := os.Stat(chainLockSuppressFile()); err == nil {
			chainLockSuppressed = true
			log.Printf("[AwgChain] The lock was lifted by hand before the manager restarted, so it stays down until a tunnel is raised on purpose")
		}
	}
	return chainLockSuppressed
}

// chainMigrateLockEngine carries the two old opt-out files over into the
// settings file, once, and then deletes them.
//
// Pack 70: both files now end the same way. The off engine is gone, so a
// machine that used to opt out of the kill switch gets the service engine
// as well; the way to run without protection is to switch the lock mode,
// not to leave a file lying in the state directory.
func chainMigrateLockEngine() {
	dir := chainStateDir()
	noGuard := filepath.Join(dir, "no-autoguard")
	noInProc := filepath.Join(dir, "no-inproc-lock")

	found := make([]string, 0, 2)
	engine := ChainLockEngineService
	if _, err := os.Stat(noGuard); err == nil {
		found = append(found, noGuard)
	}
	if _, err := os.Stat(noInProc); err == nil {
		found = append(found, noInProc)
	}
	if len(found) == 0 {
		return
	}

	global := ChainGlobal()
	global.LockEngine = engine
	if err := ChainGlobalSave(global); err != nil {
		log.Printf("[AwgChain] The old lock files %v were found, but the settings could not be written (%v), so they are left where they are and no longer read", found, err)
		return
	}
	for _, path := range found {
		if err := os.Remove(path); err != nil {
			log.Printf("[AwgChain] %s could not be deleted (%v); it is no longer read either way", path, err)
		}
	}
	log.Printf("[AwgChain] The old lock files %v are carried over: the lock engine is now %q in the settings, where it can be seen and changed", found, engine)
}
