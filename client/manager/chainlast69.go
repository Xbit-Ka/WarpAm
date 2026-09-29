//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 69 (J1): switching a tunnel off is remembered.
 *
 * The "raise the last tunnel" mode read one field, Global.LastTunnel, and
 * that field was only ever written when a tunnel went up. Nothing wrote it
 * down when a tunnel was switched off, so the mode had no way of telling
 * "this is what I used last" from "this is what I want running". Turning the
 * tunnel off by hand and rebooting therefore brought it straight back, which
 * is exactly what a user who has just switched it off does not want.
 *
 * There is one new field, Global.LastTunnelUp, and it is written in two
 * places only: here, when a stop comes from the user, and in
 * ChainNoteLastTunnel, when a raise has worked. Nothing else may touch it,
 * which is why ChainGlobalSave copies it back from the stored book.
 *
 * A stop of any hop of the chain counts, not only a stop of the leaf: the
 * hops go down together, and the tunnel the user names in the window is not
 * necessarily the one they clicked.
 */

package manager

import (
	"log"
	"strings"
)

// chainNoteAdoptedTunnel remembers a tunnel the manager found already
// running when it started.
//
// Pack 70: adoption used to go through ChainNoteLastTunnel, which also sets
// LastTunnelUp. That turned "I found this running" into "the user wants this
// running", and a tunnel switched off by hand came back after a manager
// restart. The name is still remembered, but a cleared "is up" flag on this
// very tunnel is left cleared.
func chainNoteAdoptedTunnel(name string) {
	name = strings.TrimSpace(name)
	if len(name) == 0 || ChainIsHiddenHop(name) {
		return
	}

	chainSettingsMu.Lock()
	book := chainSettingsLoadLocked()
	last := strings.TrimSpace(book.Global.LastTunnel)
	stale := strings.EqualFold(last, name) && !book.Global.LastTunnelUp
	chainSettingsMu.Unlock()

	if stale {
		log.Printf("[AwgChain] %s is adopted, but it was switched off by hand, so the start-up raise still leaves it alone", name)
		return
	}
	ChainNoteLastTunnel(name)
}

// ChainNoteTunnelDown remembers that this tunnel was switched off on purpose,
// so that the start-up raise does not bring it back. A repair does not come
// through here: it goes through UninstallTunnel, and a chain that is being
// rebuilt is still meant to be up.
func ChainNoteTunnelDown(name string) {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return
	}

	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	book := chainSettingsLoadLocked()
	changed := false

	// Pack 80: the set of tunnels that are meant to be up loses this
	// name, and it also loses every tunnel that rides on it: a hop that
	// is switched off takes the tunnel above it down, and that tunnel is
	// not meant to come back at the next boot either.
	before := len(book.Global.UpTunnels)
	set := chainUpTunnelsWithout(book.Global.UpTunnels, name)
	for _, up := range append([]string(nil), set...) {
		if chainInOwnBranch(chainOwnBranch(up), name) {
			set = chainUpTunnelsWithout(set, up)
		}
	}
	if len(set) != before {
		book.Global.UpTunnels = set
		changed = true
	}

	last := strings.TrimSpace(book.Global.LastTunnel)
	switch {
	case !book.Global.LastTunnelUp:
		// Already marked as down; only the set above may have moved.
	case len(last) == 0:
	case !strings.EqualFold(last, name) && !chainInOwnBranch(chainOwnBranch(last), name):
		// Some other tunnel was switched off. The last one still stands.
	default:
		book.Global.LastTunnelUp = false
		changed = true
	}

	if !changed {
		return
	}
	if err := chainSettingsStoreLocked(); err != nil {
		log.Printf("[AwgChain] %s was switched off by hand, but that could not be remembered: %v", name, err)
		return
	}
	log.Printf("[AwgChain] %s was switched off by hand, so the start-up raise leaves it alone until it is raised again (still wanted up: %v)", name, book.Global.UpTunnels)
}
