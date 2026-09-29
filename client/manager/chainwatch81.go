//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 81: the watch of a chain nobody wants any more lets go.
 *
 * From the log of 25 September:
 *
 *   05:39:47  the user raises the chain warpam, the leaf never handshakes
 *   05:40:10  the user raises the plain tunnel WARPv2_84, which honestly
 *             stops warpam-hop1 on its way up
 *   05:40:33  the 45 second wait for the leaf gives up and starts a watch
 *             on a chain that is already gone
 *   05:40:38  the watch repairs it, raises warpam-hop1 again and throws
 *             WARPv2_84 off the machine
 *   05:41:04  the same again
 *   05:41:31  and again, until the user switched everything off by hand
 *
 * The watch was right to exist and wrong about what it was protecting. A
 * deliberate stop already tells it to stand down (chainBeforeStop), but
 * here the chain was pushed aside while the wait for its handshake was
 * still running, so the watch was born into a world that had moved on.
 *
 * Two questions are asked from now on, both before the watch starts and on
 * every round of it:
 *
 *   1. is this chain still in the set of tunnels that are meant to be up
 *      (the set of pack 80);
 *   2. is some other ordinary tunnel up right now, which can only mean it
 *      pushed this chain out of the way.
 *
 * A tunnel that carries nothing but its proxy is not "some other ordinary
 * tunnel": those are meant to live beside a chain, and pack 80 made sure
 * they neither stop it nor are stopped by it.
 */

package manager

import (
	"fmt"
	"strings"
)

// chainWatchGiveUp says why the watch of this chain should stand down, or
// an empty string while the chain is still the thing the user wants.
func chainWatchGiveUp(leaf string) string {
	leaf = strings.TrimSpace(leaf)
	if len(leaf) == 0 {
		return ""
	}
	branch := chainOwnBranch(leaf)

	// Question 2 first, because it is the one that bit us: an ordinary
	// tunnel outside this chain cannot be up at the same time as the
	// chain, so if one is, the chain has already lost.
	for _, name := range chainWatchOtherTunnelsUp(branch) {
		return fmt.Sprintf("the tunnel \u2018%s\u2019 is up instead", name)
	}

	// Question 1: the set of pack 80. An empty set means nothing has been
	// remembered yet, and then the watch is left alone: a missing note
	// must never be read as "the user does not want this".
	wanted := ChainUpTunnels()
	if len(wanted) == 0 {
		return ""
	}
	for _, name := range wanted {
		if strings.EqualFold(name, leaf) || chainInOwnBranch(branch, name) {
			return ""
		}
	}
	return "it is no longer in the set of tunnels that are meant to be up"
}

// chainWatchOtherTunnelsUp lists the ordinary tunnels that are up and do not
// belong to this chain. Proxy only tunnels are left out on purpose.
func chainWatchOtherTunnelsUp(branch []string) []string {
	out := make([]string, 0, 2)
	trackedTunnelsLock.Lock()
	names := make([]string, 0, len(trackedTunnels))
	for name, state := range trackedTunnels {
		if state == TunnelStarted {
			names = append(names, name)
		}
	}
	trackedTunnelsLock.Unlock()

	for _, name := range names {
		if len(strings.TrimSpace(name)) == 0 || chainInOwnBranch(branch, name) {
			continue
		}
		if chainHopByName(name) {
			// A hop of some other chain is handled through its own leaf,
			// and a hidden hop is nothing the user picked.
			continue
		}
		if chainLeafIsSeparate(name) {
			continue
		}
		if _, ok := chainAdapterLUID(name); !ok {
			continue
		}
		out = append(out, name)
	}
	return out
}
