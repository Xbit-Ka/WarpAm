//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 69 (J3): which tunnels belong to the chain being raised.
 *
 * Start looks for tunnels whose addresses or routes overlap with the one it
 * is about to raise and stops them. Two things made that loop turn on the
 * chain itself:
 *
 *   1. IntersectsWith is true for a config compared with itself, and the
 *      tunnel being raised is in the tracker as soon as its service exists;
 *   2. chainSiblings only knows the direct pin relation, hop by hop, so in a
 *      chain of three hops the leaf and the bottom hop are not siblings.
 *
 * The result was visible in the log: the bottom hop came up and handshook,
 * and two milliseconds later the stop of the leaf pulled it down again, over
 * and over, so the chain never assembled after a reboot. This file answers
 * the question the loop should have been asking: is this tunnel a part of my
 * own chain?
 */

package manager

import "strings"

// chainOwnBranch lists the tunnel itself, every hop underneath it and every
// tunnel riding directly on it.
func chainOwnBranch(name string) []string {
	branch := chainHopOrder(name)
	branch = append(branch, chainChildNames(name)...)
	return branch
}

// chainInOwnBranch reports whether name is one of the tunnels in branch.
func chainInOwnBranch(branch []string, name string) bool {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return false
	}
	for _, member := range branch {
		if strings.EqualFold(strings.TrimSpace(member), name) {
			return true
		}
	}
	return false
}
