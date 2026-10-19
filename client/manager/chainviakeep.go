//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 102: two tunnels where one goes through the other are kept
 * together.
 *
 * Start stops the tunnels whose routes overlap with the one being raised.
 * Two tunnels that both carry the machine always overlap, and with the box
 * "through a tunnel" in every mode that would stop exactly the tunnel the
 * new one has to go through, or the one that goes through the new one. The
 * walk below follows the box and the PinEndpointVia of chain hops alike.
 */

package manager

import "strings"

// chainViaUnder lists the tunnels underneath name: the one it goes through,
// the one under that, and so on.
func chainViaUnder(name string) []string {
	name = strings.TrimSpace(name)
	list := make([]string, 0, 4)
	at := name
	for i := 0; i < chainMaxDepth*2 && len(at) != 0; i++ {
		next := chainViaParentName(at)
		if len(next) == 0 {
			next = chainParentName(at)
		}
		if len(next) == 0 || strings.EqualFold(next, name) {
			break
		}
		list = append(list, next)
		at = next
	}
	return list
}

// chainViaKin answers whether one of the two tunnels goes through the other,
// directly or further down.
func chainViaKin(a, b string) bool {
	for _, n := range chainViaUnder(a) {
		if strings.EqualFold(n, strings.TrimSpace(b)) {
			return true
		}
	}
	for _, n := range chainViaUnder(b) {
		if strings.EqualFold(n, strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}
