//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the tunnel service takes its MTU from the book.
 *
 * Until now three places counted the MTU, each its own way: the config
 * file for a tunnel that goes straight out, ChainInnerMTU with the fixed
 * 1420 of the outer hop for the inner hop of a chain, and chainViaCountMTU
 * for a tunnel that goes through another one. They stay as they are, and
 * this runs after them: when the book of the MTU tab (core/chainmtu) knows
 * an own maximum in the network the machine is in, the stack is counted
 * from it.
 *
 *   - a tunnel that goes straight out, and the hidden hop of a chain, run
 *     with their own maximum; the number of the config file is the answer
 *     only while nothing has been checked;
 *   - a tunnel above another one runs with the smaller of its own maximum
 *     and "the tunnel below minus 60 or 80 minus S4".
 *
 * Nothing is written into the config file.
 */

package tunnel

import (
	"log"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/chainmtu"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainMTUFromBook sets the MTU of config in memory from the book.
func chainMTUFromBook(config *conf.Config) {
	if config == nil {
		return
	}
	name := strings.TrimSpace(config.Name)
	here := chainmtu.Find()
	if len(here.Key) == 0 {
		log.Printf("[WarpAm] MTU: the network of this machine is not known, %s keeps MTU %d", name, config.Interface.MTU)
		return
	}
	mtu, steps := chainmtu.Effective(here, name)
	if mtu == 0 || len(steps) == 0 {
		return
	}
	self := steps[len(steps)-1]
	stacked := len(steps) > 1
	known := false
	for _, s := range steps {
		if s.Own > 0 {
			known = true
		}
	}
	if !known {
		// Nothing checked in this network yet: the counting of the packs
		// before stays in force.
		log.Printf("[WarpAm] MTU: nothing is checked for %s in the network %s yet, MTU %d stays", name, here.Text(), config.Interface.MTU)
		return
	}
	if !stacked && self.Own == 0 {
		return
	}
	was := config.Interface.MTU
	config.Interface.MTU = uint16(mtu)
	log.Printf("[WarpAm] MTU: %s runs with %d (was %d) in the network %s: %s", name, mtu, was, here.Text(), chainmtu.Line(steps))
	if mtu < chainmtu.IPv6Floor {
		log.Printf("[WarpAm] MTU: %d is below 1280, IPv6 inside %s will not work", mtu, name)
	}
}
