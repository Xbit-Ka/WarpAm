/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 101: a tunnel that others go through is not switched off
 * behind their back.
 *
 * Since pack 101 a tunnel set to go "through another tunnel" never goes
 * direct: without its parent it simply stops working. So before the parent
 * is switched off by hand, the window asks:
 *
 *   Yes -> the tunnels that go through it are stopped first, then it
 *   No  -> nothing is switched off
 *
 * Since pack 108 the chain with the hidden hop is asked about too, the
 * same way: it used to switch off what rides on it in silence.
 *
 * The parent is never lowered by the program itself; this window is the
 * only way it goes down, and only on a click.
 */

package ui

import (
	"fmt"
	"log"
	"strings"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainViaIsChain reports whether the tunnel is the hidden hop of a chain
// or the tunnel that rides on one.
func chainViaIsChain(t *manager.Tunnel) bool {
	if conf.ChainIsHiddenHopName(t.Name) {
		return true
	}
	c, err := t.StoredConfig()
	if err != nil {
		return false
	}
	return conf.ChainIsHiddenHopName(strings.TrimSpace(c.Interface.PinEndpointVia))
}

// chainViaJoin writes "a", "a и b" or "a, b и c".
func chainViaJoin(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " и " + names[len(names)-1]
}

// chainViaStopAsk is called on the window thread before a tunnel that is up
// is toggled. It returns the tunnels to stop first, and false when the user
// said No and nothing must be switched off.
func chainViaStopAsk(owner walk.Form, t *manager.Tunnel) ([]manager.Tunnel, bool) {
	if t == nil {
		return nil, true
	}
	state, err := t.State()
	if err == nil && state == manager.TunnelStopped {
		// WarpAm pack 103: a raise is asked about the rule of one tunnel
		// carrying the machine in a via stack.
		return nil, chainViaRaiseAsk(owner, t)
	}
	if err != nil || state != manager.TunnelStarted {
		return nil, true
	}
	all, err := manager.IPCClientTunnels()
	if err != nil {
		return nil, true
	}
	// WarpAm pack 107: the whole chain above is taken, not only the
	// tunnels that go through this one directly. In WARPv2_84, ru-central,
	// Elena, 100 switching off ru-central used to leave Elena and 100 up
	// with no way out. The farthest comes first, which is the stop order.
	var kids []manager.Tunnel
	var names []string
	for _, m := range manager.ChainViaRiders(t.Name, chainViaMembersUI("", nil)) {
		for i := range all {
			if strings.EqualFold(all[i].Name, m.Name) {
				kids = append(kids, all[i])
				names = append(names, all[i].Name)
				break
			}
		}
	}
	if len(kids) == 0 {
		return nil, true
	}
	// WarpAm pack 108: no silent case for the chain with the hidden hop any
	// more. Switching off warpam used to take 100 down without a word.
	verb, them := "работают", "с ними"
	if len(kids) == 1 {
		verb, them = "работает", "с ним"
	}
	text := fmt.Sprintf("Через %s %s %s.\r\nВыключить их тоже?\r\n\r\nДа: выключить %s вместе %s.\r\nНет: ничего не выключать.",
		t.Name, verb, chainViaJoin(names), t.Name, them)
	log.Printf("[%s] Via: asked whether to switch off %s too", t.Name, strings.Join(names, ", "))
	if walk.DlgCmdYes != walk.MsgBox(owner, chainTitle, text, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		log.Printf("[%s] Via: the answer is No, nothing is switched off", t.Name)
		return nil, false
	}
	log.Printf("[%s] Via: the answer is Yes, %s go down first, the farthest first", t.Name, strings.Join(names, ", "))
	return kids, true
}

// chainViaStopKids stops the tunnels returned by chainViaStopAsk. It runs
// off the window thread, just before the toggle of their parent.
func chainViaStopKids(kids []manager.Tunnel) {
	for i := range kids {
		if err := kids[i].Stop(); err != nil {
			log.Printf("[%s] Via: could not stop it before its parent: %v", kids[i].Name, err)
			continue
		}
		// WarpAm pack 107: the next one goes only when this one is really
		// down, so the order from the top down holds.
		if err := kids[i].WaitForStop(); err != nil {
			log.Printf("[%s] Via: could not wait for it to stop: %v", kids[i].Name, err)
		}
		// WarpAm pack 113: and only when Windows has taken its adapter
		// away. On 8.10 the adapters were still there a minute later.
		manager.ChainWaitAdapterGone(kids[i].Name)
	}
}
