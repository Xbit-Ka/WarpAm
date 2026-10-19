//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 81: two tunnels of one account never run at the same time.
 *
 * In the log of 25 September a tunnel called 100p and the leaf of the chain
 * called warpam were the same account on the same server: one private key,
 * one interface address, only the road to the server was different. Windows
 * refused to give the address to a second adapter, so 100p died half a
 * second after it was raised:
 *
 *   Unable to set interface addresses, routes, dns, and/or interface
 *   settings: The object already exists.
 *
 * and later the chain could not handshake either, because the server keeps
 * one session per key and the key was taken.
 *
 * Nothing in the window said any of this. The tunnel was shown as active
 * while it was already gone.
 *
 * So the question is asked before anything is raised, exactly like the
 * question about the port of the proxy in pack 80. If the tunnel that is
 * being raised has the same interface address, or the same private key, as
 * a tunnel that is up and is going to stay up, the raise is refused and the
 * refusal says what to do instead: a proxy on that account does not need a
 * second tunnel, it needs the proxy switched on in the settings of the
 * tunnel that is already up.
 *
 * Tunnels that this raise is about to stop are not in the way and are not
 * looked at. Hops of the chain being raised are not looked at either: they
 * are meant to run together and they carry keys of their own.
 */

package manager

import (
	"fmt"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainDupeNameIn answers whether this name is in the list, whatever the
// case of the letters.
func chainDupeNameIn(names []string, name string) bool {
	for _, one := range names {
		if strings.EqualFold(one, name) {
			return true
		}
	}
	return false
}

// chainDupeKey is the private key of a config written as text, or an empty
// string when the config carries no key at all.
func chainDupeKey(c *conf.Config) string {
	var empty conf.Key
	if c.Interface.PrivateKey == empty {
		return ""
	}
	return c.Interface.PrivateKey.String()
}

// Pack 101: the same interface address no longer stops a tunnel at all.
// Pack 100 swapped IPv4 and kept the refusal for IPv6; now the service
// swaps IPv6 too (core/tunnel/chainaddrswap.go), so only the check of the
// key below is left.

// chainDupeHint is the second half of every refusal below. It is the whole
// point of the message: the user wanted a proxy on that account and does
// not need a second tunnel for it.
// Pack 82: the message is shown in a window, so it is written in Russian.
// The log stays English.
func chainDupeHint(other string) string {
	return fmt.Sprintf("\u0415\u0441\u043b\u0438 \u0432\u0430\u043c \u043d\u0443\u0436\u0435\u043d \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0430 \u044d\u0442\u043e\u0439 \u0443\u0447\u0451\u0442\u043d\u043e\u0439 \u0437\u0430\u043f\u0438\u0441\u0438, \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435 \u0435\u0433\u043e \u0432 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430\u0445 \u0442\u0443\u043d\u043d\u0435\u043b\u044f %s.", other)
}

// ChainDuplicateConflict answers whether this config can be raised while the
// listed tunnels are up. An empty answer means it can.
//
// running is every tunnel the tracker knows about, stopping is the ones this
// raise is already going to take down, and own is the branch of the chain
// being raised.
func ChainDuplicateConflict(c *conf.Config, running, stopping, own []string) error {
	if c == nil {
		return nil
	}
	if clash := chainDupeConflicts(c, running, stopping, own); len(clash) != 0 {
		return chainDupeText(c.Name, clash[0])
	}
	return nil
}

// chainDupeConflicts lists the running tunnels with the same private key
// as c. WarpAm pack 112: the window of the raise asks about all of them
// (chainkeyclash.go), so the list is no longer cut at the first one.
func chainDupeConflicts(c *conf.Config, running, stopping, own []string) []string {
	if c == nil {
		return nil
	}
	var out []string
	key := chainDupeKey(c)
	for _, name := range running {
		if len(name) == 0 || strings.EqualFold(name, c.Name) {
			continue
		}
		if chainDupeNameIn(stopping, name) || chainInOwnBranch(own, name) {
			continue
		}
		other, err := conf.LoadFromName(name)
		if err != nil {
			continue
		}
		if len(key) != 0 && key == chainDupeKey(other) {
			out = append(out, name)
		}
	}
	return out
}

// chainDupeText is the refusal for a raise without a window.
//
// WarpAm pack 112: the advice about the proxy fits only two single
// tunnels. When the key belongs to the first step of a double tunnel, the
// proxy in the settings of that tunnel goes through its second step, which
// is another account, so the advice did not help at all.
func chainDupeText(raising, other string) error {
	shownRaising, shownOther := chainShownName(raising), chainShownName(other)
	switch {
	case conf.ChainIsHiddenHopName(raising):
		return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c: \u0435\u0433\u043e \u043f\u0435\u0440\u0432\u044b\u0439 \u0448\u0430\u0433 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442 \u0442\u043e\u0442 \u0436\u0435 \u0437\u0430\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447, \u0447\u0442\u043e \u0438 \u0440\u0430\u0431\u043e\u0442\u0430\u044e\u0449\u0438\u0439 %s. \u0412\u044b\u043a\u043b\u044e\u0447\u0438\u0442\u0435 %s, \u0447\u0442\u043e\u0431\u044b \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c %s.",
			shownRaising, shownOther, shownOther, shownRaising)
	case conf.ChainIsHiddenHopName(other):
		return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c: \u0443 \u043d\u0435\u0433\u043e \u0442\u043e\u0442 \u0436\u0435 \u0437\u0430\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447, \u0447\u0442\u043e \u0438 \u0443 \u043f\u0435\u0440\u0432\u043e\u0433\u043e \u0448\u0430\u0433\u0430 \u0434\u0432\u043e\u0439\u043d\u043e\u0433\u043e \u0442\u0443\u043d\u043d\u0435\u043b\u044f %s. \u041e\u0434\u043d\u0430 \u0443\u0447\u0451\u0442\u043d\u0430\u044f \u0437\u0430\u043f\u0438\u0441\u044c \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u0432\u0435\u0441\u0442\u0438 \u0434\u0432\u0430 \u0442\u0443\u043d\u043d\u0435\u043b\u044f \u0441\u0440\u0430\u0437\u0443. \u0412\u044b\u043a\u043b\u044e\u0447\u0438\u0442\u0435 %s, \u0447\u0442\u043e\u0431\u044b \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c %s.",
			shownRaising, shownOther, shownOther, shownRaising)
	}
	// WarpAm pack 111: the window names the tunnels the user
	// knows. A hidden hop is named by its pair, warpam instead of
	// warpam-hop1, which is not in the list at all.
	return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u043f\u043e\u0434\u043d\u044f\u0442\u044c: \u0443 \u043d\u0435\u0433\u043e \u0442\u043e\u0442 \u0436\u0435 \u0437\u0430\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447, \u0447\u0442\u043e \u0438 \u0443 \u0443\u0436\u0435 \u043f\u043e\u0434\u043d\u044f\u0442\u043e\u0433\u043e \u0442\u0443\u043d\u043d\u0435\u043b\u044f %s. \u041e\u0434\u043d\u0430 \u0443\u0447\u0451\u0442\u043d\u0430\u044f \u0437\u0430\u043f\u0438\u0441\u044c \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u0432\u0435\u0441\u0442\u0438 \u0434\u0432\u0430 \u0442\u0443\u043d\u043d\u0435\u043b\u044f \u0441\u0440\u0430\u0437\u0443. %s",
		shownRaising, shownOther, chainDupeHint(shownOther))
}
