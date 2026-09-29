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

// chainDupeAddress finds the first interface address these two configs have
// in common.
func chainDupeAddress(a, b *conf.Config) string {
	for i := range a.Interface.Addresses {
		mine := strings.ToLower(a.Interface.Addresses[i].String())
		for j := range b.Interface.Addresses {
			if mine == strings.ToLower(b.Interface.Addresses[j].String()) {
				return a.Interface.Addresses[i].String()
			}
		}
	}
	return ""
}

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
		if address := chainDupeAddress(c, other); len(address) != 0 {
			return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u043f\u043e\u0434\u043d\u044f\u0442\u044c: \u0435\u0433\u043e \u0430\u0434\u0440\u0435\u0441 %s \u0441\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442 \u0441 \u0430\u0434\u0440\u0435\u0441\u043e\u043c \u0443\u0436\u0435 \u043f\u043e\u0434\u043d\u044f\u0442\u043e\u0433\u043e \u0442\u0443\u043d\u043d\u0435\u043b\u044f %s. %s",
				c.Name, address, name, chainDupeHint(name))
		}
		if len(key) != 0 && key == chainDupeKey(other) {
			return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u043f\u043e\u0434\u043d\u044f\u0442\u044c: \u0443 \u043d\u0435\u0433\u043e \u0442\u043e\u0442 \u0436\u0435 \u0437\u0430\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447, \u0447\u0442\u043e \u0438 \u0443 \u0443\u0436\u0435 \u043f\u043e\u0434\u043d\u044f\u0442\u043e\u0433\u043e \u0442\u0443\u043d\u043d\u0435\u043b\u044f %s. \u041e\u0434\u043d\u0430 \u0443\u0447\u0451\u0442\u043d\u0430\u044f \u0437\u0430\u043f\u0438\u0441\u044c \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u0432\u0435\u0441\u0442\u0438 \u0434\u0432\u0430 \u0442\u0443\u043d\u043d\u0435\u043b\u044f \u0441\u0440\u0430\u0437\u0443. %s",
				c.Name, name, chainDupeHint(name))
		}
	}
	return nil
}
