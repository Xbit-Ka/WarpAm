//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 74: the tunnel service asks whether it is a separate tunnel.
 *
 * A tunnel that only carries the traffic of the local proxy must not touch
 * the machine: no default route, no system DNS. The wish belongs to the
 * settings book of the manager, and the tunnel service runs in a process of
 * its own, so it reads the same file. Reading is all it does: the file is
 * written by the manager and by nobody else.
 *
 * The file is small and this is asked once per interface, so it is read
 * without a cache.
 */

package tunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainSplitMaxDepth is how far down a chain is followed. A chain of the
// program is two hops; eight is a wall against a loop in the files.
const chainSplitMaxDepth = 8

// chainSplitEntry is the part of a tunnel this file cares about. Pack 79:
// two fields, not one. "Only for the proxy" means nothing without a proxy,
// and a file written by pack 74 could hold exactly that combination: the
// box was greyed out in the window but kept its tick, so a tunnel was saved
// with Proxy off and ProxySplit on. The manager then read it as an ordinary
// tunnel while this file read it as a separate one, and the tunnel came up
// with no routes, no DNS and no proxy - up and useless.
type chainSplitEntry struct {
	Proxy      bool
	ProxySplit bool
}

// separate is the one question this file asks of a settings record.
func (e chainSplitEntry) separate() bool {
	return e.Proxy && e.ProxySplit
}

// chainSplitBook is the part of settings.json this file cares about.
type chainSplitBook struct {
	Tunnels map[string]chainSplitEntry
}

// chainSplitSettingsPath is where the manager keeps the settings book.
// AwgChain pack 86: the book lives in the data folder of the program, the
// same folder the manager writes it to. ProgramData is not consulted any
// more, so a tunnel service and the manager can never read two different
// files again.
func chainSplitSettingsPath() string {
	root, err := conf.ChainDataDirIfPresent()
	if err != nil || len(root) == 0 {
		return ""
	}
	return filepath.Join(root, "settings.json")
}

// ChainTunnelIsSeparate answers whether this tunnel carries the proxy only.
// A missing or unreadable file means no: the tunnel then behaves exactly as
// it did before this pack.
func ChainTunnelIsSeparate(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return false
	}
	raw, err := os.ReadFile(chainSplitSettingsPath())
	if err != nil {
		return false
	}
	var book chainSplitBook
	if err := json.Unmarshal(raw, &book); err != nil {
		return false
	}
	for tunnel, entry := range book.Tunnels {
		if strings.EqualFold(strings.TrimSpace(tunnel), name) {
			if entry.separate() {
				return true
			}
			break
		}
	}

	// Pack 77: the box is ticked on the end of a chain, but a chain is
	// carried by its hops, and a hop that thinks it is an ordinary tunnel
	// sets the system DNS and its own routes on the machine. The hops of
	// such a chain are separate too, and a hop learns it by walking down
	// from every tunnel that is marked: PinEndpointVia of a hop names the
	// adapter it rides on, which is its parent.
	for tunnel, entry := range book.Tunnels {
		if !entry.separate() {
			continue
		}
		hop := strings.TrimSpace(tunnel)
		for i := 0; i < chainSplitMaxDepth; i++ {
			c, err := conf.LoadFromName(hop)
			if err != nil {
				break
			}
			parent := strings.TrimSpace(c.Interface.PinEndpointVia)
			if len(parent) == 0 {
				break
			}
			if strings.EqualFold(parent, name) {
				return true
			}
			hop = parent
		}
	}
	return false
}
