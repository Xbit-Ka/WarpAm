/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 66, fixed by pack 67: tunnels in a zip, the chain included.
 *
 * The export writes the tunnels the list shows. A chain leaf takes its hidden
 * hop along with it, plus a small manifest, so the pair and the three boxes
 * come back when the archive is imported. A zip without the manifest is
 * imported the old way, so archives from WireGuard and Amnezia keep working.
 *
 * Pack 67: the hidden hop is never in listview.model.tunnels, listview.go
 * filters it out, so the hop is taken from the full list of the manager.
 *
 * No new buttons and no new commands: tunnelspage.go calls these helpers from
 * the export and import actions it already has.
 */

package ui

import (
	"archive/zip"
	"encoding/json"
	"io"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainExportManifestName is the extra file the archive carries for a chain.
const chainExportManifestName = "awgchain-chain.json"

// chainExportSettings is the copy of the boxes of one chain leaf.
type chainExportSettings struct {
	KillSwitch bool
	BlockIPv6  bool
	AllowLAN   bool
	LockMode   string
}

// chainExportEntry ties a leaf to its hidden hop.
type chainExportEntry struct {
	Leaf     string
	Hop      string
	Settings chainExportSettings
}

// chainExportManifest is the whole awgchain-chain.json file.
type chainExportManifest struct {
	Version int
	Chains  []chainExportEntry
}

// chainExportKnown returns every tunnel the manager knows, hidden hops
// included. The list of the interface hides them, so it cannot be used here.
func chainExportKnown(visible []manager.Tunnel) map[string]manager.Tunnel {
	known := make(map[string]manager.Tunnel, len(visible)*2)
	for _, tunnel := range visible {
		known[strings.ToLower(strings.TrimSpace(tunnel.Name))] = tunnel
	}
	all, err := manager.IPCClientTunnels()
	if err != nil {
		return known
	}
	for _, tunnel := range all {
		known[strings.ToLower(strings.TrimSpace(tunnel.Name))] = tunnel
	}
	return known
}

// chainExportWrite puts every visible tunnel into the archive. A hidden hop is
// never written on its own, only next to the leaf that points at it.
func chainExportWrite(writer *zip.Writer, tunnels []manager.Tunnel) error {
	known := chainExportKnown(tunnels)

	written := make(map[string]bool, len(known))
	put := func(tunnel manager.Tunnel) error {
		key := strings.ToLower(strings.TrimSpace(tunnel.Name))
		if written[key] {
			return nil
		}
		cfg, err := tunnel.StoredConfig()
		if err != nil {
			return err
		}
		w, err := writer.Create(tunnel.Name + ".conf")
		if err != nil {
			return err
		}
		if _, err := w.Write(([]byte)(cfg.ToWgQuick())); err != nil {
			return err
		}
		written[key] = true
		return nil
	}

	manifest := chainExportManifest{Version: 1}

	for _, tunnel := range tunnels {
		if conf.ChainIsHiddenHopName(tunnel.Name) {
			continue
		}
		cfg, err := tunnel.StoredConfig()
		if err != nil {
			return err
		}
		if err := put(tunnel); err != nil {
			return err
		}

		// The leaf of a chain points at its hop with PinEndpointVia. If that
		// is empty the tunnel is a plain one and it travels alone.
		hopName := strings.TrimSpace(cfg.Interface.PinEndpointVia)
		if len(hopName) == 0 {
			hopName = conf.ChainHiddenHopName(tunnel.Name)
			if _, ok := known[strings.ToLower(hopName)]; !ok {
				continue
			}
		}
		hop, ok := known[strings.ToLower(hopName)]
		if !ok {
			continue
		}
		if err := put(hop); err != nil {
			return err
		}

		entry := chainExportEntry{Leaf: tunnel.Name, Hop: hop.Name}
		settings, err := manager.IPCClientChainSettings(tunnel.Name)
		if err == nil {
			entry.Settings = chainExportSettings{
				KillSwitch: settings.KillSwitch,
				BlockIPv6:  settings.BlockIPv6,
				AllowLAN:   settings.AllowLAN,
				LockMode:   settings.Mode(),
			}
		} else {
			entry.Settings = chainExportSettings{
				KillSwitch: true,
				BlockIPv6:  true,
				AllowLAN:   true,
				LockMode:   manager.ChainLockModeNormal,
			}
		}
		manifest.Chains = append(manifest.Chains, entry)
	}

	if len(manifest.Chains) == 0 {
		return nil
	}

	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	w, err := writer.Create(chainExportManifestName)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(body, byte('\n'))); err != nil {
		return err
	}
	return nil
}

// chainExportRead reads awgchain-chain.json out of an archive. A broken or
// foreign file is simply ignored, the tunnels are still imported.
func chainExportRead(f *zip.File) []chainExportEntry {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()

	body, err := io.ReadAll(rc)
	if err != nil {
		return nil
	}
	var manifest chainExportManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil
	}
	return manifest.Chains
}

// chainExportApply writes the boxes of the imported chains back through the
// manager, so the pair behaves the way it did on the machine it came from.
func chainExportApply(entries []chainExportEntry) {
	for _, entry := range entries {
		leaf := strings.TrimSpace(entry.Leaf)
		if len(leaf) == 0 {
			continue
		}
		mode := strings.TrimSpace(entry.Settings.LockMode)
		if len(mode) == 0 {
			mode = manager.ChainLockModeNormal
		}
		_ = manager.IPCClientChainSettingsSave(leaf, manager.ChainTunnelSettings{
			KillSwitch: entry.Settings.KillSwitch,
			BlockIPv6:  entry.Settings.BlockIPv6,
			AllowLAN:   entry.Settings.AllowLAN,
			LockMode:   mode,
		})
	}
}