/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 62: the check boxes of the tunnel editor.
 *
 * Pack 59 rev 2 made the three boxes independent, but on screen the two lower
 * ones sat in the middle of the dialog: a walk VBoxLayout centres a child
 * that is narrower than the column, and the column is as wide as the longest
 * box (the kill switch). So the kill switch looked left aligned and the other
 * two did not.
 *
 * Pack 62 puts every box in its own one line strip together with a spacer, so
 * the box is pinned to the left edge of that strip and all three start at the
 * same pixel.
 *
 * Nothing is renamed. Same constants, same fields, same methods as pack 57.
 *
 * The names are the ones editdialog.go calls:
 *   chainChecksBox(dlg, parent) walk.Container
 *   chainExtraChecks(dlg) error
 *   (dlg *EditDialog) chainLoadChecks()
 *   (dlg *EditDialog) chainSaveChecks(name string)
 *   (dlg *EditDialog) onBlockUntunneledTrafficCBCheckedChanged()
 *   (dlg *EditDialog) onBlockUntunneledTrafficStateChanged(state int)
 */

package ui

import (
	"strings"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

// chainCheckRow is the strip that holds the kill switch box. editdialog.go
// creates that box itself, right after chainChecksBox returns, so the spacer
// that pins it to the left can only be added afterwards, from
// chainExtraChecks. One editor dialog is open at a time, so one variable is
// enough.
var chainCheckRow *walk.Composite

// Pack 79: the three proxy controls that pack 74 put here are gone. The
// proxy of a tunnel is set on the "Proxy" tab, which follows the selected
// tunnel, and nothing about the proxy is written from this dialog any more.

// chainCheckStrip makes a one line strip with no margins.
func chainCheckStrip(parent walk.Container) (*walk.Composite, error) {
	row, err := walk.NewComposite(parent)
	if err != nil {
		return nil, err
	}
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{0, 0, 0, 0})
	layout.SetSpacing(0)
	if err = row.SetLayout(layout); err != nil {
		return nil, err
	}
	return row, nil
}

// chainChecksBox makes the column that holds the check boxes and returns the
// strip the first box goes into.
func chainChecksBox(dlg *EditDialog, parent walk.Container) walk.Container {
	chainCheckRow = nil

	col, err := walk.NewComposite(parent)
	if err != nil {
		return parent
	}
	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{0, 0, 0, 0})
	layout.SetSpacing(2)
	if err = col.SetLayout(layout); err != nil {
		return parent
	}
	dlg.chainChecks = col

	row, err := chainCheckStrip(col)
	if err != nil {
		return col
	}
	chainCheckRow = row
	return row
}

// chainExtraChecks pins the first box to the left and adds the IPv6 and the
// local network box under it, each in its own strip.
func chainExtraChecks(dlg *EditDialog) error {
	col := dlg.chainChecks
	if col == nil {
		return nil
	}

	if chainCheckRow != nil {
		if _, err := walk.NewHSpacer(chainCheckRow); err != nil {
			return err
		}
	}

	ipv6Row, err := chainCheckStrip(col)
	if err != nil {
		return err
	}
	if dlg.chainIPv6CB, err = walk.NewCheckBox(ipv6Row); err != nil {
		return err
	}
	dlg.chainIPv6CB.SetText(chainCheckIPv6Label)
	dlg.chainIPv6CB.SetToolTipText(chainCheckIPv6Hint)
	if _, err = walk.NewHSpacer(ipv6Row); err != nil {
		return err
	}

	lanRow, err := chainCheckStrip(col)
	if err != nil {
		return err
	}
	if dlg.chainLANCB, err = walk.NewCheckBox(lanRow); err != nil {
		return err
	}
	dlg.chainLANCB.SetText(chainCheckLANLabel)
	dlg.chainLANCB.SetToolTipText(chainCheckLANHint)
	if _, err = walk.NewHSpacer(lanRow); err != nil {
		return err
	}

	dlg.chainLoadChecks()
	return nil
}

// chainLoadChecks fills the boxes from the manager. A tunnel nobody has
// configured yet gets all three boxes on.
func (dlg *EditDialog) chainLoadChecks() {
	settings := manager.ChainTunnelSettings{KillSwitch: true, BlockIPv6: true, AllowLAN: true}
	name := dlg.config.Name
	if name != "" {
		if saved, err := manager.IPCClientChainSettings(name); err == nil {
			settings = saved
		}
	}
	if dlg.blockUntunneledTrafficCB != nil {
		dlg.blockUntunneledTrafficCB.SetChecked(settings.KillSwitch)
	}
	if dlg.chainIPv6CB != nil {
		dlg.chainIPv6CB.SetChecked(settings.BlockIPv6)
	}
	if dlg.chainLANCB != nil {
		dlg.chainLANCB.SetChecked(settings.AllowLAN)
	}
	dlg.chainFollowChainOnly()
}

// chainSaveChecks is called from Save, once the name of the tunnel is known.
// The lock mode of the tunnel is left as it was written by an older build; the
// program setting decides anyway.
func (dlg *EditDialog) chainSaveChecks(name string) {
	if dlg.blockUntunneledTrafficCB == nil || dlg.chainIPv6CB == nil || dlg.chainLANCB == nil {
		return
	}
	// Pack 79: the dialog writes its own three boxes and touches nothing
	// else. Everything about the proxy belongs to the "Proxy" tab now, so
	// the saved settings are read first and only the boxes of this dialog
	// are put over them. Building a fresh struct here would wipe the
	// proxy of the tunnel every time the editor was saved.
	settings := manager.ChainTunnelSettings{}
	if old, err := manager.IPCClientChainSettings(name); err == nil {
		settings = old
	}

	settings.BlockIPv6 = dlg.chainIPv6CB.Checked()

	// Pack 79, the rule "grey means not saved": the kill switch and the
	// local network hole only exist for a chain, and for a plain tunnel
	// both boxes are grey. What is grey is not written down, so a plain
	// tunnel gets a clean "no" instead of a value nobody could see or
	// change.
	if chainTunnelIsChain(dlg) {
		settings.KillSwitch = dlg.blockUntunneledTrafficCB.Checked()
		settings.AllowLAN = dlg.chainLANCB.Checked()
	} else {
		settings.KillSwitch = false
		settings.AllowLAN = false
	}

	err := manager.IPCClientChainSettingsSave(name, settings)
	if err != nil {
		showErrorCustom(dlg, chainTitle, chainCheckSaveError+err.Error())
	}
}

// onBlockUntunneledTrafficCBCheckedChanged has taken the name of the upstream
// handler, which used to rewrite AllowedIPs behind the user's back. The boxes
// are written when Save is clicked, so there is nothing to do here.
func (dlg *EditDialog) onBlockUntunneledTrafficCBCheckedChanged() {
}

// onBlockUntunneledTrafficStateChanged is what the editor calls when
// AllowedIPs change. The box no longer follows AllowedIPs.
func (dlg *EditDialog) onBlockUntunneledTrafficStateChanged(state int) {
}

// chainTunnelIsChain answers whether the tunnel in the editor belongs to a
// chain. The manager recognises a hop by PinEndpointVia (chainmanager.go:29
// isChainHop) and this is the same test on the config being edited.
func chainTunnelIsChain(dlg *EditDialog) bool {
	return strings.TrimSpace(dlg.config.Interface.PinEndpointVia) != ""
}

// chainFollowChainOnly greys out the boxes that only a chain can honour.
//
// The kill switch lives in chainArmLockInProc, which needs two hops, and the
// local network hole is cut into the rules of that very kill switch. Neither
// has any meaning for a single tunnel, so on a plain tunnel both boxes are
// disabled and their tooltip says so. The IPv6 box keeps working for every
// tunnel: pack 64 gave it its own entry point in manager\chainplain.go.
func (dlg *EditDialog) chainFollowChainOnly() {
	chain := chainTunnelIsChain(dlg)

	if dlg.blockUntunneledTrafficCB != nil {
		dlg.blockUntunneledTrafficCB.SetEnabled(chain)
		if chain {
			dlg.blockUntunneledTrafficCB.SetToolTipText(chainCheckLockHint)
		} else {
			dlg.blockUntunneledTrafficCB.SetToolTipText(chainCheckChainOnlyHint)
		}
	}

	if dlg.chainLANCB != nil {
		dlg.chainLANCB.SetEnabled(chain)
		if chain {
			dlg.chainLANCB.SetToolTipText(chainCheckLANHint)
		} else {
			dlg.chainLANCB.SetToolTipText(chainCheckChainOnlyHint)
		}
	}
}