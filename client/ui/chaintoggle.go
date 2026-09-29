/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 84: one place where a refused toggle is explained.
 *
 * The very same three branches stood in three files: the row of the list
 * (tunnelspage.go), the button of the card (confview.go) and the line of
 * the tray menu (tray.go). Three copies meant three chances of a wording
 * that drifts apart, and every later pack had to remember all three. They
 * now call one function, and the branches live here only.
 */

package ui

import (
	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

// chainToggleFailed says why a tunnel refused to be switched. The state
// given is the one the tunnel was in before it was asked, which is what
// decides whether the failure was a raise or a drop. A state that is
// neither known nor settled says nothing at all, exactly as before: a
// tunnel that was already coming up or going down has an answer of its own
// on the way.
func chainToggleFailed(owner walk.Form, oldState manager.TunnelState, err error) {
	if err == nil {
		return
	}
	var title string
	switch oldState {
	case manager.TunnelUnknown:
		title = l18n.Sprintf("Failed to determine tunnel state")
	case manager.TunnelStopped:
		title = l18n.Sprintf("Failed to activate tunnel")
	case manager.TunnelStarted:
		title = l18n.Sprintf("Failed to deactivate tunnel")
	default:
		return
	}
	showErrorCustom(owner, title, err.Error())
}
