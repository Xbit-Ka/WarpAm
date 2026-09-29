package ui

import (
	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// Pack 67: the builder asks for the two configs one at a time, first the
// outer link (WARP), then the inner one (Amnezia). That order is the law:
// nothing is swapped behind the user's back any more.
//
// The scoring of pack 54 is still here, but only as a warning. If the file
// chosen as WARP looks less like WARP than the other one, the user is told
// so and may either go on or cancel.
func chainConfirmRoles(owner walk.Form, warp *conf.Config, inner *conf.Config) bool {
	if warp == nil || inner == nil {
		return false
	}
	if conf.ChainWarpScore(warp) >= conf.ChainWarpScore(inner) {
		return true
	}

	text := "Похоже, звенья перепутаны.\r\n\r\n" +
		"Внешним (WARP) выбран: " + warp.Name + "\r\n" +
		"    " + conf.ChainRoleHint(warp) + "\r\n\r\n" +
		"Внутренним (Amnezia) выбран: " + inner.Name + "\r\n" +
		"    " + conf.ChainRoleHint(inner) + "\r\n\r\n" +
		"Внешнее звено это то, что смотрит в интернет напрямую.\r\n" +
		"Собрать цепочку в выбранном порядке?"

	return walk.DlgCmdYes == walk.MsgBox(owner, chainTitle, text,
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning)
}
