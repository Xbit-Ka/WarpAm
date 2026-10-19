//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 111: before a raise switches off a tunnel that others go
 * through, the window asks.
 *
 * A raise stops the running tunnels its addresses intersect with (the
 * loop of Start in the manager). When nothing rides on such a tunnel it
 * goes down in silence, as before. When tunnels go "through" it, they
 * would lose their way out, so the window asks first:
 *
 *   Yes -> the raise goes on as before, the manager stops the tunnel and
 *          what goes through it
 *   No  -> nothing is raised
 *
 * warpam with its hidden hop is one tunnel here: the manager names the
 * pair, never the hop. The list, the tray and the page of the tunnel all
 * come through chainViaStopAsk, so they ask the same way.
 */

package ui

import (
	"fmt"
	"log"
	"strings"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

const (
	chainStartAskHead = "Включение %s выключит %s."
	chainStartAskLine = "Через %s %s %s."
	chainStartAskTail = "Да: выключить %s и всё, что через %s идёт, и включить %s.\r\nНет: ничего не включать."
)

// chainStartVictimAsk is asked last before a raise. False means nothing is
// raised. When the manager cannot be asked, the raise goes on as before.
func chainStartVictimAsk(owner walk.Form, t *manager.Tunnel) bool {
	victims, err := manager.IPCClientChainStartVictims(t.Name)
	if err != nil {
		log.Printf("[%s] Start: could not ask the manager what this raise switches off: %v", t.Name, err)
		return true
	}
	if len(victims) == 0 {
		return true
	}
	names := make([]string, 0, len(victims))
	lines := make([]string, 0, len(victims))
	var riders []string
	for _, v := range victims {
		names = append(names, v.Name)
		verb := "работают"
		if len(v.Riders) == 1 {
			verb = "работает"
		}
		lines = append(lines, fmt.Sprintf(chainStartAskLine, v.Name, verb, chainViaJoin(v.Riders)))
		riders = append(riders, v.Riders...)
	}
	them := "него"
	if len(victims) > 1 {
		them = "них"
	}
	text := fmt.Sprintf(chainStartAskHead, t.Name, chainViaJoin(names)) + "\r\n" +
		strings.Join(lines, "\r\n") + "\r\n\r\n" +
		fmt.Sprintf(chainStartAskTail, chainViaJoin(names), them, t.Name)
	log.Printf("[%s] Start: asked whether to switch off %s, %s go through it", t.Name, strings.Join(names, ", "), strings.Join(riders, ", "))
	if walk.DlgCmdYes != walk.MsgBox(owner, chainTitle, text, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		log.Printf("[%s] Start: the answer is No, nothing is raised", t.Name)
		return false
	}
	log.Printf("[%s] Start: the answer is Yes, %s and what goes through it go down", t.Name, strings.Join(names, ", "))
	return true
}
