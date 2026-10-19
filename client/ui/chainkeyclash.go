//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the same key asks "yes or no" before a raise.
 *
 * The manager lists the running tunnels with the same private key as a
 * tunnel of the raise (chainkeyclash.go in the manager). The window says
 * which one it is, the first step of a double tunnel included, what goes
 * down with it and, when only the proxy is wanted, the second proxy that
 * goes through the first step:
 *
 *   Yes -> the manager is told, and the raise switches those tunnels off
 *   No  -> nothing is raised
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
	chainKeyClashOtherStep   = "У %s тот же закрытый ключ, что у первого шага двойного туннеля %s. Вместе они работать не могут."
	chainKeyClashOwnStep     = "У первого шага двойного туннеля %s тот же закрытый ключ, что у %s. Вместе они работать не могут."
	chainKeyClashPlain       = "У %s тот же закрытый ключ, что у %s. Вместе они работать не могут."
	chainKeyClashRiders      = "Вместе с %s выключится то, что через него идёт: %s."
	chainKeyClashProxy2      = "Второй прокси %s тоже выключится."
	chainKeyClashProxy2Hint  = "Если нужен только выход через WARP, включите у %s галочку «второй прокси через первое звено»."
	chainKeyClashTail        = "Да: выключить %s и включить %s.\r\nНет: ничего не включать."
	chainKeyClashAcceptError = "Не удалось передать ответ службе: "
)

// chainKeyClashAsk is asked first before a raise. False means nothing is
// raised. When the manager cannot be asked, the raise goes on and the
// manager refuses it itself if it has to.
func chainKeyClashAsk(owner walk.Form, t *manager.Tunnel) bool {
	clashes, err := manager.IPCClientChainKeyClashes(t.Name)
	if err != nil {
		log.Printf("[%s] Start: could not ask the manager about tunnels with the same key: %v", t.Name, err)
		return true
	}
	if len(clashes) == 0 {
		return true
	}
	var lines, others []string
	var hints []string
	for _, c := range clashes {
		switch {
		case c.OtherFirstStep:
			lines = append(lines, fmt.Sprintf(chainKeyClashOtherStep, c.Raising, c.Other))
		case c.RaisingFirstStep:
			lines = append(lines, fmt.Sprintf(chainKeyClashOwnStep, c.Raising, c.Other))
		default:
			lines = append(lines, fmt.Sprintf(chainKeyClashPlain, c.Raising, c.Other))
		}
		if len(c.Riders) != 0 {
			lines = append(lines, fmt.Sprintf(chainKeyClashRiders, c.Other, chainViaJoin(c.Riders)))
		}
		if c.OtherProxy2 {
			lines = append(lines, fmt.Sprintf(chainKeyClashProxy2, c.Other))
		}
		if c.OtherFirstStep && c.RaisingSeparate {
			hints = append(hints, fmt.Sprintf(chainKeyClashProxy2Hint, c.Other))
		}
		others = append(others, c.Other)
	}
	text := strings.Join(lines, "\r\n")
	if len(hints) != 0 {
		text += "\r\n\r\n" + strings.Join(hints, "\r\n")
	}
	text += "\r\n\r\n" + fmt.Sprintf(chainKeyClashTail, chainViaJoin(others), t.Name)
	log.Printf("[%s] Start: asked whether to switch off %s, the same private key", t.Name, strings.Join(others, ", "))
	if walk.DlgCmdYes != walk.MsgBox(owner, chainTitle, text, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		log.Printf("[%s] Start: the answer is No, nothing is raised", t.Name)
		return false
	}
	if err := manager.IPCClientChainKeyClashAccept(t.Name, others); err != nil {
		showErrorCustom(owner, chainTitle, chainKeyClashAcceptError+err.Error())
		return false
	}
	log.Printf("[%s] Start: the answer is Yes, %s goes down", t.Name, strings.Join(others, ", "))
	return true
}
