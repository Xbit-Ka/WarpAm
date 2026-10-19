//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 103: the windows of the rule "one tunnel of a via stack
 * carries the machine". Asked before a raise.
 *
 * WarpAm pack 104: the warning of the proxy tab is gone, the check is made
 * only when a tunnel is switched on. Two more questions are asked then:
 * another stack that carries the machine is in the way, and the port of
 * the proxy is taken.
 */

package ui

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

// chainViaPortDepth bounds the walk down the via links of a raise.
const chainViaPortDepth = 8

const (
	chainViaClashAsk       = "%s и %s забирают весь интернет, а в одной связке так может только один туннель. Так работать не будет.\r\n\r\nПеревести в режим «только прокси» на свободный порт:\r\n%s\r\n\r\nДа: перевести и включить %s.\r\nНет: ничего не включать."
	chainViaClashUp        = "%s уже работает в режиме «%s», а %s тоже забирает весь интернет. В одной связке так может только один туннель, так работать не будет.\r\n\r\nВыключите %s и смените режим на «только прокси» на вкладке «Прокси»."
	chainViaOtherNeeds     = "Для %s нужно включить %s в режиме «%s»."
	chainViaOtherSelf      = "%s включается в режиме «%s»."
	chainViaOtherAskText   = "%s Сейчас работает %s, через него идёт %s. Вместе они работать не могут.\r\n\r\nДа: выключить %s и всё, что через него идёт, и включить %s.\r\nНет: ничего не включать."
	chainViaOtherStuck     = "Не удалось выключить %s. Попробуйте ещё раз."
	chainViaPortAskText    = "Порт %d уже занят туннелем %s.\r\n\r\nДа: задать %s свободный порт %d и включить.\r\nНет: ничего не включать."
	// WarpAm pack 111: the ports of the tunnels below, in one window.
	chainViaPortAskLine    = "У %s порт %d, а его уже занимает %s. Свободный порт: %d."
	chainViaPortAskTail    = "Да: перенести на %s и включить %s.\r\nНет: ничего не включать."
	chainViaPortOne        = "свободный порт"
	chainViaPortMany       = "свободные порты"
	chainViaClashSaveError = "Не удалось сохранить настройки %s: "
	chainViaClashNoPort    = "Не нашлось свободного порта для прокси."
	chainViaClashPort      = "%s: порт %d"
	chainViaModeTunnel     = "туннель"
	chainViaModeBoth       = "туннель с прокси"
	// WarpAm pack 112: the second proxy of a double tunnel has a port too.
	chainViaPortSecond   = "второй прокси %s"
	chainViaPortSecondOf = "второго прокси %s"
)

// chainViaMembersUI asks the service about every tunnel. When over is set,
// that tunnel is seen with the settings st instead of the saved ones.
func chainViaMembersUI(over string, st *manager.ChainTunnelSettings) []manager.ChainViaMember {
	all, err := manager.IPCClientTunnels()
	if err != nil {
		return nil
	}
	members := make([]manager.ChainViaMember, 0, len(all))
	for i := range all {
		tunnel := all[i]
		// WarpAm pack 105: a hidden hop is never shown or offered.
		if manager.ChainIsHiddenHop(tunnel.Name) {
			continue
		}
		settings, err := manager.IPCClientChainSettings(tunnel.Name)
		if err != nil {
			continue
		}
		if st != nil && strings.EqualFold(tunnel.Name, over) {
			settings = *st
		}
		up := false
		if state, err := tunnel.State(); err == nil {
			up = state == manager.TunnelStarted || state == manager.TunnelStarting
		}
		members = append(members, manager.ChainViaMember{Name: tunnel.Name, Settings: settings, Up: up})
	}
	return members
}

// chainViaFreePorts finds n ports from 1080 upward that no tunnel is set
// to and that nothing listens on now.
func chainViaFreePorts(members []manager.ChainViaMember, n int) []int {
	used := make(map[int]bool)
	for _, m := range members {
		if m.Settings.Proxy {
			used[m.Settings.Port()] = true
		}
		// WarpAm pack 112: and the port of the second proxy.
		if m.Settings.Proxy2 && m.Settings.Proxy2Port > 0 {
			used[m.Settings.Proxy2Port] = true
		}
	}
	var ports []int
	for p := manager.ChainProxyDefaultPort; p < 65536 && len(ports) < n; p++ {
		if used[p] {
			continue
		}
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		l.Close()
		ports = append(ports, p)
	}
	return ports
}

// chainViaRaiseAsk is asked before a tunnel that is down is raised. False
// means nothing is raised.
func chainViaRaiseAsk(owner walk.Form, t *manager.Tunnel) bool {
	// WarpAm pack 112: first the same key (chainkeyclash.go). The answer
	// No ends it before anything else is asked or changed.
	if !chainKeyClashAsk(owner, t) {
		return false
	}
	if !chainViaStackAsk(owner, t, chainViaMembersUI("", nil)) {
		return false
	}
	// WarpAm pack 104: each question may change settings or stop tunnels,
	// so the next one reads everything again.
	stopping, ok := chainViaOtherStop(owner, t, chainViaMembersUI("", nil))
	if !ok {
		return false
	}
	if !chainViaPortAsk(owner, t, chainViaMembersUI("", nil), stopping) {
		return false
	}
	// WarpAm pack 111: last, what this raise switches off together with
	// what goes through it (chainstartask.go).
	return chainStartVictimAsk(owner, t)
}

// chainViaStackAsk is the rule of pack 103 inside the stack of t.
func chainViaStackAsk(owner walk.Form, t *manager.Tunnel, members []manager.ChainViaMember) bool {
	full := manager.ChainViaFull(t.Name, members, false)
	if len(full) < 2 {
		return true
	}
	// The one that keeps carrying the machine: the tunnel being raised if
	// it does, otherwise the first one that is up, otherwise the first.
	keep := -1
	for i, m := range full {
		if strings.EqualFold(m.Name, t.Name) {
			keep = i
		}
	}
	if keep < 0 {
		keep = 0
		for i, m := range full {
			if m.Up {
				keep = i
				break
			}
		}
	}
	var change []manager.ChainViaMember
	var names, up []string
	mode := chainViaModeTunnel
	for i, m := range full {
		if i == keep {
			continue
		}
		change = append(change, m)
		names = append(names, m.Name)
		if m.Up {
			if len(up) == 0 && m.Settings.Proxy {
				mode = chainViaModeBoth
			}
			up = append(up, m.Name)
		}
	}

	// Something that would have to change is up: a running tunnel is
	// never switched behind its back.
	if len(up) != 0 {
		list := strings.Join(up, ", ")
		walk.MsgBox(owner, chainTitle, fmt.Sprintf(chainViaClashUp, list, mode, full[keep].Name, list), walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return false
	}

	ports := chainViaFreePorts(members, len(change))
	if len(ports) < len(change) {
		showErrorCustom(owner, chainTitle, chainViaClashNoPort)
		return false
	}
	lines := make([]string, 0, len(change))
	for i, m := range change {
		lines = append(lines, fmt.Sprintf(chainViaClashPort, m.Name, ports[i]))
	}
	text := fmt.Sprintf(chainViaClashAsk, full[keep].Name, strings.Join(names, ", "), strings.Join(lines, "\r\n"), t.Name)
	if walk.DlgCmdYes != walk.MsgBox(owner, chainTitle, text, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return false
	}
	for i, m := range change {
		settings := m.Settings
		settings.Proxy = true
		settings.ProxySplit = true
		settings.ProxyPort = ports[i]
		if err := manager.IPCClientChainSettingsSave(m.Name, settings); err != nil {
			showErrorCustom(owner, chainTitle, fmt.Sprintf(chainViaClashSaveError, m.Name)+err.Error())
			return false
		}
	}
	ChainMarksChangedNow()
	return true
}

// chainViaModeOf names the mode of a tunnel that carries the machine.
func chainViaModeOf(s manager.ChainTunnelSettings) string {
	if s.Proxy {
		return chainViaModeBoth
	}
	return chainViaModeTunnel
}

// chainViaOtherStop is asked when the raise brings up a tunnel that
// carries the machine while a tunnel of another stack does, and something
// goes through that one. Only one of the two can carry the machine, and
// what goes through the other would be left without a way out. On yes the
// other tunnel and all that goes through it are stopped first. The answer
// is the set of the stopped tunnels; false means nothing is raised. When
// nothing goes through the other tunnel, the usual switch stays as it was.
func chainViaOtherStop(owner walk.Form, t *manager.Tunnel, members []manager.ChainViaMember) (map[string]bool, bool) {
	stack := manager.ChainViaStack(t.Name, members, false)
	in := make(map[string]bool, len(stack))
	var raising *manager.ChainViaMember
	for i := range stack {
		in[strings.ToLower(stack[i].Name)] = true
		if raising == nil && !stack[i].Up && manager.ChainViaCarriesAll(stack[i].Settings) {
			raising = &stack[i]
		}
	}
	if raising == nil {
		return nil, true
	}
	for _, m := range members {
		if !m.Up || in[strings.ToLower(m.Name)] || !manager.ChainViaCarriesAll(m.Settings) {
			continue
		}
		riders := manager.ChainViaRiders(m.Name, members)
		if len(riders) == 0 {
			continue
		}
		first := fmt.Sprintf(chainViaOtherNeeds, t.Name, raising.Name, chainViaModeOf(raising.Settings))
		if strings.EqualFold(raising.Name, t.Name) {
			first = fmt.Sprintf(chainViaOtherSelf, t.Name, chainViaModeOf(raising.Settings))
		}
		text := fmt.Sprintf(chainViaOtherAskText, first, m.Name, strings.Join(manager.ChainViaNames(riders), ", "), m.Name, t.Name)
		if walk.DlgCmdYes != walk.MsgBox(owner, chainTitle, text, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
			return nil, false
		}
		stop := append(riders, m)
		if !chainViaStopWait(stop) {
			showErrorCustom(owner, chainTitle, fmt.Sprintf(chainViaOtherStuck, m.Name))
			return nil, false
		}
		stopping := make(map[string]bool, len(stop))
		for _, x := range stop {
			stopping[strings.ToLower(x.Name)] = true
		}
		return stopping, true
	}
	return nil, true
}

// chainViaStopWait stops the tunnels in the given order and waits up to
// 15 seconds for all of them to be down.
func chainViaStopWait(list []manager.ChainViaMember) bool {
	all, err := manager.IPCClientTunnels()
	if err != nil {
		return false
	}
	byName := make(map[string]manager.Tunnel, len(all))
	for _, tn := range all {
		byName[strings.ToLower(tn.Name)] = tn
	}
	for _, m := range list {
		tn, ok := byName[strings.ToLower(m.Name)]
		if !ok {
			continue
		}
		log.Printf("[%s] Via: stopped to make room, as asked in the window", m.Name)
		if err := tn.Stop(); err != nil {
			log.Printf("[%s] Via: could not stop it: %v", m.Name, err)
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for _, m := range list {
		tn, ok := byName[strings.ToLower(m.Name)]
		if !ok {
			continue
		}
		for {
			state, err := tn.State()
			if err != nil || state == manager.TunnelStopped {
				break
			}
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return true
}

// chainViaPortAsk is asked when the port of the proxy of t is taken by a
// tunnel that is up. Yes gives t a free port and goes on.
//
// WarpAm pack 111: the tunnels below t that are down come up with it, so
// their ports are asked about in the same window. On 7 October 100 was
// raised through Elena; the window looked only at 100, and Elena was then
// refused by the manager for port 1081, which WARPv2_84 held. Every free
// port is found before the window opens, and is never a port another
// tunnel is set to, even one that is down.
func chainViaPortAsk(owner walk.Form, t *manager.Tunnel, members []manager.ChainViaMember, stopping map[string]bool) bool {
	index := make(map[string]int, len(members))
	for i := range members {
		index[strings.ToLower(members[i].Name)] = i
	}
	// t, then down along the via link while the tunnel there is down.
	var raising []int
	inRaise := make(map[string]bool)
	at := t.Name
	for n := 0; n < chainViaPortDepth && len(at) != 0; n++ {
		i, ok := index[strings.ToLower(at)]
		if !ok || inRaise[strings.ToLower(at)] || (n > 0 && members[i].Up) {
			break
		}
		raising = append(raising, i)
		inRaise[strings.ToLower(at)] = true
		at = ""
		if members[i].Settings.ProxyVia {
			at = strings.TrimSpace(members[i].Settings.ProxyViaTunnel)
		}
	}
	if len(raising) == 0 {
		return true
	}

	taken := make(map[int]string)
	for _, m := range members {
		key := strings.ToLower(m.Name)
		if !m.Up || inRaise[key] || stopping[key] {
			continue
		}
		if m.Settings.Proxy {
			taken[m.Settings.Port()] = m.Name
		}
		// WarpAm pack 112: the second proxy of a double tunnel that is up
		// holds its port as well.
		if m.Settings.Proxy2 && m.Settings.Proxy2Port > 0 {
			taken[m.Settings.Proxy2Port] = fmt.Sprintf(chainViaPortSecond, m.Name)
		}
	}
	type clash struct {
		self   int
		port   int
		holder string
		second bool
	}
	var clashes []clash
	// The bottom first: that is the order they come up in, so the one
	// below keeps its port when two of the raise have the same.
	for k := len(raising) - 1; k >= 0; k-- {
		i := raising[k]
		if members[i].Settings.Proxy {
			port := members[i].Settings.Port()
			if holder, ok := taken[port]; ok {
				clashes = append(clashes, clash{i, port, holder, false})
			} else {
				taken[port] = members[i].Name
			}
		}
		if members[i].Settings.Proxy2 && members[i].Settings.Proxy2Port > 0 {
			port := members[i].Settings.Proxy2Port
			if holder, ok := taken[port]; ok {
				clashes = append(clashes, clash{i, port, holder, true})
			} else {
				taken[port] = fmt.Sprintf(chainViaPortSecond, members[i].Name)
			}
		}
	}
	if len(clashes) == 0 {
		return true
	}

	ports := chainViaFreePorts(members, len(clashes))
	if len(ports) < len(clashes) {
		showErrorCustom(owner, chainTitle, chainViaClashNoPort)
		return false
	}
	var text string
	if len(clashes) == 1 && !clashes[0].second && strings.EqualFold(members[clashes[0].self].Name, t.Name) {
		text = fmt.Sprintf(chainViaPortAskText, clashes[0].port, clashes[0].holder, t.Name, ports[0])
	} else {
		lines := make([]string, 0, len(clashes))
		for k, c := range clashes {
			who := members[c.self].Name
			if c.second {
				who = fmt.Sprintf(chainViaPortSecondOf, who)
			}
			lines = append(lines, fmt.Sprintf(chainViaPortAskLine, who, c.port, c.holder, ports[k]))
		}
		where := chainViaPortOne
		if len(clashes) > 1 {
			where = chainViaPortMany
		}
		text = strings.Join(lines, "\r\n") + "\r\n\r\n" + fmt.Sprintf(chainViaPortAskTail, where, t.Name)
	}
	if walk.DlgCmdYes != walk.MsgBox(owner, chainTitle, text, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return false
	}
	for k, c := range clashes {
		m := members[c.self]
		// WarpAm pack 112: two clashes of one tunnel change one set of
		// settings, so it is read from the list each time.
		settings := members[c.self].Settings
		if c.second {
			settings.Proxy2Port = ports[k]
		} else {
			settings.ProxyPort = ports[k]
		}
		members[c.self].Settings = settings
		if err := manager.IPCClientChainSettingsSave(m.Name, settings); err != nil {
			showErrorCustom(owner, chainTitle, fmt.Sprintf(chainViaClashSaveError, m.Name)+err.Error())
			return false
		}
		log.Printf("[%s] Via: the port %d was taken by %s, the proxy is moved to %d as asked in the window", m.Name, c.port, c.holder, ports[k])
	}
	ChainMarksChangedNow()
	return true
}
