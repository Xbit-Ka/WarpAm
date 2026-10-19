//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 103: only one tunnel of a via stack may carry the machine.
 *
 * A stack is the tunnel, the tunnels it goes through, and the tunnels that
 * go through it. A tunnel carries the machine in the modes "tunnel" and
 * "tunnel with proxy"; only "proxy only" leaves the routes alone. Two of
 * them in one stack put two default routes side by side with the same
 * metric, and Windows picks one at random.
 *
 * WarpAm pack 104: the tunnels that go through a tunnel which is being
 * stopped are stopped with it, so none of them is left up without a way
 * out.
 */

package manager

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainDNSLookupText is shown in the window when the name of the server
// did not resolve.
const chainDNSLookupText = "Не удалось найти адрес сервера по имени. Возможно, DNS ещё не работает: сеть или другой туннель ещё поднимаются. Попробуйте ещё раз через несколько секунд."

// chainViaClashRefused is the answer of the manager when the window was
// not asked, for example a raise at boot.
const chainViaClashRefused = "Туннель %s не включён: %s забирают весь интернет, а в одной связке так может только один туннель.\r\nПоставьте остальным режим «только прокси» на вкладке «Прокси»."

// chainViaStackDepth bounds every walk along the via links.
const chainViaStackDepth = 8

// ChainViaMember is one tunnel as the rule sees it.
type ChainViaMember struct {
	Name     string
	Settings ChainTunnelSettings
	Up       bool
}

// ChainViaCarriesAll says whether a tunnel in these settings takes the
// traffic of the whole machine.
func ChainViaCarriesAll(s ChainTunnelSettings) bool {
	return !(s.Proxy && s.ProxySplit)
}

// chainViaIndex gives the place of every member by name and the walk one
// step down along the via link.
func chainViaIndex(all []ChainViaMember) (map[string]int, func(string) string) {
	index := make(map[string]int, len(all))
	for i, m := range all {
		index[strings.ToLower(m.Name)] = i
	}
	parent := func(n string) string {
		i, ok := index[strings.ToLower(n)]
		if !ok || !all[i].Settings.ProxyVia {
			return ""
		}
		p := strings.TrimSpace(all[i].Settings.ProxyViaTunnel)
		if _, ok := index[strings.ToLower(p)]; !ok || strings.EqualFold(p, n) {
			return ""
		}
		return all[index[strings.ToLower(p)]].Name
	}
	return index, parent
}

// ChainViaStack gives the stack of name: the tunnel itself, the tunnels
// below it, and the tunnels above it that are up, or all of them when
// allRiders is set.
func ChainViaStack(name string, all []ChainViaMember, allRiders bool) []ChainViaMember {
	index, parent := chainViaIndex(all)
	self, ok := index[strings.ToLower(name)]
	if !ok {
		return nil
	}

	stack := []int{self}
	seen := map[string]bool{strings.ToLower(name): true}
	for p, n := parent(name), 0; len(p) != 0 && n < chainViaStackDepth && !seen[strings.ToLower(p)]; p, n = parent(p), n+1 {
		seen[strings.ToLower(p)] = true
		stack = append(stack, index[strings.ToLower(p)])
	}
	for i, m := range all {
		if seen[strings.ToLower(m.Name)] || (!allRiders && !m.Up) {
			continue
		}
		for p, n := parent(m.Name), 0; len(p) != 0 && n < chainViaStackDepth; p, n = parent(p), n+1 {
			if strings.EqualFold(p, name) {
				stack = append(stack, i)
				break
			}
		}
	}

	out := make([]ChainViaMember, 0, len(stack))
	for _, i := range stack {
		out = append(out, all[i])
	}
	return out
}

// ChainViaFull gives the tunnels of the stack of name that carry the
// machine. The tunnels below always count, because they are raised with
// it; the tunnels above count when they are up, or always when allRiders
// is set. More than one in the answer means the stack will not work.
func ChainViaFull(name string, all []ChainViaMember, allRiders bool) []ChainViaMember {
	var full []ChainViaMember
	for _, m := range ChainViaStack(name, all, allRiders) {
		if ChainViaCarriesAll(m.Settings) {
			full = append(full, m)
		}
	}
	return full
}

// ChainViaRiders gives the tunnels that are up and go through name,
// directly or further up, the farthest first, which is the order they
// are stopped in.
func ChainViaRiders(name string, all []ChainViaMember) []ChainViaMember {
	_, parent := chainViaIndex(all)
	type rider struct {
		member ChainViaMember
		depth  int
	}
	var riders []rider
	for _, m := range all {
		if !m.Up || strings.EqualFold(m.Name, name) {
			continue
		}
		for p, n := parent(m.Name), 1; len(p) != 0 && n <= chainViaStackDepth; p, n = parent(p), n+1 {
			if strings.EqualFold(p, name) {
				riders = append(riders, rider{m, n})
				break
			}
		}
	}
	sort.SliceStable(riders, func(i, j int) bool { return riders[i].depth > riders[j].depth })
	out := make([]ChainViaMember, 0, len(riders))
	for _, r := range riders {
		out = append(out, r.member)
	}
	return out
}

// ChainViaNames lists the names of the members.
func ChainViaNames(members []ChainViaMember) []string {
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.Name)
	}
	return names
}

// chainViaClashError is the safety net of the manager. The window asks
// first; this catches what comes without a window.
func (s *ManagerService) chainViaClashError(name string) error {
	members := s.chainViaMembers()
	if members == nil {
		return nil
	}
	full := ChainViaFull(name, members, false)
	if len(full) < 2 {
		return nil
	}
	list := strings.Join(ChainViaNames(full), ", ")
	log.Printf("[%s] Via: %s all carry the machine and only one of them may, so it is not raised", name, list)
	return fmt.Errorf(chainViaClashRefused, name, list)
}

// chainViaMembers is every tunnel as the service sees it now.
func (s *ManagerService) chainViaMembers() []ChainViaMember {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil
	}
	members := make([]ChainViaMember, 0, len(names))
	for _, n := range names {
		// WarpAm pack 105: a hidden hop belongs to its chain and is never
		// counted or offered to be changed.
		if conf.ChainIsHiddenHopName(n) {
			continue
		}
		state, _ := s.State(n)
		members = append(members, ChainViaMember{
			Name:     n,
			Settings: ChainSettingsFor(n),
			Up:       state == TunnelStarted || state == TunnelStarting,
		})
	}
	return members
}

// chainViaStopRiders stops what goes through name before name itself is
// stopped to make room for another tunnel. A tunnel left up on a parent
// that is gone looks alive and works for nobody. except is the tunnel
// being raised, which is never stopped here.
//
// WarpAm pack 110: byUser says that the user switched name off. Then
// every rider is noted as switched off by hand as well. The note used to
// cover only the tunnels that pin to name, not those that go through it
// by the "via" box, so after a reboot the start-up raise brought 100 back
// up, and 100 raised warpam (pack 101), which the user had switched off.
func (s *ManagerService) chainViaStopRiders(name, except string, byUser bool) {
	for _, m := range ChainViaRiders(name, s.chainViaMembers()) {
		if strings.EqualFold(m.Name, except) {
			continue
		}
		log.Printf("[WarpAm] %s goes through %s, which is being stopped, so it is stopped too", m.Name, name)
		if err := s.Stop(m.Name); err != nil {
			log.Printf("[WarpAm] %s could not be stopped: %v", m.Name, err)
			continue
		}
		// WarpAm pack 113: the next one goes only when Windows has taken
		// this adapter away (chainadaptergone.go).
		ChainWaitAdapterGone(m.Name)
		if byUser {
			ChainNoteTunnelDown(m.Name)
		}
	}
}
