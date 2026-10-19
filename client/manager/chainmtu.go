//go:build windows

/* WarpAm pack 112: the MTU of every tunnel, in the network it is used in.
 *
 * The book itself lives in core/chainmtu (Data\mtu.json). The manager does
 * three things with it:
 *
 *   - before a raise, every tunnel the raise brings up that has no number
 *     in this network yet is checked outside, through the physical
 *     adapter (chainMTUBeforeRaise). A number typed in by hand and a check
 *     that already failed here are left alone: the button tries again.
 *
 * WarpAm pack 113: the check inside a tunnel that goes through another
 * one is kept as a correction of that pair, not as the own maximum, and a
 * number typed in by hand is replaced by the buttons and by the check
 * inside.
 *   - after a raise, a ping inside the tunnel tells whether its server
 *     takes packets as big as the MTU. When it does not, the adapter is
 *     lowered at once and the own maximum is saved as "lowered by the
 *     check inside" (chainMTUInnerLater).
 *   - the MTU tab reads the table (116) and asks for checks, a number by
 *     hand and the reset of this network (117). A check lasts seconds, so
 *     117 only starts it and the tab asks for the table again.
 */

package manager

import (
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/chainmtu"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// 113, 114 and 115 are the key clash and the chain length.
const (
	ChainMTUTableMethodType  MethodType = 116
	ChainMTUActionMethodType MethodType = 117
)

// ChainMTURow is one line of the MTU tab. Hop is 0 for a single tunnel, 1
// and 2 for the first and the second link of a double one.
type ChainMTURow struct {
	Tunnel  string
	Shown   string
	Hop     int
	Own     int
	OwnFrom string
	Chain   int
	Parent  string
	Path    int
	When    time.Time
	Failed  bool
	Manual  bool
	Inner   bool
	Busy    bool
}

// ChainMTUTable is the whole tab: the network and the lines.
type ChainMTUTable struct {
	Network string
	Rows    []ChainMTURow
	Busy    bool
}

// ChainMTUAction is what a button of the tab asks for: "check" with Name,
// "checkall", "reset", "manual" with Name and Value (0 clears the number).
type ChainMTUAction struct {
	Do    string
	Name  string
	Value int
}

var chainMTUState = struct {
	sync.Mutex
	busy map[string]bool
}{busy: make(map[string]bool)}

// chainMTUServer is the address of the server of a tunnel, IPv4 first.
func chainMTUServer(c *conf.Config) net.IP {
	for i := range c.Peers {
		endpoint := c.Peers[i].Endpoint
		if endpoint.IsEmpty() {
			continue
		}
		host := strings.Trim(strings.TrimSpace(endpoint.Host), "[]")
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
		resolved, err := net.LookupIP(host)
		if err != nil || len(resolved) == 0 {
			continue
		}
		for _, ip := range resolved {
			if ip.To4() != nil {
				return ip
			}
		}
		return resolved[0]
	}
	return nil
}

// chainMTUTake marks name as being checked; false when it already is.
func chainMTUTake(name string) bool {
	chainMTUState.Lock()
	defer chainMTUState.Unlock()
	k := strings.ToLower(name)
	if chainMTUState.busy[k] {
		return false
	}
	chainMTUState.busy[k] = true
	return true
}

func chainMTUDrop(name string) {
	chainMTUState.Lock()
	delete(chainMTUState.busy, strings.ToLower(name))
	chainMTUState.Unlock()
}

func chainMTUBusy(name string) bool {
	chainMTUState.Lock()
	defer chainMTUState.Unlock()
	return chainMTUState.busy[strings.ToLower(name)]
}

// chainMTUCheck checks one tunnel outside and writes what it found. force
// replaces a number typed in by hand; the buttons of the tab do so.
func chainMTUCheck(here chainmtu.Here, name, why string, force bool) {
	if !chainMTUTake(name) {
		return
	}
	defer chainMTUDrop(name)
	c, err := conf.LoadFromName(name)
	if err != nil {
		log.Printf("[WarpAm] MTU check: %s has no config: %v", name, err)
		return
	}
	server := chainMTUServer(c)
	if server == nil {
		log.Printf("[WarpAm] MTU check: %s has no server address, nothing is checked", name)
		return
	}
	res, err := chainmtu.PathMTU(here, server)
	if err != nil || res.Path == 0 {
		log.Printf("[WarpAm] MTU check: %s (%s): neither the server %s nor the spare address answered (%v); the raise keeps the old counting, the button of the MTU tab tries again", name, why, server, err)
		chainmtu.Put(here, name, chainmtu.Entry{Failed: true}, force)
		return
	}
	own := chainmtu.FromPath(res.Path, c)
	log.Printf("[WarpAm] MTU check: %s (%s) in the network %s: path %d to %s (%d probes, %s), own maximum %d", name, why, here.Text(), res.Path, res.Target, res.Probes, res.Took.Round(time.Millisecond), own)
	chainmtu.Put(here, name, chainmtu.Entry{Max: own, Path: res.Path, Target: res.Target.String()}, force)
}

// chainMTUBeforeRaise checks the tunnels the raise of name brings up that
// have no entry in this network yet. It runs inside Start, before the
// first tunnel is installed, so the service already counts with them.
func (s *ManagerService) chainMTUBeforeRaise(name string) {
	here := chainmtu.Find()
	if len(here.Key) == 0 {
		log.Printf("[WarpAm] MTU check: the network of this machine is not known, nothing is checked before %s", name)
		return
	}
	list := s.chainStartRaiseList(name)
	var wg sync.WaitGroup
	for _, t := range list {
		// Pack 113: an entry with nothing but a correction inside another
		// tunnel knows no own maximum yet.
		if e, known := chainmtu.Get(here, t); known && (e.Max > 0 || e.Failed) {
			continue
		}
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			chainMTUCheck(here, t, "before the raise of "+name, false)
		}(t)
	}
	wg.Wait()
}

// chainMTUInnerLater runs after a tunnel is installed and checks inside it
// whether its server takes packets as big as the MTU.
func (s *ManagerService) chainMTUInnerLater(name string) {
	if conf.ChainIsHiddenHopName(name) {
		// The hidden hop carries no address of its own to ping from in a
		// way that means anything; the tunnel above it is checked.
		return
	}
	go func() {
		c, err := conf.LoadFromName(name)
		if err != nil {
			return
		}
		var local net.IP
		for _, a := range c.Interface.Addresses {
			if a.IP.To4() != nil {
				local = a.IP.To4()
				break
			}
		}
		if local == nil {
			return
		}
		target := net.IPv4(1, 1, 1, 1).To4()
		for _, d := range c.Interface.DNS {
			if d.To4() != nil {
				target = d.To4()
				break
			}
		}
		var luid winipcfg.LUID
		found := false
		for i := 0; i < 30 && !found; i++ {
			time.Sleep(time.Second)
			if state, err := s.State(name); err == nil && state == TunnelStopped {
				return
			}
			luid, found = chainAdapterLUID(name)
		}
		if !found {
			return
		}
		// The first handshake may still be on its way.
		time.Sleep(3 * time.Second)
		row, err := luid.Interface()
		if err != nil {
			return
		}
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return
		}
		mtu := int(ipif.NLMTU)
		res, err := chainmtu.InnerCheck(local, row.InterfaceIndex, target, mtu)
		if err != nil {
			log.Printf("[WarpAm] MTU check inside %s could not run: %v", name, err)
			return
		}
		switch {
		case !res.Answered:
			log.Printf("[WarpAm] MTU check inside %s: %s does not answer a ping, nothing can be said about MTU %d", name, target, mtu)
			return
		case res.Fits == mtu:
			log.Printf("[WarpAm] MTU check inside %s: packets of %d get through to %s, the MTU stays", name, mtu, target)
			return
		case res.Fits == 0:
			log.Printf("[WarpAm] MTU check inside %s: small pings get through, but none of %v; the MTU %d stays, the button of the MTU tab can lower it", name, res.Tried, mtu)
			return
		}
		here := chainmtu.Find()
		ipif.NLMTU = uint32(res.Fits)
		if err := ipif.Set(); err != nil {
			log.Printf("[WarpAm] MTU check inside %s: only %d gets through instead of %d, lowering the adapter failed: %v", name, res.Fits, mtu, err)
		} else {
			log.Printf("[WarpAm] MTU check inside %s: only %d gets through instead of %d, the adapter is lowered to %d", name, res.Fits, mtu, res.Fits)
		}
		chainMTUInnerSave(here, name, res.Fits, res.Tried)
	}()
}

// chainMTUInnerSave writes what the check inside found (pack 113). A
// tunnel that goes straight out has its own maximum lowered, even one
// typed in by hand. A tunnel that goes through another one keeps its own
// maximum: the bytes it loses beyond the counting are noted for that very
// pair and count only while it goes through the same tunnel.
func chainMTUInnerSave(here chainmtu.Here, name string, fits int, tried []int) {
	if len(here.Key) == 0 {
		return
	}
	steps := chainmtu.Stack(here, name)
	if len(steps) < 2 {
		old, _ := chainmtu.Get(here, name)
		log.Printf("[WarpAm] MTU check inside %s (sizes tried %v): it goes straight out, so its own maximum becomes %d", name, tried, fits)
		chainmtu.Put(here, name, chainmtu.Entry{Max: fits, Path: old.Path, Inner: true, Target: old.Target}, true)
		return
	}
	self := steps[len(steps)-1]
	below := steps[len(steps)-2]
	counted := below.MTU - self.Overhead
	extra := counted - fits
	if extra <= 0 {
		log.Printf("[WarpAm] MTU check inside %s (sizes tried %v): %d gets through inside %s, which is no less than the counting %d, nothing is noted", name, tried, fits, self.Parent, counted)
		return
	}
	log.Printf("[WarpAm] MTU check inside %s (sizes tried %v): inside %s it loses %d bytes more than the counting (%d - %d = %d, but only %d gets through); this is noted for %s inside %s only, its own maximum stays", name, tried, self.Parent, extra, below.MTU, self.Overhead, counted, fits, name, self.Parent)
	chainmtu.PutInside(here, name, self.Parent, extra)
}

// chainMTUNames lists the tunnels of the tab: a double tunnel gives two
// lines, its hidden hop first.
func chainMTUNames() []ChainMTURow {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	var rows []ChainMTURow
	for _, n := range names {
		if conf.ChainIsHiddenHopName(n) {
			continue
		}
		if hop := chainParentName(n); len(hop) != 0 && conf.ChainIsHiddenHopName(hop) {
			rows = append(rows, ChainMTURow{Tunnel: hop, Shown: n, Hop: 1}, ChainMTURow{Tunnel: n, Shown: n, Hop: 2})
			continue
		}
		rows = append(rows, ChainMTURow{Tunnel: n, Shown: n})
	}
	return rows
}

// ChainMTUTableNow fills the tab.
func ChainMTUTableNow() ChainMTUTable {
	here := chainmtu.Find()
	out := ChainMTUTable{Network: here.Text()}
	entries := chainmtu.All(here)
	for _, r := range chainMTUNames() {
		e, ok := entries[strings.ToLower(strings.TrimSpace(r.Tunnel))]
		if ok {
			r.Path, r.When, r.Failed, r.Manual, r.Inner = e.Path, e.When, e.Failed, e.Manual, e.Inner
		}
		mtu, steps := chainmtu.Effective(here, r.Tunnel)
		r.Chain = mtu
		if len(steps) != 0 {
			self := steps[len(steps)-1]
			r.Own, r.OwnFrom = self.Own, self.OwnFrom
			if len(self.Parent) != 0 {
				r.Parent = chainShownName(self.Parent)
			}
		}
		r.Busy = chainMTUBusy(r.Tunnel)
		if r.Busy {
			out.Busy = true
		}
		out.Rows = append(out.Rows, r)
	}
	return out
}

// chainMTUDo carries out a button of the tab. The checks run on their own.
func (s *ManagerService) chainMTUDo(a ChainMTUAction) error {
	here := chainmtu.Find()
	if len(here.Key) == 0 {
		return fmt.Errorf("the network of this machine is not known")
	}
	switch a.Do {
	case "check":
		go chainMTUCheck(here, a.Name, "asked in the MTU tab", true)
	case "checkall":
		// Pack 113: a number typed in by hand is checked and replaced too.
		for _, r := range chainMTUNames() {
			go chainMTUCheck(here, r.Tunnel, "all tunnels, asked in the MTU tab", true)
		}
	case "reset":
		log.Printf("[WarpAm] MTU: every number of the network %s is removed", here.Text())
		return chainmtu.Reset(here)
	case "manual":
		if a.Value == 0 {
			log.Printf("[WarpAm] MTU: the number of %s typed in by hand is removed", a.Name)
			return chainmtu.Forget(here, a.Name)
		}
		if a.Value < chainmtu.Floor || a.Value > 1500 {
			return fmt.Errorf("MTU %d is out of %d..1500", a.Value, chainmtu.Floor)
		}
		log.Printf("[WarpAm] MTU: %s gets %d by hand in the network %s", a.Name, a.Value, here.Text())
		return chainmtu.Put(here, a.Name, chainmtu.Entry{Max: a.Value, Manual: true}, true)
	default:
		return fmt.Errorf("unknown MTU action %q", a.Do)
	}
	return nil
}

func (s *ManagerService) chainServeMTUTable(decoder *gob.Decoder, encoder *gob.Encoder) error {
	if err := encoder.Encode(ChainMTUTableNow()); err != nil {
		return err
	}
	return encoder.Encode(errToString(nil))
}

func (s *ManagerService) chainServeMTUAction(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var a ChainMTUAction
	if err := decoder.Decode(&a); err != nil {
		return err
	}
	var err error
	if s.chainMayChange("A change of the MTU") {
		err = s.chainMTUDo(a)
	} else {
		err = fmt.Errorf("the caller of the pipe is not the elevated interface")
	}
	return encoder.Encode(errToString(err))
}

// IPCClientChainMTUTable asks for the lines of the MTU tab.
func IPCClientChainMTUTable() (ChainMTUTable, error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	var reply ChainMTUTable
	if err := rpcEncoder.Encode(ChainMTUTableMethodType); err != nil {
		return reply, err
	}
	if err := rpcDecoder.Decode(&reply); err != nil {
		return reply, err
	}
	return reply, rpcDecodeError()
}

// IPCClientChainMTUAction carries out a button of the MTU tab.
func IPCClientChainMTUAction(a ChainMTUAction) error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	if err := rpcEncoder.Encode(ChainMTUActionMethodType); err != nil {
		return err
	}
	if err := rpcEncoder.Encode(a); err != nil {
		return err
	}
	return rpcDecodeError()
}
