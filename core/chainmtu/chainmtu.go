//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the book of MTU values.
 *
 * Until now the bottom tunnel of a stack took its MTU from its config file,
 * and WARPv2_84 carried 1280 there "just in case". Every tunnel above it
 * was counted from that number, so the whole stack lost bytes it never had
 * to lose: 100 at the top ran with about 1064 instead of about 1200.
 *
 * What is kept here is one number per tunnel: its own maximum, the largest
 * MTU its packets can have on the straight way to its server. It is found
 * outside, with a ping that must not be cut (probe.go), and nothing has to
 * be raised for that. The MTU a tunnel gets inside a stack is never kept:
 * it is counted at every raise, the smaller of its own maximum and of
 * "the parent minus the header of this tunnel minus S4". So a change of the
 * tunnel it goes through needs no new check at all.
 *
 * The header is 60 bytes when the server of the tunnel is an IPv4 address
 * and 80 when it is an IPv6 address: an IP header of 20 or 40 bytes, UDP 8,
 * the WireGuard data header 16 and its tag 16. The log of 7 October agrees:
 * 1280 became 1208 inside WARPv2_84, which is 60 and S4 12.
 *
 * The own maximum depends on the line of the machine (PPPoE 1492, a mobile
 * network about 1400), so it is kept per network. A network is the adapter
 * with the default route together with its gateway, and the gateway is
 * known by its hardware address, because two home routers both called
 * 192.168.1.1 are two different networks.
 *
 * WarpAm pack 113: the check inside a tunnel that goes through another one
 * says nothing about the own maximum of that tunnel. On 8.10 100 inside
 * Elena got through only with 1265, this was kept as the own maximum of
 * 100, and later 100 alone ran with 1265 although its way out took 1428.
 * Such a finding is now kept apart, as "inside Elena 100 loses 16 bytes
 * more", and it counts only while 100 goes through Elena. Only a tunnel
 * that goes straight out has its own maximum lowered by the check inside.
 *
 * The file is Data\mtu.json. The manager writes it after a check, and the
 * tunnel service writes it after the check inside (probe.go) lowered a
 * number; both read it again right before they write, so neither throws
 * away what the other has just put in.
 */

package chainmtu

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const (
	// DefaultMTU is what a tunnel gets when nothing better is known, the
	// number WireGuard itself uses.
	DefaultMTU = 1420
	// Floor is the smallest MTU ever given out: the IPv4 minimum.
	Floor = 576
	// IPv6Floor is the smallest MTU IPv6 works with. Below it the adapter
	// keeps IPv4 only (core/tunnel/addressconfig.go).
	IPv6Floor = 1280
)

// Entry is what is known about one tunnel in one network.
type Entry struct {
	// Max is the own maximum. Zero means nothing is known.
	Max int
	// Path is the size of the largest packet that got through outside.
	Path int
	// Manual is true when the number was typed in the MTU tab.
	// WarpAm pack 113: it is no protection any more. The buttons
	// "Пересчитать" and "Проверить все туннели" and the check inside the
	// tunnel replace it with what they found.
	Manual bool
	// Inner is true when the check inside the raised tunnel lowered Max.
	// Pack 113: only for a tunnel that goes straight out.
	Inner bool
	// Inside is what the check inside found for this tunnel inside
	// another one (pack 113): the name of the tunnel underneath and how
	// many bytes more than the counting this tunnel loses inside it.
	Inside map[string]int `json:",omitempty"`
	// Failed is true when neither the server nor the spare address
	// answered. The raise does not try again; the button does.
	Failed bool
	// Target is the address that answered.
	Target string
	When   time.Time
}

// Network is one network with the numbers found in it.
type Network struct {
	Adapter string
	Gateway string
	Tunnels map[string]Entry
}

// Book is the whole file.
type Book struct {
	Networks map[string]*Network
}

// Here is the network the machine is in right now.
type Here struct {
	Key     string
	Adapter string
	Gateway string
	// Index is the interface index of the adapter, Local4 and Local6 its
	// addresses. A check leaves through this adapter and nothing else.
	Index  uint32
	Local4 net.IP
	Local6 net.IP
}

// Text is the line the MTU tab shows above the table.
func (h Here) Text() string {
	if len(h.Key) == 0 {
		return ""
	}
	if len(h.Gateway) == 0 {
		return h.Adapter
	}
	return h.Adapter + ", \u0448\u043b\u044e\u0437 " + h.Gateway
}

var bookMu sync.Mutex

// path is Data\mtu.json, or "" when the data folder is not there.
func path() string {
	root, err := conf.ChainDataDirIfPresent()
	if err != nil || len(root) == 0 {
		return ""
	}
	return filepath.Join(root, "mtu.json")
}

// load reads the file. A missing or broken file is an empty book: the
// numbers are found again at the next raise, nothing else depends on them.
func load() *Book {
	b := &Book{Networks: make(map[string]*Network)}
	p := path()
	if len(p) == 0 {
		return b
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return b
	}
	if json.Unmarshal(raw, b) != nil || b.Networks == nil {
		b.Networks = make(map[string]*Network)
	}
	for _, n := range b.Networks {
		if n != nil && n.Tunnels == nil {
			n.Tunnels = make(map[string]Entry)
		}
	}
	return b
}

// store writes beside the file and renames over it, as settings.json is
// written since pack 68.
func store(b *Book) error {
	p := path()
	if len(p) == 0 {
		return fmt.Errorf("the data folder is not there")
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	temp := p + ".new"
	if err = os.WriteFile(temp, data, 0600); err != nil {
		os.Remove(temp)
		return err
	}
	err = os.Rename(temp, p)
	for try := 2; err != nil && try <= 5; try++ {
		time.Sleep(100 * time.Millisecond)
		err = os.Rename(temp, p)
	}
	if err != nil {
		os.Remove(temp)
	}
	return err
}

func key(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Get gives the entry of one tunnel in the network here.
func Get(here Here, name string) (Entry, bool) {
	if len(here.Key) == 0 {
		return Entry{}, false
	}
	bookMu.Lock()
	defer bookMu.Unlock()
	n := load().Networks[here.Key]
	if n == nil {
		return Entry{}, false
	}
	e, ok := n.Tunnels[key(name)]
	return e, ok
}

// All gives every entry of the network here.
func All(here Here) map[string]Entry {
	out := make(map[string]Entry)
	if len(here.Key) == 0 {
		return out
	}
	bookMu.Lock()
	defer bookMu.Unlock()
	if n := load().Networks[here.Key]; n != nil {
		for k, e := range n.Tunnels {
			out[k] = e
		}
	}
	return out
}

// Put writes the entry of one tunnel in the network here. A manual number
// is kept unless the new entry is manual too or force is set.
func Put(here Here, name string, e Entry, force bool) error {
	if len(here.Key) == 0 {
		return fmt.Errorf("the network of this machine is not known")
	}
	bookMu.Lock()
	defer bookMu.Unlock()
	b := load()
	n := b.Networks[here.Key]
	if n == nil {
		n = &Network{Tunnels: make(map[string]Entry)}
		b.Networks[here.Key] = n
	}
	n.Adapter = here.Adapter
	n.Gateway = here.Gateway
	if old, ok := n.Tunnels[key(name)]; ok && old.Manual && !e.Manual && !force {
		return nil
	} else if ok && e.Inside == nil {
		// Pack 113: a new own maximum does not change what is lost
		// inside another tunnel, so that is kept.
		e.Inside = old.Inside
	}
	if e.When.IsZero() {
		e.When = time.Now()
	}
	n.Tunnels[key(name)] = e
	return store(b)
}

// PutInside writes how many bytes more than the counting name loses
// inside parent (pack 113). Zero removes the note. The own maximum of
// name is not touched.
func PutInside(here Here, name, parent string, extra int) error {
	if len(here.Key) == 0 {
		return fmt.Errorf("the network of this machine is not known")
	}
	bookMu.Lock()
	defer bookMu.Unlock()
	b := load()
	n := b.Networks[here.Key]
	if n == nil {
		n = &Network{Tunnels: make(map[string]Entry)}
		b.Networks[here.Key] = n
	}
	n.Adapter = here.Adapter
	n.Gateway = here.Gateway
	e := n.Tunnels[key(name)]
	inside := make(map[string]int, len(e.Inside)+1)
	for k, v := range e.Inside {
		inside[k] = v
	}
	if extra > 0 {
		inside[key(parent)] = extra
	} else {
		delete(inside, key(parent))
	}
	if len(inside) == 0 {
		inside = nil
	}
	e.Inside = inside
	n.Tunnels[key(name)] = e
	return store(b)
}

// Forget removes one tunnel from the network here.
func Forget(here Here, name string) error {
	bookMu.Lock()
	defer bookMu.Unlock()
	b := load()
	n := b.Networks[here.Key]
	if n == nil {
		return nil
	}
	delete(n.Tunnels, key(name))
	return store(b)
}

// Reset removes every number of the network here. The button "Сбросить
// MTU" does this; the other networks keep theirs.
func Reset(here Here) error {
	bookMu.Lock()
	defer bookMu.Unlock()
	b := load()
	delete(b.Networks, here.Key)
	return store(b)
}

// OwnMax is the own maximum of a tunnel in the network here, or zero.
func OwnMax(here Here, name string) int {
	if e, ok := Get(here, name); ok && e.Max > 0 && !e.Failed {
		return e.Max
	}
	return 0
}

//
// The network here.
//

// isTunnelAdapter is the rule of chainProxyIsTunnelAdapter
// (core/tunnel/chainproxyway.go): a virtual adapter, or one named after a
// tunnel of this program.
func isTunnelAdapter(row *winipcfg.MibIfRow2, names []string) bool {
	switch row.Type {
	case winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel, winipcfg.IfTypeSoftwareLoopback:
		return true
	}
	alias := strings.TrimSpace(row.Alias())
	for _, name := range names {
		if strings.EqualFold(strings.TrimSpace(name), alias) {
			return true
		}
	}
	return false
}

// Find looks for the network the machine is in: the default route with the
// lowest metric on an adapter that is not a tunnel.
func Find() Here {
	names, _ := conf.ListConfigNames()
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return Here{}
	}
	var best *winipcfg.MibIPforwardRow2
	var bestRow *winipcfg.MibIfRow2
	lowest := ^uint32(0)
	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp || isTunnelAdapter(ifrow, names) {
			continue
		}
		iface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}
		if row.Metric+iface.Metric < lowest {
			lowest = row.Metric + iface.Metric
			best = row
			bestRow = ifrow
		}
	}
	if best == nil {
		return Here{}
	}
	h := Here{Adapter: strings.TrimSpace(bestRow.Alias()), Index: best.InterfaceIndex}
	gateway := best.NextHop.IP()
	if gateway != nil && !gateway.IsUnspecified() {
		h.Gateway = gateway.String()
	}
	h.Local4 = localAddress(best.InterfaceLUID, windows.AF_INET)
	h.Local6 = localAddress(best.InterfaceLUID, windows.AF_INET6)
	mac := gatewayMAC(best.InterfaceLUID, gateway)
	guid := ""
	if g, err := best.InterfaceLUID.GUID(); err == nil {
		guid = g.String()
	}
	h.Key = strings.ToLower(guid + "|" + h.Gateway + "|" + mac)
	return h
}

// localAddress is the first usable address of the adapter in one family.
func localAddress(luid winipcfg.LUID, family winipcfg.AddressFamily) net.IP {
	rows, err := winipcfg.GetUnicastIPAddressTable(family)
	if err != nil {
		return nil
	}
	for i := range rows {
		if rows[i].InterfaceLUID != luid {
			continue
		}
		ip := rows[i].Address.IP()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if family == windows.AF_INET6 && (ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast()) {
			continue
		}
		return append(net.IP(nil), ip...)
	}
	return nil
}

var procGetIpNetEntry2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpNetEntry2")

// mibIPNetRow2 is MIB_IPNET_ROW2 of netioapi.h, 88 bytes.
type mibIPNetRow2 struct {
	Address               winipcfg.RawSockaddrInet
	InterfaceIndex        uint32
	InterfaceLUID         winipcfg.LUID
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint8
	_                     [3]byte
	ReachabilityTime      uint32
}

// gatewayMAC is the hardware address of the gateway as text, or "" when
// Windows does not know it.
func gatewayMAC(luid winipcfg.LUID, gateway net.IP) string {
	if gateway == nil || gateway.IsUnspecified() {
		return ""
	}
	var row mibIPNetRow2
	if row.Address.SetIP(gateway, 0) != nil {
		return ""
	}
	row.InterfaceLUID = luid
	if r, _, _ := procGetIpNetEntry2.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return ""
	}
	n := int(row.PhysicalAddressLength)
	if n <= 0 || n > len(row.PhysicalAddress) {
		return ""
	}
	return net.HardwareAddr(row.PhysicalAddress[:n]).String()
}

//
// The MTU inside a stack.
//

// Overhead is what a tunnel adds to every packet: 60 bytes for a server
// with an IPv4 address, 80 for IPv6, and its S4.
func Overhead(c *conf.Config) int {
	overhead := 60
	for i := range c.Peers {
		host := strings.Trim(strings.TrimSpace(c.Peers[i].Endpoint.Host), "[]")
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			overhead = 80
		}
	}
	return overhead + int(c.Interface.TransportPacketJunkSize)
}

// FromPath turns the largest packet that got through outside into the own
// maximum of the tunnel.
func FromPath(path int, c *conf.Config) int {
	mtu := path - Overhead(c)
	if mtu < Floor {
		mtu = Floor
	}
	return mtu
}

// viaEntry is the part of settings.json the stack is read from.
type viaEntry struct {
	ProxyVia       bool
	ProxyViaTunnel string
	Proxy2         bool
	Proxy2Port     int
}

// viaBook reads the "through a tunnel" boxes of every tunnel.
func viaBook() map[string]viaEntry {
	root, err := conf.ChainDataDirIfPresent()
	if err != nil || len(root) == 0 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(root, "settings.json"))
	if err != nil {
		return nil
	}
	var b struct {
		Tunnels map[string]viaEntry
	}
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	out := make(map[string]viaEntry, len(b.Tunnels))
	for name, e := range b.Tunnels {
		out[key(name)] = e
	}
	return out
}

// Proxy2Wanted answers whether the pair of this hidden hop asks for the
// second proxy through it, and on which port (pack 112, point 5).
func Proxy2Wanted(hop string) (bool, int) {
	if !conf.ChainIsHiddenHopName(hop) {
		return false, 0
	}
	pair := strings.TrimSuffix(key(hop), conf.ChainHiddenSuffix)
	if strings.EqualFold(key(hop), conf.ChainLegacyOuter) {
		pair = key(conf.ChainLegacyInner)
	}
	e, ok := viaBook()[pair]
	if !ok || !e.Proxy2 {
		return false, 0
	}
	return true, e.Proxy2Port
}

// Step is one tunnel of a stack, from the bottom up.
type Step struct {
	Name string
	// Own is the own maximum, zero when not known; OwnFrom says where it
	// came from: "check", "inner", "manual", "config", "default".
	Own     int
	OwnFrom string
	// MTU is what the tunnel runs with in this stack.
	MTU int
	// Parent is the tunnel below, "" at the bottom; Overhead is what this
	// tunnel adds inside the parent.
	Parent   string
	Overhead int
	// Extra is what the check inside found this tunnel loses inside this
	// very parent on top of Overhead (pack 113).
	Extra int
}

const maxDepth = 8

// parentOf is the tunnel below name: the hidden hop it pins to, or the
// tunnel it is set to go through.
func parentOf(c *conf.Config, book map[string]viaEntry) string {
	if pin := strings.TrimSpace(c.Interface.PinEndpointVia); conf.ChainIsHiddenHopName(pin) {
		return pin
	}
	if len(strings.TrimSpace(c.Interface.PinEndpointVia)) != 0 {
		// A hidden hop pins to the physical adapter, which is no tunnel.
		return ""
	}
	e, ok := book[key(c.Name)]
	if !ok || !e.ProxyVia {
		return ""
	}
	parent := strings.TrimSpace(e.ProxyViaTunnel)
	if conf.ChainIsHiddenHopName(parent) {
		return ""
	}
	return parent
}

// Stack counts the MTU of name and of every tunnel underneath it, the
// bottom first. The last step is name itself.
func Stack(here Here, name string) []Step {
	book := viaBook()
	var names []string
	var configs []*conf.Config
	seen := make(map[string]bool)
	at := strings.TrimSpace(name)
	for i := 0; i < maxDepth && len(at) != 0 && !seen[key(at)]; i++ {
		seen[key(at)] = true
		c, err := conf.LoadFromName(at)
		if err != nil {
			break
		}
		names = append([]string{at}, names...)
		configs = append([]*conf.Config{c}, configs...)
		at = parentOf(c, book)
	}
	entries := All(here)
	steps := make([]Step, len(names))
	for i := range names {
		c := configs[i]
		s := Step{Name: names[i], Overhead: Overhead(c)}
		if e, ok := entries[key(names[i])]; ok && e.Max > 0 && !e.Failed {
			s.Own = e.Max
			switch {
			case e.Manual:
				s.OwnFrom = "manual"
			case e.Inner:
				s.OwnFrom = "inner"
			default:
				s.OwnFrom = "check"
			}
		}
		if i == 0 {
			switch {
			case s.Own > 0:
				s.MTU = s.Own
			case c.Interface.MTU > 0:
				s.MTU = int(c.Interface.MTU)
				s.OwnFrom = "config"
			default:
				s.MTU = DefaultMTU
				s.OwnFrom = "default"
			}
		} else {
			s.Parent = names[i-1]
			if e, ok := entries[key(names[i])]; ok {
				s.Extra = e.Inside[key(s.Parent)]
			}
			s.MTU = steps[i-1].MTU - s.Overhead - s.Extra
			if s.Own > 0 && s.Own < s.MTU {
				s.MTU = s.Own
			}
			if s.MTU < Floor {
				s.MTU = Floor
			}
		}
		steps[i] = s
	}
	return steps
}

// Effective is the MTU name runs with right now, with the steps below it.
// Zero means the tunnel is not known.
func Effective(here Here, name string) (int, []Step) {
	steps := Stack(here, name)
	if len(steps) == 0 {
		return 0, nil
	}
	return steps[len(steps)-1].MTU, steps
}

// Line writes a stack for the log: "WARPv2_84 1420 (check) > ru-central
// 1348 (1420 - 72)".
func Line(steps []Step) string {
	parts := make([]string, 0, len(steps))
	for i, s := range steps {
		if i == 0 {
			parts = append(parts, fmt.Sprintf("%s %d (%s)", s.Name, s.MTU, s.OwnFrom))
			continue
		}
		part := fmt.Sprintf("%s %d (%d - %d", s.Name, s.MTU, steps[i-1].MTU, s.Overhead)
		if s.Extra > 0 {
			part += fmt.Sprintf(" - %d found inside %s", s.Extra, s.Parent)
		}
		if s.Own > 0 && s.Own == s.MTU && s.Own < steps[i-1].MTU-s.Overhead-s.Extra {
			part += fmt.Sprintf(", own maximum %d from %s", s.Own, s.OwnFrom)
		}
		parts = append(parts, part+")")
	}
	return strings.Join(parts, " > ")
}

// Names lists the tunnel names in the book of the network here, sorted.
func Names(here Here) []string {
	all := All(here)
	out := make([]string, 0, len(all))
	for k := range all {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
