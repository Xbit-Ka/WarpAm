//go:build windows

/* AwgChain patch 54 - the window asks the manager about the chain.
 *
 * Everything the chain knows about itself lives in the manager: which hops a
 * chain has, whether they run, and whether the kill switch is armed. The
 * window knew none of that, so the only honest answer was the log or
 * awgchain.bat. One extra IPC call fixes it. The answer carries names and
 * states only, never keys.
 */

package manager

import (
	"encoding/gob"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// ChainStatusMethodType sits far above the upstream method numbers, so a new
// upstream method can never take the same value by accident.
const ChainStatusMethodType MethodType = 100

// ChainHopStatus is one link of the chain.
type ChainHopStatus struct {
	Name   string
	State  TunnelState
	Hidden bool
}

// ChainStatusInfo is the whole picture the panel draws.
type ChainStatusInfo struct {
	Leaf     string
	Hops     []ChainHopStatus
	LockOn   bool
	LockLeaf string
	InProc   bool
	// LeafIsChain says whether the tunnel in Leaf is really a chain of at
	// least two hops. Pack 71: a plain tunnel gets no kill switch at all,
	// and the window used to show it the same line as a chain that is
	// merely waiting for its adapters.
	LeafIsChain bool
	// BootLockOn says that the machine is closed by the lock that is put
	// up before any tunnel exists (paranoid start). Pack 71.
	BootLockOn bool
	// Proxies are the local proxies that are running right now, one per
	// tunnel that asks for one. Pack 74.
	Proxies []ChainProxyInfo
	// ProxyModes says how the proxy of every configured tunnel is set
	// up, by the lower case name of the tunnel. Pack 80: the window
	// marks the rows of the list and the lines of the tray menu with
	// this, and a mark has to be there for a tunnel that is down too,
	// so it cannot be taken from Proxies. Asking the manager about
	// every tunnel one by one would be a pipe call per row, and the
	// window already polls this call every two seconds.
	ProxyModes map[string]string
}

// The three ways a tunnel can be set up, as ProxyModes reports them.
const (
	// ChainProxyModeNone is a tunnel with no proxy at all.
	ChainProxyModeNone = ""
	// ChainProxyModeWith is a tunnel that works as usual and carries a
	// proxy as an extra door into itself.
	ChainProxyModeWith = "with"
	// ChainProxyModeOnly is a tunnel that carries nothing but its proxy:
	// no default route, no system DNS, the address of the machine does
	// not change.
	ChainProxyModeOnly = "only"
	// Pack 98: the same two, when the proxy also listens on the local
	// network. An older window does not know them and shows no mark.
	ChainProxyModeWithLAN = "with-lan"
	ChainProxyModeOnlyLAN = "only-lan"
)

// chainProxyModes reads the proxy setting of every tunnel there is.
func chainProxyModes() map[string]string {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil
	}
	modes := make(map[string]string, len(names))
	for _, name := range names {
		settings := ChainSettingsFor(name)
		if !settings.Proxy {
			continue
		}
		mode := ChainProxyModeWith
		if settings.ProxySplit {
			mode = ChainProxyModeOnly
		}
		if settings.Bind() == ChainProxyBindLAN {
			if mode == ChainProxyModeOnly {
				mode = ChainProxyModeOnlyLAN
			} else {
				mode = ChainProxyModeWithLAN
			}
		}
		modes[strings.ToLower(strings.TrimSpace(name))] = mode
	}
	return modes
}

// chainLockLeafName tells which chain the kill switch is holding.
func chainLockLeafName() string {
	chainLockMu.Lock()
	defer chainLockMu.Unlock()
	return chainLockLeaf
}

// chainPickLeaf finds the visible tunnel of a chain: the one that owns a
// hidden hop. A chain that is not stopped wins over a stopped one.
func (s *ManagerService) chainPickLeaf() string {
	tunnels, err := s.Tunnels()
	if err != nil {
		return ""
	}
	known := make(map[string]bool, len(tunnels))
	for _, t := range tunnels {
		known[strings.ToLower(t.Name)] = true
	}
	best := ""
	for _, t := range tunnels {
		if conf.ChainIsHiddenHopName(t.Name) {
			continue
		}
		if !known[strings.ToLower(conf.ChainHiddenHopName(t.Name))] {
			continue
		}
		if best == "" {
			best = t.Name
		}
		if state, err := s.State(t.Name); err == nil && state != TunnelStopped {
			return t.Name
		}
	}
	return best
}

// ChainStatus is the answer the window gets.
func (s *ManagerService) ChainStatus() ChainStatusInfo {
	info := ChainStatusInfo{
		LockOn:   chainLockIsOn(),
		LockLeaf: chainLockLeafName(),
		// Pack 68: the only engine that locks anything runs in the service.
		InProc:   !chainLockEngineOff(),
		// Pack 71: the lock of the paranoid start stands without a tunnel,
		// and the window has to be able to say so.
		BootLockOn: chainBootLockIsOn(),
		// Pack 74: the local proxies, so the window can show the port and
		// say whether anything can go through it right now.
		Proxies: ChainProxyState(),
		// Pack 80: how every tunnel is set up, so the window can mark
		// the ones that carry a proxy without asking about each of
		// them separately.
		ProxyModes: chainProxyModes(),
	}
	if info.BootLockOn {
		info.LockOn = true
	}
	leaf := info.LockLeaf
	if leaf == "" {
		leaf = s.chainPickLeaf()
	}
	if leaf == "" {
		return info
	}
	info.Leaf = leaf
	// Pack 71: two hops or more is a chain; anything else is a plain
	// tunnel and has no kill switch to report.
	info.LeafIsChain = len(chainHopOrder(leaf)) >= 2
	for _, name := range chainHopOrder(leaf) {
		state, err := s.State(name)
		if err != nil {
			state = TunnelUnknown
		}
		info.Hops = append(info.Hops, ChainHopStatus{
			Name:   name,
			State:  state,
			Hidden: conf.ChainIsHiddenHopName(name),
		})
	}
	return info
}

// chainServeStatus is the server side of the call. ipc_server.go calls it from
// its switch, so the patch touches upstream code in exactly one place.
func (s *ManagerService) chainServeStatus(encoder *gob.Encoder) error {
	return encoder.Encode(s.ChainStatus())
}

// IPCClientChainStatus is the client side of the call.
func IPCClientChainStatus() (info ChainStatusInfo, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(ChainStatusMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&info)
	return
}
