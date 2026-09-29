//go:build windows

/* AwgChain - patch 8: chain ordering inside the manager.
 *
 * Until now the order of the hops lived in awgchain.bat: it created hop 1,
 * waited, pinned a route, then created hop 2. The graphical interface knew
 * nothing about that, so a click on hop 2 started a tunnel with no way out.
 *
 * Patch 8 moves the ordering into the manager, which is the one component
 * both the interface and the command line talk to:
 *
 *   starting a hop  -> every hop underneath it is raised first, deepest
 *                      first, and we wait for each one to handshake
 *   stopping a hop  -> every hop riding on top of it is torn down first
 *
 * The relationship is read from the PinEndpointVia field of patch 1, so no
 * hop list is hard-coded here. A tunnel whose PinEndpointVia names a physical
 * adapter (hop 1 pins to Ethernet) has no parent and behaves as before.
 */

package manager

import (
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	chainMaxDepth     = 4
	chainHopUpTimeout = 45 * time.Second
	chainPollInterval = time.Second
)

// chainParentOfConfig returns the name of the tunnel this config rides on, or
// an empty string when PinEndpointVia points at something that is not another
// tunnel of ours (a physical adapter, typically).
func chainParentOfConfig(c *conf.Config) string {
	if c == nil {
		return ""
	}
	via := strings.TrimSpace(c.Interface.PinEndpointVia)
	if via == "" {
		return ""
	}
	names, err := conf.ListConfigNames()
	if err != nil {
		return ""
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimSpace(n), via) {
			return n
		}
	}
	return ""
}

// chainParentName is the same question asked with only a name in hand.
func chainParentName(name string) string {
	c, err := conf.LoadFromName(name)
	if err != nil {
		return ""
	}
	return chainParentOfConfig(c)
}

// chainChildNames lists the tunnels that ride on this one.
func chainChildNames(name string) []string {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(name)
	children := make([]string, 0, len(names))
	for _, n := range names {
		if strings.EqualFold(n, name) {
			continue
		}
		c, err := conf.LoadFromName(n)
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(c.Interface.PinEndpointVia), trimmed) {
			children = append(children, n)
		}
	}
	return children
}

// chainHopHandshook asks the running tunnel over UAPI whether it has talked
// to its peer yet. A hop with no handshake is not a usable path for the hop
// above it, so we wait for this before moving on.
func (s *ManagerService) chainHopHandshook(name string) bool {
	c, err := s.RuntimeConfig(name)
	if err != nil || c == nil {
		return false
	}
	for i := range c.Peers {
		if !c.Peers[i].LastHandshakeTime.IsEmpty() {
			return true
		}
	}
	return false
}

func (s *ManagerService) chainWaitForHop(name string) error {
	return s.chainWaitForHopTimeout(name, chainHopUpTimeout)
}

// chainWaitForHopTimeout is the same wait, with the deadline chosen by the
// caller. Pack 67: the boot raise gives its first tries 15 seconds instead of
// the full 45, so five quick tries cost a minute and a quarter, not four
// minutes.
func (s *ManagerService) chainWaitForHopTimeout(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := s.State(name)
		if err == nil && state == TunnelStarted && s.chainHopHandshook(name) {
			log.Printf("[%s] Chain hop is up and handshook, carrying on", name)
			return nil
		}
		time.Sleep(chainPollInterval)
	}
	// Pack 82: shown in a window, so Russian. The log stays English.
	return fmt.Errorf("\u0417\u0432\u0435\u043d\u043e \u0446\u0435\u043f\u043e\u0447\u043a\u0438 %s \u043d\u0435 \u0443\u0441\u043f\u0435\u043b\u043e \u043e\u0431\u043c\u0435\u043d\u044f\u0442\u044c\u0441\u044f \u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u0435\u043c", name)
}

// chainStartParents raises everything underneath the named tunnel.
func (s *ManagerService) chainStartParents(name string, depth int) error {
	if depth >= chainMaxDepth {
		return nil
	}
	parent := chainParentName(name)
	if parent == "" {
		return nil
	}
	state, err := s.State(parent)
	if err == nil && state == TunnelStarted && s.chainHopHandshook(parent) {
		return nil
	}
	if err == nil && (state == TunnelStarted || state == TunnelStarting) {
		log.Printf("[%s] Chain: waiting for the hop underneath (%s)", name, parent)
		return s.chainWaitForHop(parent)
	}
	log.Printf("[%s] Chain: raising the hop underneath first (%s)", name, parent)
	err = s.chainStartHopWithRetry(parent)
	if err != nil {
		return fmt.Errorf("\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u043d\u044f\u0442\u044c \u0437\u0432\u0435\u043d\u043e \u0446\u0435\u043f\u043e\u0447\u043a\u0438 %s: %v", parent, err)
	}
	return s.chainWaitForHop(parent)
}

// chainStopChildren tears down everything riding on the named tunnel. It uses
// UninstallTunnel directly rather than ManagerService.Stop, so that the hook
// patch 8 puts in Stop cannot call back into itself.
func (s *ManagerService) chainStopChildren(name string, depth int) {
	if depth >= chainMaxDepth {
		return
	}
	for _, child := range chainChildNames(name) {
		state, err := s.State(child)
		if err == nil && state == TunnelStopped {
			continue
		}
		log.Printf("[%s] Chain: stopping the hop on top first (%s)", name, child)
		s.chainStopChildren(child, depth+1)
		err = UninstallTunnel(child)
		if err != nil && err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			log.Printf("[%s] Chain: could not stop %s: %v", name, child, err)
		}
	}
}

// ---------------------------------------------------------------------------
// patch 16: taking the chain down takes the hidden hop with it.
//
// Patch 8 only walked upwards: stopping a hop dropped whatever rode on top of
// it. Turning off the visible tunnel of a pair therefore left the outer WARP
// hop running on its own. A hidden hop is of no use by itself, so once the
// tunnel riding on it is down, and nothing else rides on it, it goes too.
// ---------------------------------------------------------------------------

// chainHiddenParentOf returns the hidden outer hop this tunnel rides on, or an
// empty string when the hop underneath is a tunnel the user drives directly.
func chainHiddenParentOf(name string) string {
	parent := chainParentName(name)
	if parent == "" {
		return ""
	}
	if !conf.ChainIsHiddenHopName(parent) {
		return ""
	}
	return parent
}

// chainParentStillNeeded reports whether another tunnel riding on this hop is
// still up or coming up, in which case the hop has to stay where it is.
func (s *ManagerService) chainParentStillNeeded(parent string, except string) bool {
	for _, child := range chainChildNames(parent) {
		if strings.EqualFold(child, except) {
			continue
		}
		state, err := s.State(child)
		if err != nil {
			continue
		}
		if state == TunnelStarted || state == TunnelStarting {
			return true
		}
	}
	return false
}

// chainStopHiddenParents drops the hidden hops underneath a chain tunnel. It
// uses UninstallTunnel directly, the same way chainStopChildren does, so the
// hook in Stop cannot call back into itself.
func (s *ManagerService) chainStopHiddenParents(name string, depth int) {
	if depth >= chainMaxDepth {
		return
	}
	parent := chainHiddenParentOf(name)
	if parent == "" {
		return
	}
	state, err := s.State(parent)
	if err == nil && state == TunnelStopped {
		return
	}
	if s.chainParentStillNeeded(parent, name) {
		log.Printf("[%s] Chain: the hop underneath (%s) still carries another tunnel, so it stays up", name, parent)
		return
	}
	log.Printf("[%s] Chain: the hidden hop underneath (%s) goes down as well", name, parent)
	err = UninstallTunnel(parent)
	if err != nil && err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		log.Printf("[%s] Chain: could not stop %s: %v", name, parent, err)
	}
	s.chainStopHiddenParents(parent, depth+1)
}
