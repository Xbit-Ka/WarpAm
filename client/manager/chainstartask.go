//go:build windows

/* WarpAm pack 111: a raise that would switch off a chain asks first.
 *
 * When a new tunnel comes up, every running tunnel whose addresses
 * intersect with it and that no rule keeps is stopped (the loop of Start).
 * That is right while nothing rides on the stopped tunnel. The log of
 * 7 October shows the other case: at 15:43:58 raising ru-central stopped
 * warpam-hop1 and with it warpam, in silence. Had anything gone through
 * warpam, it would have lost its way out without a word.
 *
 * The rule agreed on:
 *
 *   - warpam with its hidden hop warpam-hop1 is one tunnel. Stopping it
 *     on its own is the usual silent stop.
 *   - the window asks only when tunnels that are up go "through" a tunnel
 *     the raise is about to stop.
 *   - the list and the tray ask the same way; there is no "do not ask".
 *   - a raise without a window (boot, repair) asks nobody, as before.
 *
 * The loop of Start is moved here as chainStartScan, so that the question
 * of the window and the stop itself are decided by the very same code.
 * ChainStartVictims runs it quietly for the tunnel and for every tunnel
 * underneath that the raise brings up as well.
 */

package manager

import (
	"encoding/gob"
	"log"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/debuglog"
)

// ChainStartVictimsMethodType comes after 111, ChainGuiLogMethodType.
const ChainStartVictimsMethodType MethodType = 112

// ChainStartVictim is a running tunnel a raise would stop, by the name the
// user knows, with the tunnels that are up and go through it.
type ChainStartVictim struct {
	Name   string
	Riders []string
}

type chainStartVictimsReply struct {
	List []ChainStartVictim
}

// chainStartScan decides which tunnels the raise of c pushes out of the
// way: tt are to be stopped, maybeBusy are among them and may still be
// changing state, running is everything that is up. quiet leaves the log
// alone, for the question of the window.
func (s *ManagerService) chainStartScan(c *conf.Config, tunnelName string, own []string, raisingSeparate, quiet bool) (tt, maybeBusy, running []string) {
	note := func(format string, a ...interface{}) {
		if !quiet {
			log.Printf(format, a...)
		}
	}
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	tt = make([]string, 0, len(trackedTunnels))
	maybeBusy = make([]string, 0, len(trackedTunnels))
	// Pack 81: everything that is up right now, whether it intersects with
	// this config or not. Two tunnels of one account do not have to
	// intersect to be impossible together, so the question below is asked
	// of all of them.
	running = make([]string, 0, len(trackedTunnels))
	for t, state := range trackedTunnels {
		if state != TunnelStopped {
			running = append(running, t)
		}
		c2, err := conf.LoadFromName(t)
		if err != nil || !c.IntersectsWith(c2) {
			// If we can't get the config, assume it doesn't intersect.
			continue
		}
		if chainInOwnBranch(own, t) {
			note("[%s] Keeping \u2018%s\u2019 running: it is a hop of this very chain", c.Name, t)
			continue
		}
		if chainViaKin(tunnelName, t) {
			// WarpAm pack 102: one of the two goes through the other.
			note("[%s] Keeping \u2018%s\u2019 running: one of the two goes through the other", c.Name, t)
			continue
		}
		if chainSiblings(c, c2) {
			// AwgChain: hops of one chain are meant to run together. The inner hop
			// pins its endpoint through the outer one, so the overlap is by design.
			note("[%s] Keeping chain sibling \u2018%s\u2019 running", c.Name, t)
			continue
		}
		if raisingSeparate {
			// Pack 80: the tunnel being raised only carries its own
			// proxy, so it has no claim on anything that is already up.
			note("[%s] Keeping \u2018%s\u2019 running: the tunnel being raised carries only its proxy", c.Name, t)
			continue
		}
		if chainTunnelIsSeparate(t) {
			// Pack 80: and the other way round - a tunnel that carries
			// only its proxy holds no default route, so an ordinary
			// tunnel coming up does not have to push it out of the way.
			note("[%s] Keeping \u2018%s\u2019 running: it carries only its proxy", c.Name, t)
			continue
		}
		if !quiet {
			debuglog.Fire("start-decision", c.Name, t, "is stopped: its addresses intersect and no rule keeps it")
		}
		tt = append(tt, t)
		// Pack 68 (F1): the tracker is only a hint. Unknown means "not
		// seen yet", which is the normal state right after the service
		// starts, so it is checked with the service manager below
		// instead of refusing the raise on the spot.
		if len(t) > 0 && (state == TunnelStarting || state == TunnelStopping || state == TunnelUnknown) {
			maybeBusy = append(maybeBusy, t)
		}
	}
	return tt, maybeBusy, running
}

// chainStartRaiseList is the tunnel and every tunnel underneath it that is
// not up yet: the hidden hop it pins to and the tunnel it goes through,
// and theirs in turn. Start raises all of them.
func (s *ManagerService) chainStartRaiseList(name string) []string {
	list := []string{name}
	seen := map[string]bool{strings.ToLower(name): true}
	for i := 0; i < len(list) && len(list) < chainMaxDepth*4; i++ {
		for _, p := range []string{chainParentName(list[i]), chainViaParentName(list[i])} {
			if len(p) == 0 || seen[strings.ToLower(p)] {
				continue
			}
			seen[strings.ToLower(p)] = true
			if state, err := s.State(p); err == nil && state == TunnelStarted {
				continue
			}
			list = append(list, p)
		}
	}
	return list
}

func chainNameIn(list []string, name string) bool {
	for _, n := range list {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// ChainStartVictims lists the running tunnels the raise of name would stop
// and that other tunnels go through. A tunnel nothing goes through is left
// out: it is stopped in silence, as before. Nothing is changed here.
func (s *ManagerService) ChainStartVictims(name string) []ChainStartVictim {
	raising := s.chainStartRaiseList(name)
	members := s.chainViaMembers()
	seen := make(map[string]bool)
	var out []ChainStartVictim
	for _, r := range raising {
		c, err := conf.LoadFromName(r)
		if err != nil {
			continue
		}
		tt, _, _ := s.chainStartScan(c, r, chainOwnBranch(r), chainTunnelIsSeparate(r), true)
		for _, t := range tt {
			if chainNameIn(raising, t) {
				continue
			}
			if state, err := s.State(t); err != nil || (state != TunnelStarted && state != TunnelStarting) {
				continue
			}
			// warpam and warpam-hop1 are one tunnel for the user.
			shown := chainShownName(t)
			if seen[strings.ToLower(shown)] {
				continue
			}
			seen[strings.ToLower(shown)] = true
			var riders []string
			for _, m := range ChainViaRiders(shown, members) {
				if !chainNameIn(raising, m.Name) {
					riders = append(riders, m.Name)
				}
			}
			if len(riders) == 0 {
				continue
			}
			out = append(out, ChainStartVictim{Name: shown, Riders: riders})
		}
	}
	return out
}

func (s *ManagerService) chainServeStartVictims(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var name string
	if err := decoder.Decode(&name); err != nil {
		return err
	}
	reply := chainStartVictimsReply{List: s.ChainStartVictims(name)}
	if err := encoder.Encode(reply); err != nil {
		return err
	}
	return encoder.Encode(errToString(nil))
}

// IPCClientChainStartVictims asks the manager what the raise of name would
// switch off together with what goes through it.
func IPCClientChainStartVictims(name string) ([]ChainStartVictim, error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	if err := rpcEncoder.Encode(ChainStartVictimsMethodType); err != nil {
		return nil, err
	}
	if err := rpcEncoder.Encode(name); err != nil {
		return nil, err
	}
	var reply chainStartVictimsReply
	if err := rpcDecoder.Decode(&reply); err != nil {
		return nil, err
	}
	return reply.List, rpcDecodeError()
}
