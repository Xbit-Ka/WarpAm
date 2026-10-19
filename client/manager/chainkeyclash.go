//go:build windows

/* WarpAm pack 112: the same key asks "yes or no" instead of refusing.
 *
 * 7 October, 16:52:51: WARPv2_84 was switched on while warpam was up, and
 * the refusal advised to switch the proxy on in the settings of warpam.
 * That proxy goes through the second step of warpam, another account, so
 * the advice could not help. The key of WARPv2_84 is the key of the first
 * step, warpam-hop1.
 *
 * Now the window asks before the raise (113): which running tunnels have
 * the same key as anything the raise brings up, whether that is the first
 * step of a double tunnel, what goes through it and whether its second
 * proxy is on. "Yes" tells the manager (114) that those tunnels may be
 * switched off for this raise; Start then stops them like the tunnels
 * whose addresses intersect. "No" raises nothing. The yes holds for two
 * minutes and only for the tunnels the raise brings up.
 *
 * A raise without a window gets the refusal of chaindupe.go, as before.
 */

package manager

import (
	"encoding/gob"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	ChainKeyClashesMethodType     MethodType = 113
	ChainKeyClashAcceptMethodType MethodType = 114
)

// chainKeyClashHold is how long a "yes" of the window counts.
const chainKeyClashHold = 2 * time.Minute

// ChainKeyClash is one running tunnel with the same key as a tunnel of the
// raise, by the names the user knows.
type ChainKeyClash struct {
	// Raising is the tunnel of the raise; RaisingFirstStep says the key is
	// the key of its first step.
	Raising          string
	RaisingFirstStep bool
	// Other is the running tunnel; OtherFirstStep says the key is the key
	// of its first step, OtherProxy2 that its second proxy is on.
	Other          string
	OtherFirstStep bool
	OtherProxy2    bool
	// RaisingSeparate says the tunnel switched on carries only its proxy.
	RaisingSeparate bool
	// Riders go through Other and go down with it.
	Riders []string
}

type chainKeyClashesReply struct {
	List []ChainKeyClash
}

type chainKeyClashAccept struct {
	Name   string
	Others []string
}

var chainKeyClashYes = struct {
	sync.Mutex
	raising []string
	others  []string
	until   time.Time
}{}

// ChainKeyClashes lists what the raise of name would clash with. Nothing
// is changed here.
func (s *ManagerService) ChainKeyClashes(name string) []ChainKeyClash {
	raising := s.chainStartRaiseList(name)
	members := s.chainViaMembers()
	separate := chainTunnelIsSeparate(name)
	seen := make(map[string]bool)
	var out []ChainKeyClash
	for _, r := range raising {
		c, err := conf.LoadFromName(r)
		if err != nil {
			continue
		}
		own := chainOwnBranch(r)
		tt, _, running := s.chainStartScan(c, r, own, chainTunnelIsSeparate(r), true)
		for _, other := range chainDupeConflicts(c, running, tt, own) {
			if chainNameIn(raising, other) {
				continue
			}
			shown := chainShownName(other)
			if seen[strings.ToLower(shown)] {
				continue
			}
			seen[strings.ToLower(shown)] = true
			clash := ChainKeyClash{
				Raising:          chainShownName(r),
				RaisingFirstStep: conf.ChainIsHiddenHopName(r),
				Other:            shown,
				OtherFirstStep:   conf.ChainIsHiddenHopName(other),
				RaisingSeparate:  separate,
			}
			if clash.OtherFirstStep {
				clash.OtherProxy2, _ = chainProxy2Wanted(other)
			}
			for _, m := range ChainViaRiders(shown, members) {
				if !chainNameIn(raising, m.Name) {
					clash.Riders = append(clash.Riders, m.Name)
				}
			}
			out = append(out, clash)
		}
	}
	return out
}

// chainKeyClashAccepted gives the tunnels of clash the window said yes to
// for the raise of tunnelName.
func chainKeyClashAccepted(tunnelName string, clash []string) []string {
	chainKeyClashYes.Lock()
	defer chainKeyClashYes.Unlock()
	if time.Now().After(chainKeyClashYes.until) || !chainNameIn(chainKeyClashYes.raising, tunnelName) {
		return nil
	}
	var out []string
	for _, other := range clash {
		if chainNameIn(chainKeyClashYes.others, chainShownName(other)) {
			out = append(out, other)
		}
	}
	return out
}

// chainKeyClashStops is asked by Start: the tunnels with the same key the
// window said yes to are stopped like the ones whose addresses intersect.
// The tunnel they ride on goes too: warpam goes with warpam-hop1.
func (s *ManagerService) chainKeyClashStops(c *conf.Config, tunnelName string, running, tt, own []string) []string {
	clash := chainDupeConflicts(c, running, tt, own)
	if len(clash) == 0 {
		return nil
	}
	yes := chainKeyClashAccepted(tunnelName, clash)
	for _, t := range yes {
		log.Printf("[WarpAm] %s is switched off for %s: the same private key, and the window said yes", chainShownName(t), chainShownName(tunnelName))
	}
	return yes
}

func (s *ManagerService) chainServeKeyClashes(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var name string
	if err := decoder.Decode(&name); err != nil {
		return err
	}
	if err := encoder.Encode(chainKeyClashesReply{List: s.ChainKeyClashes(name)}); err != nil {
		return err
	}
	return encoder.Encode(errToString(nil))
}

func (s *ManagerService) chainServeKeyClashAccept(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var ask chainKeyClashAccept
	if err := decoder.Decode(&ask); err != nil {
		return err
	}
	if !s.chainMayChange("Switching off a tunnel with the same key") {
		return encoder.Encode(errToString(nil))
	}
	raising := s.chainStartRaiseList(ask.Name)
	chainKeyClashYes.Lock()
	chainKeyClashYes.raising = raising
	chainKeyClashYes.others = ask.Others
	chainKeyClashYes.until = time.Now().Add(chainKeyClashHold)
	chainKeyClashYes.Unlock()
	log.Printf("[WarpAm] The window said yes: %s may be switched off to raise %s", strings.Join(ask.Others, ", "), ask.Name)
	return encoder.Encode(errToString(nil))
}

// IPCClientChainKeyClashes asks which running tunnels have the same key as
// the raise of name.
func IPCClientChainKeyClashes(name string) ([]ChainKeyClash, error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	if err := rpcEncoder.Encode(ChainKeyClashesMethodType); err != nil {
		return nil, err
	}
	if err := rpcEncoder.Encode(name); err != nil {
		return nil, err
	}
	var reply chainKeyClashesReply
	if err := rpcDecoder.Decode(&reply); err != nil {
		return nil, err
	}
	return reply.List, rpcDecodeError()
}

// IPCClientChainKeyClashAccept tells the manager the window said yes.
func IPCClientChainKeyClashAccept(name string, others []string) error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	if err := rpcEncoder.Encode(ChainKeyClashAcceptMethodType); err != nil {
		return err
	}
	if err := rpcEncoder.Encode(chainKeyClashAccept{Name: name, Others: others}); err != nil {
		return err
	}
	return rpcDecodeError()
}
