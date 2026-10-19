//go:build windows

/* WarpAm pack 112: a chain is not longer than 4 tunnels.
 *
 * Every tunnel in a chain wraps the packets of the one above it into its
 * own: 60 bytes for a server with an IPv4 address, 80 for IPv6, and its
 * S4. With 1420 at the bottom the fourth tunnel is left with about 1204,
 * the fifth with about 1132; with 1280 at the bottom, as WARPv2_84 has
 * now, the fifth is left with less than 1000. So the fifth is refused.
 *
 * The length is the whole chain that would come out: the tunnels below,
 * the tunnel itself and the longest branch of the tunnels that already go
 * through it. A double tunnel counts as 2: its hidden hop takes its share
 * of the MTU as well.
 *
 * The tab asks first (115) and puts the box or the list back; the save of
 * the settings and the raise ask again, for old settings and for raises
 * without a window.
 *
 * WarpAm pack 113: a loop is asked about before the length. On 8.10 the
 * log said "ru-central may not go through 100: the chain would have 6
 * tunnels (ru-central, Elena, 100, ru-central, Elena, 100)", which is true
 * and says nothing: 100 itself goes through ru-central, so the real answer
 * is that the two would go through each other.
 */

package manager

import (
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// ChainLengthCheckMethodType comes after 114, the answer to the key clash.
const ChainLengthCheckMethodType MethodType = 115

// ChainMaxLength is the most tunnels a chain may have.
const ChainMaxLength = 4

type chainLengthAsk struct {
	Name string
	Via  string
}

// chainLengthWeight is 2 for a double tunnel and 1 for the rest.
func chainLengthWeight(name string) int {
	if hop := chainParentName(name); len(hop) != 0 && conf.ChainIsHiddenHopName(hop) {
		return 2
	}
	return 1
}

// chainLengthShown is the name in the list of the message.
func chainLengthShown(name string) string {
	if chainLengthWeight(name) == 2 {
		return name + " (\u0434\u0432\u043e\u0439\u043d\u043e\u0439)"
	}
	return name
}

// chainLengthBelow is the tunnels under via, the bottom first, via last.
func chainLengthBelow(via string) []string {
	var out []string
	seen := make(map[string]bool)
	for at := via; len(at) != 0 && !seen[strings.ToLower(at)] && len(out) < chainMaxDepth*2; at = chainViaParentName(at) {
		seen[strings.ToLower(at)] = true
		out = append([]string{at}, out...)
	}
	return out
}

// chainLengthAbove is the longest branch of the tunnels that go through
// name, the nearest first, with its weight.
func chainLengthAbove(name string, depth int) ([]string, int) {
	if depth > chainMaxDepth*2 {
		return nil, 0
	}
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil, 0
	}
	var best []string
	bestWeight := 0
	for _, n := range names {
		if conf.ChainIsHiddenHopName(n) || strings.EqualFold(n, name) {
			continue
		}
		if !strings.EqualFold(chainViaParentName(n), name) {
			continue
		}
		branch, weight := chainLengthAbove(n, depth+1)
		weight += chainLengthWeight(n)
		if weight > bestWeight {
			best, bestWeight = append([]string{n}, branch...), weight
		}
	}
	return best, bestWeight
}

// chainLengthWith counts the chain name would be in if it went through via
// ("" for straight out). above adds the tunnels that already ride on name.
func chainLengthWith(name, via string, above bool) (int, []string) {
	var list []string
	if len(strings.TrimSpace(via)) != 0 {
		list = chainLengthBelow(via)
	}
	list = append(list, name)
	if above {
		branch, _ := chainLengthAbove(name, 0)
		list = append(list, branch...)
	}
	count := 0
	shown := make([]string, 0, len(list))
	for _, n := range list {
		count += chainLengthWeight(n)
		shown = append(shown, chainLengthShown(n))
	}
	return count, shown
}

// chainLengthLoop answers whether via, or a tunnel under it, goes through
// name. Both the "via" box and the pin of a tunnel count.
func chainLengthLoop(name, via string) bool {
	seen := make(map[string]bool)
	for at := strings.TrimSpace(via); len(at) != 0 && !seen[strings.ToLower(at)]; {
		if strings.EqualFold(at, strings.TrimSpace(name)) {
			return true
		}
		seen[strings.ToLower(at)] = true
		next := chainViaParentName(at)
		if len(next) == 0 {
			next = chainParentName(at)
		}
		at = strings.TrimSpace(next)
	}
	return false
}

// chainLengthLoopText is the Russian text of the window for a loop.
func chainLengthLoopText(name, via string) string {
	return fmt.Sprintf("\u041d\u0435\u043b\u044c\u0437\u044f \u043f\u0443\u0441\u0442\u0438\u0442\u044c %s \u0447\u0435\u0440\u0435\u0437 %s: %s \u0441\u0430\u043c \u0438\u0434\u0451\u0442 \u0447\u0435\u0440\u0435\u0437 %s.", name, via, via, name)
}

// ChainLengthProblem is the Russian text of the window when name may not
// go through via, or "" when it may.
func ChainLengthProblem(name, via string) string {
	if len(strings.TrimSpace(via)) == 0 {
		return ""
	}
	// Pack 113: a loop first, the length only after it.
	if chainLengthLoop(name, via) {
		log.Printf("[WarpAm] %s may not go through %s: %s itself goes through %s", name, via, via, name)
		return chainLengthLoopText(name, via)
	}
	count, list := chainLengthWith(name, via, true)
	if count <= ChainMaxLength {
		return ""
	}
	log.Printf("[WarpAm] %s may not go through %s: the chain would have %d tunnels (%s), %d at most", name, via, count, strings.Join(list, ", "), ChainMaxLength)
	return fmt.Sprintf("\u041d\u0435\u043b\u044c\u0437\u044f \u043f\u0443\u0441\u0442\u0438\u0442\u044c %s \u0447\u0435\u0440\u0435\u0437 %s: \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u0441\u0442\u0430\u043d\u0435\u0442 \u0434\u043b\u0438\u043d\u043d\u0435\u0435 4 \u0442\u0443\u043d\u043d\u0435\u043b\u0435\u0439 (%s). \u041a\u0430\u0436\u0434\u044b\u0439 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043e\u0442\u043d\u0438\u043c\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044c MTU, \u043f\u044f\u0442\u043e\u043c\u0443 \u043c\u0435\u0441\u0442\u0430 \u043f\u043e\u0447\u0442\u0438 \u043d\u0435 \u043e\u0441\u0442\u0430\u0451\u0442\u0441\u044f.",
		name, via, strings.Join(list, ", "))
}

// chainLengthSaveProblem is asked by the save of the settings. Only a new
// or changed via is refused, so that an old long chain does not block the
// save of something else; the raise refuses that one.
func chainLengthSaveProblem(name string, old, now ChainTunnelSettings) string {
	if !now.ProxyVia {
		return ""
	}
	via := strings.TrimSpace(now.ProxyViaTunnel)
	if old.ProxyVia && strings.EqualFold(strings.TrimSpace(old.ProxyViaTunnel), via) {
		return ""
	}
	return ChainLengthProblem(name, via)
}

// chainLengthStartProblem is asked by Start: the tunnels below and the
// tunnel itself, which is what the raise brings up.
func chainLengthStartProblem(name string) error {
	if conf.ChainIsHiddenHopName(name) {
		return nil
	}
	// Pack 113: a loop first, the length only after it.
	if parent := chainViaParentName(name); len(parent) != 0 && chainLengthLoop(name, parent) {
		log.Printf("[WarpAm] %s is not raised: it goes through %s, and %s itself goes through %s", name, parent, parent, name)
		return fmt.Errorf("%s", chainLengthLoopText(name, parent))
	}
	count, list := chainLengthWith(name, chainViaParentName(name), false)
	if count <= ChainMaxLength {
		return nil
	}
	log.Printf("[WarpAm] %s is not raised: its chain has %d tunnels (%s), %d at most", name, count, strings.Join(list, ", "), ChainMaxLength)
	return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c: \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u0434\u043b\u0438\u043d\u043d\u0435\u0435 4 \u0442\u0443\u043d\u043d\u0435\u043b\u0435\u0439 (%s). \u041a\u0430\u0436\u0434\u044b\u0439 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043e\u0442\u043d\u0438\u043c\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044c MTU, \u043f\u044f\u0442\u043e\u043c\u0443 \u043c\u0435\u0441\u0442\u0430 \u043f\u043e\u0447\u0442\u0438 \u043d\u0435 \u043e\u0441\u0442\u0430\u0451\u0442\u0441\u044f.",
		name, strings.Join(list, ", "))
}

// chainIPv6ServerNote writes into the log when a tunnel with a server on
// IPv6 goes through a tunnel that carries no IPv6: such a chain cannot work.
func chainIPv6ServerNote(name string) {
	below := chainLengthBelow(chainViaParentName(name))
	list := append(below, name)
	for i := 1; i < len(list); i++ {
		c, err := conf.LoadFromName(list[i])
		if err != nil {
			continue
		}
		six := false
		for _, p := range c.Peers {
			if ip := net.ParseIP(strings.Trim(strings.TrimSpace(p.Endpoint.Host), "[]")); ip != nil && ip.To4() == nil {
				six = true
			}
		}
		if !six {
			continue
		}
		parent, err := conf.LoadFromName(list[i-1])
		if err != nil {
			continue
		}
		carries := false
		for _, p := range parent.Peers {
			for _, a := range p.AllowedIPs {
				if a.IP.To4() == nil && a.Cidr == 0 {
					carries = true
				}
			}
		}
		if !carries {
			log.Printf("[WarpAm] %s has its server on IPv6, but %s under it carries no IPv6 (no ::/0 in AllowedIPs): this chain will not work", list[i], list[i-1])
		}
	}
}

func (s *ManagerService) chainServeLengthCheck(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var ask chainLengthAsk
	if err := decoder.Decode(&ask); err != nil {
		return err
	}
	if err := encoder.Encode(ChainLengthProblem(ask.Name, ask.Via)); err != nil {
		return err
	}
	return encoder.Encode(errToString(nil))
}

// IPCClientChainLengthCheck asks whether name may go through via. The
// answer is the text for the window, "" when it may.
func IPCClientChainLengthCheck(name, via string) (string, error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	if err := rpcEncoder.Encode(ChainLengthCheckMethodType); err != nil {
		return "", err
	}
	if err := rpcEncoder.Encode(chainLengthAsk{Name: name, Via: via}); err != nil {
		return "", err
	}
	var text string
	if err := rpcDecoder.Decode(&text); err != nil {
		return "", err
	}
	return text, rpcDecodeError()
}
