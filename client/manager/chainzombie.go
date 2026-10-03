//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 95: a hop that sends and hears nothing back.
 *
 * The night of 30 September: Elena kept a fresh handshake and kept sending,
 * and nothing came back through her, because the server took our transport
 * packets of one length for handshake responses and dropped them. Pack 85
 * only sees a hop whose received counter stands at zero, and that one had
 * received a few keepalives, so the chain was called healthy.
 *
 * A hop is dead here when over 15 seconds it sent more than 3 KB and
 * received at most 160 bytes, about two keepalives. The guard then goes in
 * two steps. First it asks the engine of that hop for a new handshake over
 * the pipe, without touching services, routes or the lock, at most once in
 * 30 seconds per hop, and that does not count as a repair. Ten seconds later
 * it looks again: a hop that did handshake and is still dead is rebuilt from
 * itself, and when the handshake did not come the chain is rebuilt from the
 * lowest dead hop, because the fault is then below.
 */

package manager

import (
	"bufio"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	chainZombieWindow = 15 * time.Second
	chainZombieSent   = 3 * 1024
	chainZombieHeard  = 160
	chainZombieAskGap = 30 * time.Second
	chainZombieWait   = 10 * time.Second
)

type chainZombieSample struct {
	at time.Time
	tx uint64
	rx uint64
}

type chainZombieHop struct {
	samples []chainZombieSample
	dead    bool
	deadAt  time.Time
	asked   time.Time
}

var (
	chainZombieMu   sync.Mutex
	chainZombieHops = make(map[string]*chainZombieHop)
)

// chainZombieTrouble takes one reading of the counters of a running hop and
// answers why it is dead, or "" when it is not.
func chainZombieTrouble(name string, runtime *conf.Config) string {
	key := strings.ToLower(name)
	now := time.Now()
	tx := chainProxyWatchSent(runtime)
	rx := chainHopReceived(runtime)

	chainZombieMu.Lock()
	defer chainZombieMu.Unlock()
	h := chainZombieHops[key]
	if h == nil {
		h = &chainZombieHop{}
		chainZombieHops[key] = h
	}
	// Counters that went back mean the hop was raised again.
	if n := len(h.samples); n > 0 && (tx < h.samples[n-1].tx || rx < h.samples[n-1].rx) {
		h.samples = nil
	}
	h.samples = append(h.samples, chainZombieSample{at: now, tx: tx, rx: rx})
	for len(h.samples) > 1 && now.Sub(h.samples[1].at) >= chainZombieWindow {
		h.samples = h.samples[1:]
	}
	first := h.samples[0]
	span := now.Sub(first.at)
	if span < chainZombieWindow {
		h.dead = false
		return ""
	}
	sent, heard := tx-first.tx, rx-first.rx
	if sent <= chainZombieSent || heard > chainZombieHeard {
		h.dead = false
		return ""
	}
	if !h.dead {
		h.deadAt = now
	}
	h.dead = true
	return fmt.Sprintf("%s sends but hears nothing back: %d bytes out and %d in over %d seconds", name, sent, heard, int(span.Seconds()))
}

// chainZombieIsDead answers whether a hop was found dead in the last reading.
func chainZombieIsDead(name string) bool {
	chainZombieMu.Lock()
	defer chainZombieMu.Unlock()
	h := chainZombieHops[strings.ToLower(name)]
	return h != nil && h.dead && time.Since(h.deadAt) < 4*chainZombieWindow
}

// chainZombieStep is called by the watch for the hop it found broken. It
// answers the hop to repair from, and wait true when the watch should not
// repair anything this round.
func (s *ManagerService) chainZombieStep(leaf, broken string) (string, bool) {
	if len(broken) == 0 || !chainZombieIsDead(broken) {
		return broken, false
	}
	key := strings.ToLower(broken)
	now := time.Now()
	chainZombieMu.Lock()
	h := chainZombieHops[key]
	asked := h.asked
	if asked.IsZero() || now.Sub(asked) >= chainZombieAskGap {
		h.asked = now
		chainZombieMu.Unlock()
		if err := chainAskRehandshake(broken); err != nil {
			log.Printf("[WarpAm] %s sends but hears nothing back, and the new handshake could not be asked for (%v)", broken, err)
		} else {
			log.Printf("[WarpAm] %s sends but hears nothing back, so a new handshake was asked for; nothing is rebuilt for now, the watch looks again in %d seconds", broken, int(chainZombieWait.Seconds()))
		}
		return broken, true
	}
	chainZombieMu.Unlock()
	if now.Sub(asked) < chainZombieWait {
		return broken, true
	}

	handshook := false
	if runtime, err := s.RuntimeConfig(broken); err == nil && runtime != nil {
		if age, ok := chainHandshakeAge(runtime); ok && age < now.Sub(asked) {
			handshook = true
		}
	}
	if handshook {
		log.Printf("[WarpAm] %s did handshake again and still hears nothing back, so it is rebuilt", broken)
		return broken, false
	}
	for _, name := range chainHopOrder(leaf) {
		if chainZombieIsDead(name) {
			if !strings.EqualFold(name, broken) {
				log.Printf("[WarpAm] %s did not handshake again, and %s below it is dead too, so the chain is rebuilt from %s", broken, name, name)
			} else {
				log.Printf("[WarpAm] %s did not handshake again, so it is rebuilt", broken)
			}
			return name, false
		}
	}
	return broken, false
}

// chainAskRehandshake asks the engine of a running tunnel for a new
// handshake with each of its peers. The keys come from the stored config,
// because the runtime one is redacted for a window without elevation.
func chainAskRehandshake(name string) error {
	stored, err := conf.LoadFromName(name)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("set=1\n")
	for i := range stored.Peers {
		fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\nrehandshake=true\n", stored.Peers[i].PublicKey.HexString())
	}
	b.WriteString("\n")

	pipe, err := connectTunnelServicePipe(name)
	if err != nil {
		return err
	}
	pipe.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = pipe.Write([]byte(b.String())); err != nil {
		pipe.Unlock()
		disconnectTunnelServicePipe(name)
		return err
	}
	// The answer is errno=N and an empty line; all of it is read so the
	// next request on this pipe starts clean.
	reader := bufio.NewReader(pipe)
	answer := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			pipe.Unlock()
			disconnectTunnelServicePipe(name)
			return err
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			break
		}
		answer = line
	}
	pipe.Unlock()
	if answer != "errno=0" {
		return fmt.Errorf("the tunnel answered %q", answer)
	}
	return nil
}
