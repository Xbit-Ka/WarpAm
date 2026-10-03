//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 89: the watch over a tunnel that carries only its proxy.
 *
 * What happened on 28 September. The chain was up, Elena carried the proxy,
 * the browser worked through it, and then it stopped. The log of that hour
 * says the rest: at 10:20:43 Elena sent a handshake initiation and received
 * the response, so the agreement with the server was fresh; after that not
 * one "Receiving keepalive packet" ever came again, while our side kept
 * sending them; and from 10:20:53 every connection the proxy tried ended
 * with "nothing answered in time". Raising the tunnel again by hand put it
 * right at once.
 *
 * That is one way silence: the tunnel is up by every measure the program
 * had, and nothing comes back through it. Nobody was watching for it. The
 * guard of the chain follows the chain, and the watch of pack 86 stops at
 * the first handshake, by design, because after that the guard takes over
 * and a proxy tunnel has no guard.
 *
 * So this file watches the receiving side of a tunnel that carries only its
 * proxy. It compares two numbers that the tunnel service already keeps, the
 * bytes received and the bytes sent, and it acts only when our side is
 * clearly asking for something: silence while nothing is being sent is not
 * silence at all, it is an idle tunnel, and no line is written about it.
 *
 * The repair is deliberately the same thing the user did by hand, a stop and
 * a raise of that one tunnel, and it is done at most once in five minutes so
 * a server that is simply down does not turn into a loop of restarts. Every
 * step says so in the log.
 */

package manager

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	// chainProxyWatchStep is how often the counters are read.
	chainProxyWatchStep = 5 * time.Second
	// chainProxyWatchDeaf is the silence that is written into the log.
	chainProxyWatchDeaf = 30 * time.Second
	// chainProxyWatchFix is the silence after which the tunnel is raised
	// again. Three times the first complaint: long enough for a server that
	// is only busy, short enough that a person does not go looking for the
	// browser settings first.
	chainProxyWatchFix = 90 * time.Second
	// chainProxyWatchGap is the shortest time between two repairs.
	chainProxyWatchGap = 5 * time.Minute
	// chainProxyWatchAsked is how many bytes our side has to have sent
	// during the silence before the silence means anything.
	chainProxyWatchAsked = 4096
)

var chainProxyWatching sync.Map

// chainProxyWatchSent is everything this tunnel has sent to its peers.
func chainProxyWatchSent(c *conf.Config) uint64 {
	var total uint64
	for i := range c.Peers {
		total += uint64(c.Peers[i].TxBytes)
	}
	return total
}

// ChainProxyWatchFollow watches one tunnel that carries only its proxy. A
// tunnel of any other kind is left to the guard of the chain.
func ChainProxyWatchFollow(name string) {
	name = strings.TrimSpace(name)
	if len(name) == 0 || ChainIsHiddenHop(name) || !chainLeafIsSeparate(name) {
		return
	}
	key := strings.ToLower(name)
	if _, busy := chainProxyWatching.LoadOrStore(key, true); busy {
		return
	}
	defer chainProxyWatching.Delete(key)

	s := chainSilenceService()
	var (
		lastRx  uint64
		markTx  uint64
		rxMoved time.Time
		said    bool
		fixed   time.Time
	)

	for {
		time.Sleep(chainProxyWatchStep)

		state, err := s.State(name)
		if err != nil || state != TunnelStarted {
			return
		}
		// WarpAm pack 95: a proxy tunnel that is a hop of the chain the
		// guard watches is the guard's, which asks for a handshake before
		// it rebuilds anything. Two watches restarting one tunnel would
		// fight. The counting starts over when the guard lets go.
		if chainWatchedHop(name) {
			lastRx, markTx, rxMoved, said = 0, 0, time.Time{}, false
			continue
		}
		runtime, err := s.RuntimeConfig(name)
		if err != nil || runtime == nil {
			continue
		}
		rx := chainHopReceived(runtime)
		tx := chainProxyWatchSent(runtime)

		if rxMoved.IsZero() || rx > lastRx {
			if said {
				log.Printf("[WarpAm] %s receives again after %d seconds of one way silence", name, int(time.Since(rxMoved).Seconds()))
			}
			lastRx, markTx, rxMoved, said = rx, tx, time.Now(), false
			continue
		}

		deaf := time.Since(rxMoved)
		asked := tx - markTx
		if asked < chainProxyWatchAsked {
			// Nothing worth speaking of was sent, so nothing was expected
			// back. An idle tunnel is not a broken one.
			continue
		}

		if !said && deaf >= chainProxyWatchDeaf {
			said = true
			age := "never"
			if a, ok := chainHandshakeAge(runtime); ok {
				age = fmt.Sprintf("%d seconds old", int(a.Seconds()))
			}
			log.Printf("[WarpAm] %s has received nothing for %d seconds while it sent %d bytes, and its handshake is %s. The agreement with the server holds and the packets are being dropped on the way back, so every connection of the proxy on this tunnel will time out", name, int(deaf.Seconds()), asked, age)
		}

		if deaf >= chainProxyWatchFix && (fixed.IsZero() || time.Since(fixed) >= chainProxyWatchGap) {
			fixed = time.Now()
			log.Printf("[WarpAm] %s carries only its proxy and has been deaf for %d seconds, so it is stopped and raised again, which is what putting it right by hand does", name, int(deaf.Seconds()))
			if err := s.Stop(name); err != nil {
				log.Printf("[WarpAm] %s could not be stopped for the repair: %v", name, err)
				continue
			}
			time.Sleep(2 * time.Second)
			if err := s.Start(name); err != nil {
				log.Printf("[WarpAm] %s could not be raised again after the repair: %v. It stays down until it is raised by hand", name, err)
				return
			}
			log.Printf("[WarpAm] %s is up again after the repair", name)
			lastRx, markTx, rxMoved, said = 0, 0, time.Time{}, false
		}
	}
}

// The failures of the proxy, counted instead of repeated.
//
// The same hour of the log carries thirty three lines that say the same
// thing about thirty three addresses. They are one event, one tunnel that
// stopped receiving, and reading them one by one tells nobody anything. The
// first failure of a run is written in full, the run is then counted and
// reported at most once every fifteen seconds, and the end of the run is
// written down as well, because "it works again" is the line that was
// missing most of all.

const (
	chainProxyFailQuiet = 15 * time.Second
	chainProxyFailApart = 30 * time.Second
)

type chainProxyFailRun struct {
	first time.Time
	last  time.Time
	told  time.Time
	count int
}

var (
	chainProxyFailMu sync.Mutex
	chainProxyFails  = make(map[string]*chainProxyFailRun)
)

// ChainProxyDialFailed writes down one connection the proxy could not make.
func ChainProxyDialFailed(leaf, address string, port uint16, why string) {
	now := time.Now()
	chainProxyFailMu.Lock()
	run, seen := chainProxyFails[leaf]
	if !seen || now.Sub(run.last) > chainProxyFailApart {
		chainProxyFails[leaf] = &chainProxyFailRun{first: now, last: now, told: now, count: 1}
		chainProxyFailMu.Unlock()
		log.Printf("[WarpAm] The proxy of %s could not reach %s:%d through the tunnel: %s", leaf, address, port, why)
		return
	}
	run.last = now
	run.count++
	if now.Sub(run.told) < chainProxyFailQuiet {
		chainProxyFailMu.Unlock()
		return
	}
	since := int(now.Sub(run.told).Seconds())
	count := run.count
	run.told = now
	chainProxyFailMu.Unlock()
	log.Printf("[WarpAm] The proxy of %s could not reach %d addresses in the last %d seconds, the last of them %s:%d: %s", leaf, count, since, address, port, why)
}

// ChainProxyDialWorked ends a run of failures.
func ChainProxyDialWorked(leaf string) {
	chainProxyFailMu.Lock()
	run, seen := chainProxyFails[leaf]
	if !seen {
		chainProxyFailMu.Unlock()
		return
	}
	delete(chainProxyFails, leaf)
	chainProxyFailMu.Unlock()
	log.Printf("[WarpAm] The proxy of %s reaches its addresses again after %d failures over %d seconds", leaf, run.count, int(time.Since(run.first).Seconds()))
}
