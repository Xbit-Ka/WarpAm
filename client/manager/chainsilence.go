//go:build windows

/* AwgChain pack 86: the line that says the server is silent.
 *
 * On the night of 26 September the chain was rebuilt over and over, and the
 * log of that night never once said the plain thing that was happening: the
 * hop was sending handshake initiations and nothing was coming back. The
 * guard knew it, because a hop with no handshake fails its check, but the
 * only words written were about a repair, so every reading of that log ended
 * in a guess.
 *
 * This watch exists to write that one sentence, and to tell three states
 * apart that the guard writes almost alike. They mean entirely different
 * things:
 *
 *   * no handshake at all since the tunnel was started. Almost always the
 *     configuration: a wrong port, a wrong key, or obfuscation parameters
 *     the server does not expect. This is the case that gets the
 *     fingerprint of the configuration, the size of its initiation packet
 *     and the comparison with everything that ever answered this server.
 *   * a handshake happened and then went stale. That is a lost link, not a
 *     wrong configuration, and it is the guard's business.
 *   * a handshake happened and no byte ever came back. The agreement holds
 *     and the traffic does not flow, which is a third thing again.
 *
 * A tunnel that is answered gets one quiet line and its fingerprint is
 * written into the memory of chainfingermem.go, so the next silence on that
 * server has something to be compared with. Nothing here changes the chain:
 * it only speaks.
 */

package manager

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	// chainSilenceFirst is how long a fresh tunnel is given before the
	// silence is called out. A handshake over a working link comes back in
	// well under a second; ten seconds is already two retries of the
	// protocol and covers a slow hop underneath.
	chainSilenceFirst = 10 * time.Second

	// chainSilenceRepeat is how often it is said again while nothing comes
	// back.
	chainSilenceRepeat = 30 * time.Second

	// chainSilenceStep is how often the state is read.
	chainSilenceStep = 2 * time.Second

	// chainSilenceGiveUp is when the watch stops talking. By then the guard
	// has long taken the case over and the repair lines carry the story.
	chainSilenceGiveUp = 5 * time.Minute

	// chainSilenceRxWait is how long a handshaken tunnel may stay without a
	// single received byte before that is said out loud. It is the third
	// state, and it is not the same trouble as a silent handshake.
	chainSilenceRxWait = 20 * time.Second
)

// chainSilenceEndpoints names where the initiations of this tunnel are going.
func chainSilenceEndpoints(name string) string {
	stored, err := chainSilenceService().RuntimeConfig(name)
	if err != nil || stored == nil {
		return ""
	}
	parts := make([]string, 0, len(stored.Peers))
	for i := range stored.Peers {
		endpoint := stored.Peers[i].Endpoint.String()
		if len(strings.TrimSpace(endpoint)) == 0 {
			continue
		}
		parts = append(parts, endpoint)
	}
	return strings.Join(parts, ", ")
}

// chainSilenceService is the handle the watch asks its questions through.
// The manager answers its own pipes, exactly as the start-up raise does.
func chainSilenceService() *ManagerService {
	return &ManagerService{}
}

// chainSilenceStored is the configuration as it lies on the disk. The
// fingerprint has to come from there and not from the runtime state, which
// carries the counters of the adapter and not the agreement with the
// server.
func chainSilenceStored(name string) *conf.Config {
	stored, err := conf.LoadFromName(name)
	if err != nil {
		return nil
	}
	return stored
}

// chainSilenceSayConfig writes what this tunnel is asking the server for.
// It is the part that was missing on the weekend of 27 September: the
// fingerprint, the size of the initiation packet, and what the same server
// answered before.
func chainSilenceSayConfig(name string) {
	stored := chainSilenceStored(name)
	if stored == nil {
		log.Printf("[WarpAm] %s: its configuration cannot be read, so there is no fingerprint to report", name)
		return
	}
	log.Printf("[WarpAm] %s: %s, initiation packet %d bytes", name, stored.ChainFingerprintLine(), ChainFingerInitSize(stored))
	for _, line := range ChainFingerCompareLines(name, stored) {
		log.Printf("[WarpAm] %s: %s", name, line)
	}
}

// chainSilenceWatching holds the tunnels that are being watched right now.
//
// Pack 87: the watch is started from the tracker, on the step to the state
// "started". A service that reports started, then unknown for a moment,
// then started again takes that step twice, and the log of 28 September
// shows the result: "Elena handshook 0 seconds after it was started" and
// the line of the remembered fingerprint printed twice within the same
// millisecond. One watch per tunnel from here on.
var chainSilenceWatching sync.Map

// ChainSilenceFollow watches one tunnel that has just been started.
func ChainSilenceFollow(name string) {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return
	}
	key := strings.ToLower(name)
	if _, busy := chainSilenceWatching.LoadOrStore(key, true); busy {
		return
	}
	defer chainSilenceWatching.Delete(key)
	s := chainSilenceService()
	started := time.Now()
	var said time.Time
	var handshook time.Time
	saidRx := false

	for {
		time.Sleep(chainSilenceStep)

		state, err := s.State(name)
		if err != nil || state != TunnelStarted {
			// The tunnel is gone or on its way somewhere else. Whoever took
			// it there writes the lines from here on.
			return
		}
		runtime, err := s.RuntimeConfig(name)
		if err != nil || runtime == nil {
			continue
		}

		if age, ok := chainHandshakeAge(runtime); ok {
			// State two and three begin here: the agreement with the server
			// holds. The first handshake is reported once and remembered,
			// because a fingerprint that was answered is the only yardstick
			// the next silence on this server will have.
			if handshook.IsZero() {
				handshook = time.Now()
				if !said.IsZero() {
					log.Printf("[WarpAm] %s finally got a handshake after %d seconds of silence", name, int(time.Since(started).Seconds()))
				} else {
					log.Printf("[WarpAm] %s handshook %d seconds after it was started", name, int(time.Since(started).Seconds()-age.Seconds()))
				}
				if stored := chainSilenceStored(name); stored != nil {
					ChainFingerRemember(name, stored)
					log.Printf("[WarpAm] %s: the answered fingerprint %s is remembered for this server", name, stored.ChainFingerprint())
				}
			}
			// The third state: handshakes come and no byte ever does. Said
			// once, and then this watch is done, because the guard follows
			// the receiving side from here on.
			if chainHopReceived(runtime) != 0 {
				return
			}
			if !saidRx && time.Since(handshook) >= chainSilenceRxWait {
				saidRx = true
				log.Printf("[WarpAm] %s handshakes with its server and has received nothing for %d seconds. The agreement holds, so this is not the configuration: the traffic is being dropped on the way, by a filter of this machine or by the server", name, int(time.Since(handshook).Seconds()))
				return
			}
			continue
		}

		// State one: not a single handshake since the tunnel was started.
		waited := time.Since(started)
		if waited > chainSilenceGiveUp {
			return
		}
		if waited < chainSilenceFirst {
			continue
		}
		if !said.IsZero() && time.Since(said) < chainSilenceRepeat {
			continue
		}
		first := said.IsZero()
		said = time.Now()
		if endpoints := chainSilenceEndpoints(name); len(endpoints) != 0 {
			log.Printf("[WarpAm] %s has been sending handshake initiations to %s for %d seconds and has had no answer. The adapter is up and the packets are leaving, so either they do not reach the server, or the server refuses them: a wrong port, a wrong key, or obfuscation parameters that do not match the ones on the server", name, endpoints, int(waited.Seconds()))
		} else {
			log.Printf("[WarpAm] %s has been sending handshake initiations for %d seconds and has had no answer, and no endpoint is written in its runtime state", name, int(waited.Seconds()))
		}
		// The fingerprint and the comparison are written once, with the
		// first complaint. Repeating them every thirty seconds would bury
		// the log without adding a fact.
		if first {
			chainSilenceSayConfig(name)
		}
	}
}
