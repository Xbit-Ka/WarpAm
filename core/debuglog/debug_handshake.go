/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110, debug feature: the first seconds of the peers.
 *
 * The ordinary log says when a handshake was sent and when the answer
 * came. It does not say whether anything went through in between. This
 * feature reads the peers every 100 ms for the first 20 seconds after the
 * start and writes every change of the handshake time and of the bytes
 * sent and received, so a lost packet and a slow server look different.
 *
 * Point: "tunnel-ready" (name string, get func() (string, error)). get is
 * the IpcGet of the engine.
 */

package debuglog

import (
	"bufio"
	"fmt"
	"strings"
	"time"
)

const (
	peerTick      = 100 * time.Millisecond
	peerWatch     = 20 * time.Second
	peerAfterDone = 3 * time.Second
)

func init() {
	Register("handshake", true, func() {
		Listen("tunnel-ready", tunnelReady)
	})
}

type peerState struct {
	handshake string
	tx, rx    string
}

func tunnelReady(args ...any) {
	if len(args) < 2 {
		return
	}
	name := fmt.Sprint(args[0])
	get, ok := args[1].(func() (string, error))
	if !ok || get == nil {
		return
	}
	begin := time.Now()
	Go("peer watch", func() {
		seen := map[string]peerState{}
		var doneAt time.Time
		for time.Since(begin) < peerWatch {
			if !doneAt.IsZero() && time.Since(doneAt) > peerAfterDone {
				return
			}
			state, err := get()
			if err != nil {
				Printf("peers %s: could not be read: %v", name, err)
				return
			}
			for key, now := range parsePeers(state) {
				old, known := seen[key]
				if known && old == now {
					continue
				}
				seen[key] = now
				Printf("peers %s: %s handshake %s, sent %s bytes, received %s bytes, %d ms after the start", name, key, now.handshake, now.tx, now.rx, time.Since(begin).Milliseconds())
				if now.handshake != "none" && doneAt.IsZero() {
					doneAt = time.Now()
				}
			}
			time.Sleep(peerTick)
		}
	})
}

// parsePeers reads the answer of IpcGet. The key is shortened the way the
// engine writes it in the log, so the two logs can be matched.
func parsePeers(state string) map[string]peerState {
	out := map[string]peerState{}
	key := ""
	cur := peerState{handshake: "none", tx: "0", rx: "0"}
	flush := func() {
		if key != "" {
			out[key] = cur
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(state))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			key = v
			if len(key) > 8 {
				key = key[:8]
			}
			cur = peerState{handshake: "none", tx: "0", rx: "0"}
		case "last_handshake_time_sec":
			if v != "0" {
				cur.handshake = "at " + v
			}
		case "tx_bytes":
			cur.tx = v
		case "rx_bytes":
			cur.rx = v
		}
	}
	flush()
	return out
}
