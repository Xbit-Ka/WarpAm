//go:build windows

/* WarpAm pack 111: three small notes the manager keeps for itself.
 *
 * A final refusal. Some refusals of Start do not change with time: two
 * tunnels with the same private key stay the same two tunnels. The log of
 * 7 October shows warpam-hop1 refused for the key of WARPv2_84 five times
 * in a row, two seconds apart (15:49:28 to 15:49:36), because the retry of
 * a hop took every error for a service that was still busy. Such an error
 * is now wrapped, and the retry gives up at once.
 *
 * A failed raise through another tunnel. 100 goes through Elena, Elena
 * through ru-central. Elena was refused at 15:46:56 for its port, at once,
 * and 100 still waited the whole 45 seconds for her (15:47:37). The raise
 * that fails now leaves a note, and the wait above it reads the note.
 *
 * A process ended by the manager. A service that ignores Stop while it is
 * starting is ended (pack 101). Windows then reports "The process
 * terminated unexpectedly", and the window showed it as an error of the
 * tunnel (15:46:33), although it was exactly what the user asked for.
 */

package manager

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainFinalError is a refusal that trying again cannot change.
type chainFinalError struct{ err error }

func (e chainFinalError) Error() string { return e.err.Error() }
func (e chainFinalError) Unwrap() error { return e.err }

// chainFinal marks err as final. The text stays the same, so the window
// shows exactly what it showed before.
func chainFinal(err error) error {
	if err == nil {
		return nil
	}
	return chainFinalError{err}
}

// chainIsFinal reports whether err was marked by chainFinal.
func chainIsFinal(err error) bool {
	var f chainFinalError
	return errors.As(err, &f)
}

// chainShownName is the name the user knows. A hidden hop is never shown,
// so it is named by the tunnel that rides on it (warpam for warpam-hop1).
func chainShownName(name string) string {
	if !conf.ChainIsHiddenHopName(name) {
		return name
	}
	if kids := chainChildNames(name); len(kids) != 0 {
		return kids[0]
	}
	return name
}

// chainNoteMemory is how long a note below counts.
const chainNoteMemory = 10 * time.Minute

type chainNote struct {
	at  time.Time
	err error
}

var chainViaFailed = struct {
	sync.Mutex
	m map[string]chainNote
}{m: make(map[string]chainNote)}

// chainViaNoteFailed is written when the raise of name through its parent
// ends with a refusal.
func chainViaNoteFailed(name string, err error) {
	chainViaFailed.Lock()
	chainViaFailed.m[strings.ToLower(name)] = chainNote{time.Now(), err}
	chainViaFailed.Unlock()
}

// chainViaFailedSince gives the refusal of the raise of name that came
// after since, or nil.
func chainViaFailedSince(name string, since time.Time) error {
	chainViaFailed.Lock()
	defer chainViaFailed.Unlock()
	n, ok := chainViaFailed.m[strings.ToLower(name)]
	if !ok || n.at.Before(since) || time.Since(n.at) > chainNoteMemory {
		return nil
	}
	return n.err
}

// chainKilledAfter is how long after the manager ended a process the
// error of that process is not shown.
const chainKilledAfter = 15 * time.Second

var chainKilled = struct {
	sync.Mutex
	m map[string]time.Time
}{m: make(map[string]time.Time)}

// chainNoteKilled is written just before the manager ends the process of
// a tunnel service.
func chainNoteKilled(name string) {
	chainKilled.Lock()
	chainKilled.m[strings.ToLower(name)] = time.Now()
	chainKilled.Unlock()
}

// chainWasKilled reports, once, whether the manager has just ended the
// process of this tunnel itself.
func chainWasKilled(name string) bool {
	chainKilled.Lock()
	defer chainKilled.Unlock()
	key := strings.ToLower(name)
	at, ok := chainKilled.m[key]
	if !ok {
		return false
	}
	delete(chainKilled.m, key)
	return time.Since(at) <= chainKilledAfter
}
