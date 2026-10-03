//go:build windows

/* AwgChain pack 92: a tunnel that never manages to start.
 *
 * On 28 September the service of Elena was created six times and died on
 * its first line every time, because it was pointed at a configuration
 * file that was not there. Between the attempts the manager kept the name
 * in the set of tunnels that are meant to be up, so the next start of the
 * program would have walked into the same wall, and the proxy of that
 * tunnel took its port each time.
 *
 * Counting is the whole trick. One death on start is an accident: a server
 * that is busy, an adapter that is still going away, a machine that is
 * waking up. Three in a row without a single successful start is a tunnel
 * that cannot come up at all, and a tunnel that cannot come up has no
 * business being raised again at every boot.
 *
 * The counter is per name and it is cleared the moment the tunnel really
 * starts, so a tunnel that is simply flaky is never touched.
 */

package manager

import (
	"log"
	"strings"
	"sync"
)

// chainStillbornLimit is how many deaths in a row it takes.
const chainStillbornLimit = 3

var (
	chainStillbornMu    sync.Mutex
	chainStillbornCount = make(map[string]int)
)

// ChainStillbornReset is called when a tunnel really started. Whatever
// happened before does not count any more.
func ChainStillbornReset(name string) {
	key := strings.ToLower(strings.TrimSpace(name))
	if len(key) == 0 {
		return
	}

	chainStillbornMu.Lock()
	defer chainStillbornMu.Unlock()

	delete(chainStillbornCount, key)
}

// ChainStillbornNote is called when the service of a tunnel ended without
// ever reaching the started state. After three such ends in a row the name
// is taken out of the set that is raised at start-up, by the same call the
// program uses when a tunnel is switched off by hand.
func ChainStillbornNote(name string) {
	name = strings.TrimSpace(name)
	key := strings.ToLower(name)
	if len(key) == 0 {
		return
	}

	chainStillbornMu.Lock()
	chainStillbornCount[key]++
	count := chainStillbornCount[key]
	if count >= chainStillbornLimit {
		delete(chainStillbornCount, key)
	}
	chainStillbornMu.Unlock()

	log.Printf("[WarpAm] The service of %s ended without ever starting, %d time(s) in a row", name, count)
	if count < chainStillbornLimit {
		return
	}
	log.Printf("[WarpAm] %s did not start %d times in a row, so it is taken out of the set that is raised at start-up", name, chainStillbornLimit)
	ChainNoteTunnelDown(name)
}
