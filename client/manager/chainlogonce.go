//go:build windows

/* AwgChain pack 64: a journal that only speaks when something changes.
 *
 * The chain watch runs every five seconds. Lines that describe a standing
 * state, such as "the kill switch is switched off in the settings of X",
 * used to be written on every single round. chainLogChanged remembers the
 * last text of a topic and stays quiet while it is the same.
 */

package manager

import (
	"fmt"
	"log"
	"sync"
)

var (
	chainLogOnceLock sync.Mutex
	chainLogOnceSeen = make(map[string]string)
)

// chainLogChanged writes the line only when the text of this topic is not the
// one that was written last.
func chainLogChanged(topic, format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)

	chainLogOnceLock.Lock()
	last, seen := chainLogOnceSeen[topic]
	repeat := seen && last == text
	if !repeat {
		chainLogOnceSeen[topic] = text
	}
	chainLogOnceLock.Unlock()

	if repeat {
		return
	}
	log.Print(text)
}

// chainLogForget clears the memory of a topic, so that the next call writes
// its line again. It runs when the state it describes is torn down.
func chainLogForget(topic string) {
	chainLogOnceLock.Lock()
	delete(chainLogOnceSeen, topic)
	chainLogOnceLock.Unlock()
}