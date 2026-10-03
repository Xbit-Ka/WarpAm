//go:build windows

/* AwgChain pack 85: one place that decides whether an error is worth a window.
 *
 * On the night of 26 September the chain failed to stop its hop 92 times, and
 * every failure opened a modal window with the same text. Closing one let the
 * next one in, about twenty times over, and pressing Exit in the tray made the
 * whole queue play itself out with the sound of closing windows. The error
 * itself was real, but the second identical window carries no information at
 * all.
 *
 * The rules here:
 *   - the same text is not shown again while its window is still open, and not
 *     again for two minutes after it was closed;
 *   - a text nobody has seen yet is shown at once, even while another window
 *     stands open, because that is genuinely new information;
 *   - what is not shown is still counted, and the count is both written to the
 *     log and added to the next window of that same text, so nothing is
 *     quietly dropped;
 *   - while the program is going away nothing is shown at all.
 */

package ui

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lxn/walk"
)

// chainNoticeQuiet is how long the same text stays silent after its window was
// closed.
const chainNoticeQuiet = 2 * time.Minute

type chainNoticeState struct {
	shownAt time.Time
	repeats int
}

var (
	chainNoticeMu       sync.Mutex
	chainNoticeSeen     = make(map[string]*chainNoticeState)
	chainNoticeOpen     bool
	chainNoticeQuitting bool
)

// ChainNoticeStopShowing is called when the program starts to go away, so that
// the errors of the shutdown itself do not open windows nobody can answer.
func ChainNoticeStopShowing() {
	chainNoticeMu.Lock()
	chainNoticeQuitting = true
	chainNoticeMu.Unlock()
}

func chainNoticeSignature(title, message string) string {
	return title + "\x00" + message
}

// chainNoticeAllow decides whether this text may be shown right now. It
// returns how many times the same text was swallowed since it was last shown.
func chainNoticeAllow(title, message string, holdsWindow bool) (bool, int) {
	signature := chainNoticeSignature(title, message)
	now := time.Now()

	chainNoticeMu.Lock()
	defer chainNoticeMu.Unlock()

	if chainNoticeQuitting {
		log.Printf("[WarpAm] Notice while quitting, log only: %s: %s", title, message)
		return false, 0
	}

	state := chainNoticeSeen[signature]
	if state == nil {
		// Never seen before, so it is shown even if another window stands
		// open: this is the one case that carries new information.
		state = &chainNoticeState{}
		chainNoticeSeen[signature] = state
	} else {
		quiet := chainNoticeOpen || now.Sub(state.shownAt) < chainNoticeQuiet
		if quiet {
			state.repeats++
			log.Printf("[WarpAm] Notice repeated %d time(s), log only: %s: %s", state.repeats, title, message)
			return false, 0
		}
	}

	repeats := state.repeats
	state.repeats = 0
	state.shownAt = now
	if holdsWindow {
		chainNoticeOpen = true
	}
	return true, repeats
}

// chainNoticeDone marks the window of this text as closed.
func chainNoticeDone(title, message string) {
	signature := chainNoticeSignature(title, message)
	chainNoticeMu.Lock()
	defer chainNoticeMu.Unlock()
	chainNoticeOpen = false
	if state := chainNoticeSeen[signature]; state != nil {
		// The quiet time counts from the moment the window was closed, not
		// from the moment it was opened, otherwise a window that stood open
		// for an hour would let the same error straight back in.
		state.shownAt = time.Now()
	}
}

// chainNoticeWithRepeats adds the line about swallowed repeats.
func chainNoticeWithRepeats(message string, repeats int) string {
	switch {
	case repeats == 1:
		return message + "\n\n" + chainNoticeRepeatOne
	case repeats > 1:
		return message + "\n\n" + fmt.Sprintf(chainNoticeRepeatMan, repeats)
	}
	return message
}

// chainNoticeError shows an error window, or writes the line to the log when
// the same error is already on screen or was just answered.
func chainNoticeError(owner walk.Form, title, message string) {
	allowed, repeats := chainNoticeAllow(title, message, true)
	if !allowed {
		return
	}
	walk.MsgBox(owner, title, chainNoticeWithRepeats(message, repeats), walk.MsgBoxIconError)
	chainNoticeDone(title, message)
}

// chainNoticeWarning is the same door for warnings.
func chainNoticeWarning(owner walk.Form, title, message string) {
	allowed, repeats := chainNoticeAllow(title, message, true)
	if !allowed {
		return
	}
	walk.MsgBox(owner, title, chainNoticeWithRepeats(message, repeats), walk.MsgBoxIconWarning)
	chainNoticeDone(title, message)
}

// chainNoticeBalloon asks whether a tray balloon may be shown. A balloon holds
// nothing back, it fades on its own, so it does not take the open flag.
func chainNoticeBalloon(title, message string) bool {
	allowed, _ := chainNoticeAllow(title, message, false)
	return allowed
}
