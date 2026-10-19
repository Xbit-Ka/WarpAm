//go:build windows

/* WarpAm pack 110: the window writes into the log again.
 *
 * The log of the run of 6.10 had 162 lines of the manager, 1710 of the
 * tunnels and not one of the window, although the window asked whether to
 * switch a chain off and got an answer. The window opens the ring read
 * only, by design: it runs without the rights of the manager. Its
 * log.Printf went to stderr, which nobody reads, so the lines of packs 107
 * and 108 ("Via: asked whether to switch off ...", "the answer is Yes")
 * never reached the log.
 *
 * The lines now go to the manager over the pipe, and the manager writes
 * them with [GUI] in front. A line is queued and sent by its own goroutine,
 * so a log.Printf of the window never waits for the pipe, and a full queue
 * drops the line instead of freezing the window.
 */

package manager

import (
	"encoding/gob"
	"io"
	"log"
	"strings"
)

// ChainGuiLogMethodType comes after 110, ChainSecureMethodType.
const ChainGuiLogMethodType MethodType = 111

const (
	chainGuiLogQueue   = 256
	chainGuiLogMaxLine = 1000
)

// chainServeGuiLog writes one line of the window. Nothing is answered, so
// the window does not wait. A caller without the elevated token is not
// written down: the log is for the program, not for anyone on the pipe.
func (s *ManagerService) chainServeGuiLog(decoder *gob.Decoder) error {
	var line string
	if err := decoder.Decode(&line); err != nil {
		return err
	}
	if s.elevatedToken == 0 {
		return nil
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > chainGuiLogMaxLine {
		line = line[:chainGuiLogMaxLine] + " ..."
	}
	if len(line) != 0 {
		log.Printf("[GUI] %s", line)
	}
	return nil
}

var chainGuiLogLines = make(chan string, chainGuiLogQueue)

type chainGuiLogWriter struct{}

func (chainGuiLogWriter) Write(p []byte) (int, error) {
	select {
	case chainGuiLogLines <- string(p):
	default:
	}
	return len(p), nil
}

// ChainGuiLogWriter is what the window gives to log.SetOutput once the
// pipe to the manager is open. Called once.
func ChainGuiLogWriter() io.Writer {
	go func() {
		for line := range chainGuiLogLines {
			rpcMutex.Lock()
			err := rpcEncoder.Encode(ChainGuiLogMethodType)
			if err == nil {
				err = rpcEncoder.Encode(line)
			}
			rpcMutex.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return chainGuiLogWriter{}
}
