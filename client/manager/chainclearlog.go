//go:build windows

/* AwgChain pack 85: the window asks the manager to empty the log.
 *
 * The log is one shared ring in a memory mapped file. The manager owns it for
 * writing, while every window opens the same mapping read only, so a button in
 * the window cannot clear anything by itself. One more IPC call is the whole
 * story: the window asks, the manager clears and writes one line saying who is
 * reading an empty log now, which keeps the journal honest.
 */

package manager

import (
	"encoding/gob"
	"log"

	"github.com/amnezia-vpn/amneziawg-windows-client/ringlogger"
)

// ChainClearLogMethodType sits above the numbers the chain packs have
// already taken: 100 is ChainStatusMethodType and 101 to 108 belong to
// chainsettingsipc.go, so 101 was a duplicate case in the dispatch
// switch and the manager did not compile.
const ChainClearLogMethodType MethodType = 109

// ChainClearLog empties the ring the whole program writes into.
func (s *ManagerService) ChainClearLog() error {
	if ringlogger.Global == nil {
		return nil
	}
	err := ringlogger.Global.Clear()
	if err != nil {
		return err
	}
	log.Printf("[AwgChain] The log was cleared from the window")
	return nil
}

func (s *ManagerService) chainServeClearLog(encoder *gob.Encoder) error {
	return encoder.Encode(errToString(s.ChainClearLog()))
}

// IPCClientChainClearLog is the client side of the call.
func IPCClientChainClearLog() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(ChainClearLogMethodType)
	if err != nil {
		return
	}
	return rpcDecodeError()
}
