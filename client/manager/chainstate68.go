/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 68 (F1): who is really in the middle of changing state.
 *
 * Start used to refuse the whole raise when any overlapping tunnel was in
 * the state TunnelUnknown. Unknown is not a transition, it is "nobody asked
 * the service yet", and it is the state of every tunnel the tracker has not
 * seen since the service started. That is why a raise straight after boot
 * could answer "Please allow the tunnel to finish activating" and stop
 * there, with nothing in the log.
 *
 * The tracker is only a hint now. Anything that looks busy is checked with
 * the service manager, and only a service that really is starting or
 * stopping counts as busy.
 */

package manager

import "log"

// chainFirstInTransition returns the first name the service manager says is
// starting or stopping right now, or an empty string when nothing is busy.
func (s *ManagerService) chainFirstInTransition(names []string) string {
	for _, name := range names {
		if len(name) == 0 {
			continue
		}
		state, err := s.State(name)
		if err != nil {
			// A tunnel whose state cannot be read is not a reason to refuse
			// the raise: the stop below will deal with it.
			log.Printf("[WarpAm] The state of %s could not be read (%v), so it is taken as settled", name, err)
			continue
		}
		if state == TunnelStarting || state == TunnelStopping {
			return name
		}
	}
	return ""
}
