/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 68 (G2): a settings file that cannot be read is kept.
 *
 * Until now a settings.json that failed to parse was passed over in silence
 * and the defaults were used, and the very next save wrote those defaults
 * over the file. Everything the user had set was gone, and nothing in the
 * log said why. The broken file is now moved aside under a name of its own,
 * so it can be looked at, and the move is written down.
 */

package manager

import (
	"fmt"
	"log"
	"os"
)

// chainSettingsKeepBroken renames a settings file that cannot be parsed to
// settings.json.bad-<n> and says so in the log.
func chainSettingsKeepBroken(path string, parseErr error) {
	for n := 1; n <= 20; n++ {
		kept := fmt.Sprintf("%s.bad-%d", path, n)
		if _, err := os.Stat(kept); err == nil {
			// That name is taken by an earlier broken file; keep it.
			continue
		}
		if err := os.Rename(path, kept); err != nil {
			log.Printf("[AwgChain] The settings file is damaged (%v) and could not be moved aside (%v), so the defaults are used", parseErr, err)
			return
		}
		log.Printf("[AwgChain] The settings file is damaged (%v). It is kept as %s and the defaults are used", parseErr, kept)
		return
	}
	log.Printf("[AwgChain] The settings file is damaged (%v) and there are already twenty copies kept aside, so it is left alone and the defaults are used", parseErr)
}
