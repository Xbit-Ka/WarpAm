//go:build windows

/* AwgChain pack 92: one hand at a time in the configurations folder.
 *
 * On 28 September a tunnel disappeared. Nothing in the log said so, because
 * the two pieces of code that deleted its files both did it silently and
 * neither of them looked at what the other was doing.
 *
 * The first was the Configs section: decrypting a tunnel writes <name>.conf
 * and then removes <name>.conf.dpapi. The second was the migration inherited
 * from WireGuard, which is woken by the folder watcher on every change:
 * it reads <name>.conf, writes <name>.conf.dpapi and then removes the plain
 * file. Run them at the same time on one tunnel and each of them deletes the
 * file the other has just written. Nothing is left.
 *
 * The migration is gone in this pack, see migration_windows.go, but that
 * alone would only make the accident rarer. A configuration is written by
 * the window, by the Configs section, by the importer and by the store
 * watcher, and any two of them can meet. So every call that writes into the
 * folder now goes through the lock below, and every removal of a file says
 * in the log which tunnel it belonged to and why it went.
 *
 * The lock is held for the length of one file, never for a whole pass over
 * the folder: encrypting forty tunnels must not stop the window from
 * reading the list.
 */

package conf

import (
	"log"
	"os"
	"sync"
)

// chainStoreMu is the folder. Whoever writes a configuration file holds it.
var chainStoreMu sync.Mutex

// ChainStoreHold takes the configurations folder for the caller. It is
// exported because the manager seals and unseals files through calls that
// live in this package but are driven from outside it.
func ChainStoreHold() {
	chainStoreMu.Lock()
}

// ChainStoreRelease gives the folder back.
func ChainStoreRelease() {
	chainStoreMu.Unlock()
}

// chainRemoveFile is the only way a configuration file leaves the disk. It
// says what it removed and why, because a program that can lose a tunnel
// without writing a line is a program nobody can help.
func chainRemoveFile(path, why string) error {
	err := os.Remove(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		log.Printf("[AwgChain] The file %s could not be removed (%s): %v", path, why, err)
		return err
	}
	log.Printf("[AwgChain] The file %s was removed: %s", path, why)
	return nil
}
