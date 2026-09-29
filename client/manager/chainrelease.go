//go:build windows

/* AwgChain pack 92: releasing the folder so that it can be carried away.
 *
 * A portable copy lives in one folder and keeps everything it owns inside
 * it, but while it runs it also holds things that do not fit in a folder:
 * a manager service registered under a path on this machine, a service per
 * tunnel pointing at a configuration file under that path, network adapters
 * created by those services, and a data folder whose rights name the system
 * account alone. Copying such a folder onto a stick and starting it on
 * another machine used to end in a heap of questions: the configurations
 * could not be read, because the account that sealed them does not exist
 * there; the folder could not be opened, because its descriptor let nobody
 * else in; and the machine that was left behind kept services pointing at a
 * path that no longer had a program in it.
 *
 * This is the one button that undoes all of it in order. Every tunnel is
 * lowered and its service deleted, the adapters that are left are named in
 * the log, the rights of the data folder are opened for the users of the
 * machine, and the wish to start with Windows is switched off, which is
 * what lets the ordinary exit of the program delete the manager service on
 * its way out. The configurations can be decrypted first, and that is
 * asked in the window rather than decided here, because a folder that is
 * carried to a machine of the same person is better left encrypted.
 *
 * The manager service is deliberately not deleted here. Deleting it means
 * stopping it, and stopping it is killing the process that is answering
 * this very call, so the window would never hear how it went. The exit
 * that follows does it, and it is the path the program has always used.
 *
 * An installed copy is refused. There is an installer behind it that owns
 * the services and the folder, and the way to move an installed copy is to
 * remove it and install it where it is wanted.
 */

package manager

import (
	"errors"
	"log"

	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
)

// ChainReleaseResult is what the window is told. Every number is counted
// after the step really happened, so a partial release is described as one.
type ChainReleaseResult struct {
	// Unsealed is how many configurations were decrypted, when that was
	// asked for.
	Unsealed int
	// Tunnels is how many tunnel services were deleted, Left is how many
	// of them refused to go.
	Tunnels int
	Left    int
	// Adapters is how many of our adapters are still in the network list.
	// The driver removes them by itself a moment after the service that
	// made them is gone, so this is a note and not a failure.
	Adapters int
	// RightsOpen says the data folder can now be read by the person at the
	// machine, which is what makes the folder usable after the move.
	RightsOpen bool
	// AutoStartOff says the wish to start with Windows is cleared, which
	// is what allows the exit to delete the manager service.
	AutoStartOff bool
}

// chainReleaseTunnels lowers every tunnel the store knows about and deletes
// its service. A service that is already gone is not a failure: the name is
// counted as done, because the end state is the one that was asked for.
func chainReleaseTunnels() (deleted, left int) {
	names, err := chainSecureNames()
	if err != nil {
		log.Printf("[AwgChain] The tunnels could not be listed while releasing the folder: %v", err)
		return 0, 0
	}
	for _, name := range names {
		tunnelName := name
		stepErr := chainSecureRetry("Removing the service of "+tunnelName, func() error {
			removeErr := UninstallTunnel(tunnelName)
			if removeErr == nil {
				return nil
			}
			// A name with no service behind it any more is the state this
			// step wants, so the error of opening it is not repeated.
			if _, queryErr := chainReleaseServiceExists(tunnelName); queryErr != nil {
				return nil
			}
			return removeErr
		})
		if stepErr != nil {
			log.Printf("[AwgChain] The service of %s is still there: %v", tunnelName, stepErr)
			left++
			continue
		}
		deleted++
	}
	log.Printf("[AwgChain] %d tunnel services were removed while releasing the folder, %d are still there", deleted, left)
	return deleted, left
}

// chainReleaseServiceExists opens the service of a tunnel and closes it
// again. It answers the question the step above needs: is there still
// anything to delete.
func chainReleaseServiceExists(name string) (bool, error) {
	m, err := serviceManager()
	if err != nil {
		return false, err
	}
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return false, err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return false, err
	}
	service.Close()
	return true, nil
}

// chainReleaseAdapters names the adapters of ours that are still in the
// network list. Nothing is done to them: an adapter belongs to the driver
// and it goes away by itself once the service that created it is gone.
func chainReleaseAdapters() int {
	left := chainOrphanAdapters(map[string]bool{})
	for _, name := range left {
		log.Printf("[AwgChain] The adapter %s is still in the network list, the driver removes it a moment after its service is gone", name)
	}
	return len(left)
}

// chainReleaseAutoStart clears the wish to start with Windows and takes it
// off the service as well. A folder that is about to be moved must not be
// started from its old path by the next boot of this machine, and the exit
// of the program only deletes the manager service when this wish is gone.
func chainReleaseAutoStart() error {
	err := chainSecureSaveGlobal(func(global *ChainGlobalSettings) {
		global.AutoStart = false
		global.AutoStartSet = true
	})
	if err != nil {
		return err
	}
	chainSetManagerStartType(false)
	log.Printf("[AwgChain] The program will not start with Windows any more, so closing it deletes the manager service")
	return nil
}

// ChainReleaseFolder is the whole button. It is called by the manager on
// the request of the window and it returns when every step it could do is
// done: the window closes the program only when the answer carries no
// error, because the exit is the step that deletes the manager service.
func ChainReleaseFolder(unseal bool) (*ChainReleaseResult, error) {
	if chainSecureInstalledHere() {
		return nil, errors.New("this copy was put here by its installer, so it is the installer that moves it: remove the program and install it where it is wanted")
	}
	if chainSecureGlobal().InstallSealed {
		return nil, errors.New("this copy is closed from changes, so the rights of its folder cannot be opened")
	}

	result := &ChainReleaseResult{}

	if unseal {
		done, failed, err := chainSecureUnsealAll()
		result.Unsealed = done
		if err != nil {
			log.Printf("[AwgChain] The folder was not released: %d configurations were decrypted, %d were not: %v", done, failed, err)
			return result, err
		}
	}

	result.Tunnels, result.Left = chainReleaseTunnels()
	if result.Left != 0 {
		return result, errors.New("some tunnel services could not be removed, so the folder was left as it is")
	}

	result.Adapters = chainReleaseAdapters()

	// The rights come after the services. A tunnel service reads its
	// configuration as the system account, so opening the folder while the
	// services are still there would change the rights under a running
	// tunnel for no reason.
	err := chainSecureSetAcl(true)
	if err != nil {
		return result, err
	}
	result.RightsOpen = true

	err = chainReleaseAutoStart()
	if err != nil {
		return result, err
	}
	result.AutoStartOff = true

	log.Printf("[AwgChain] The folder is released for moving")
	return result, nil
}
