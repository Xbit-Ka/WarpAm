//go:build windows

/* AwgChain pack 86: the manager side of the portable mode.
 *
 * Three things live here, and all three have to be done by the manager
 * because the window is not the account that owns the files.
 *
 *   * The box "encrypt the configurations". The store in package conf asks
 *     a hook before every write; this file points that hook at the box.
 *   * The two buttons "encrypt" and "decrypt". The files are sealed for the
 *     system account, so only the service can seal and unseal them.
 *   * The button that opens or closes the rights of the Data folder. The
 *     folder is born strict in both modes. The state is kept as a flag in
 *     settings.json and the descriptor is put back at every start, so the
 *     button and the folder can never tell two different stories.
 *
 * Pack 91 changed three things here.
 *
 * The password is gone. It was never a key, it could never become one, and
 * the only thing it did was stand between the user and his own files.
 *
 * Nothing reports success on trust any more. Every step that writes to the
 * disk is read back, and a step that did not take is repeated five times,
 * one second apart, before the window is told that it failed. The reason
 * is a real complaint: the window said that four configurations had been
 * decrypted while one of them was still encrypted, because the old file
 * could not be removed and nobody looked at the answer of the removal.
 *
 * And there is one more button: it closes the installation from changes.
 * It encrypts everything, puts the strict descriptor on the whole data
 * folder, raises a flag and takes the two buttons that could undo any of
 * that out of the window. There is no way back inside the program: the
 * installer is what clears it, because it deletes the data folder.
 */

package manager

import (
	"encoding/gob"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// ChainSecureMethodType continues the numbering of the chain packs: 100 is
// the status call, 101 to 108 are the settings calls, 109 clears the log.
const ChainSecureMethodType MethodType = 110

// The actions the window can ask for.
const (
	ChainSecureActionStatus = "status"
	ChainSecureActionSeal   = "seal"
	ChainSecureActionUnseal = "unseal"
	ChainSecureActionOpen   = "aclopen"
	ChainSecureActionStrict = "aclstrict"
	// ChainSecureActionSealInstall closes the installation from changes.
	// It is the one action of this program that cannot be taken back.
	ChainSecureActionSealInstall = "sealinstall"
	// ChainSecureActionRelease prepares a portable folder to be carried
	// away: see chainrelease.go. The window closes the program after it,
	// and that exit is what deletes the manager service.
	ChainSecureActionRelease = "release"
)

// chainSecureTries and chainSecureWait are the patience of every step that
// writes to the disk. A file is often held open for a moment by a backup
// tool or by the window itself, and giving up on the first refusal is what
// turned a passing lock into a failure the user had to read about.
const (
	chainSecureTries = 5
	chainSecureWait  = time.Second
)

// chainSecureInstallKey and chainSecureInstallValue are written by the
// installer of this program, see client/installer/wireguard.wxs. They are
// how the manager knows that the copy it belongs to was installed and not
// unpacked into a folder somewhere: only an installed copy can be closed
// from changes, because only an installed copy can be removed again.
const (
	chainSecureInstallKey   = "Software\\AmneziaWG"
	chainSecureInstallValue = "InstallPath"
)

// chainSecureOpenSid is the account the open folder is opened for: the
// built in Users group. A portable folder is meant to be read by the person
// sitting at the machine without a prompt for administrator rights, and
// naming the group instead of one user keeps the descriptor the same on a
// machine where the folder is carried to.
const chainSecureOpenSid = conf.ChainAclOpenSid

// ChainSecureRequest is what the window sends. Pack 91 took the password
// out of it: there is nothing it could have been used for.
type ChainSecureRequest struct {
	Action string
	// Unseal belongs to the action that releases the folder: it says the
	// configurations are to be decrypted before the folder is let go. The
	// window asks the question, because the answer depends on where the
	// folder is going and only the user knows that.
	Unseal bool
}

// ChainSecureReply is what the settings tab draws its two buttons from.
type ChainSecureReply struct {
	// Sealed and Plain are the files in the Configurations folder, counted
	// right now. The buttons are named after these two numbers, so a folder
	// somebody edited by hand is described honestly.
	Sealed int
	Plain  int
	// Encrypt is the box: whether new configurations are written encrypted.
	Encrypt bool
	// AclOpen says that the data folder is open for the Users group.
	AclOpen bool
	// RightsDirs and RightsFiles are the folders and the files that really
	// carry the descriptor the flag above asks for, counted by reading the
	// disk. RightsWrong is everything under the data folder that does not.
	// The line in the window is built from these three, so it describes the
	// disk and not the wish.
	RightsDirs  int
	RightsFiles int
	RightsWrong int
	// InstallSealed says the installation was closed from changes.
	InstallSealed bool
	// CanSeal says this copy was installed by the installer, which is the
	// only kind of copy that can be closed from changes.
	CanSeal bool
	// CanRelease says the opposite: this copy lives in a folder somebody
	// unpacked, so it is the kind of copy that can be prepared for moving.
	// An installed copy is moved by its installer.
	CanRelease bool
	// Release is the answer of that preparation, when it was asked for.
	// It is nil for every other action.
	Release *ChainReleaseResult
	// Root is the folder everything is read from, for the line in the tab.
	Root string
	// Done is how many files the last action really changed, counted after
	// the disk was read back. Failed is how many it could not change.
	Done   int
	Failed int
}

// chainEncryptConfigsWanted reads the box. A settings file written before
// this pack has no such key, and the wish flag tells that apart from a box
// the user has switched off: without it an old file would read as "the user
// does not want encryption" and the next save would write the keys of every
// tunnel to the disk as text.
func chainEncryptConfigsWanted() bool {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	global := chainSettingsLoadLocked().Global
	if !global.EncryptConfigsSet {
		return true
	}
	return global.EncryptConfigs
}

// chainSecureSaveGlobal changes the three fields of this pack in place. It
// does not go through ChainGlobalSave, because that call also applies the
// autostart box to the service manager, and none of this has anything to do
// with autostart.
func chainSecureSaveGlobal(change func(*ChainGlobalSettings)) error {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	book := chainSettingsLoadLocked()
	change(&book.Global)
	return chainSettingsStoreLocked()
}

func chainSecureGlobal() ChainGlobalSettings {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	return chainSettingsLoadLocked().Global
}

// ChainSecureSetEncrypt is the box in the settings tab.
func (s *ManagerService) ChainSecureSetEncrypt(on bool) error {
	err := chainSecureSaveGlobal(func(global *ChainGlobalSettings) {
		global.EncryptConfigs = on
		global.EncryptConfigsSet = true
	})
	if err != nil {
		return err
	}
	if on {
		log.Printf("[AwgChain] New configurations will be encrypted for this machine")
	} else {
		log.Printf("[AwgChain] New configurations will be written in plain text, the folder can be carried to another machine")
	}
	return nil
}

// chainSecureCount is the pair of numbers the buttons are named after.
func chainSecureCount() (sealed, plain int) {
	sealed, plain, err := conf.ChainCountConfigs()
	if err != nil {
		log.Printf("[AwgChain] The configurations could not be counted: %v", err)
		return 0, 0
	}
	return sealed, plain
}

// chainSecureStatus fills in the reply without doing anything. Every number
// in it is read from the disk at this moment: the window is not allowed to
// draw a state it was told about minutes ago.
func chainSecureStatus() *ChainSecureReply {
	global := chainSecureGlobal()
	sealed, plain := chainSecureCount()
	root, err := conf.ChainDataDirIfPresent()
	if err != nil {
		root = ""
	}
	dirs, files, wrong, checkErr := conf.ChainCheckDataTree(chainSecureWantedSid(global))
	if checkErr != nil {
		log.Printf("[AwgChain] The rights of the data folder could not be read: %v", checkErr)
	}
	return &ChainSecureReply{
		Sealed:        sealed,
		Plain:         plain,
		Encrypt:       chainEncryptConfigsWanted(),
		AclOpen:       global.DataAclOpen,
		RightsDirs:    dirs,
		RightsFiles:   files,
		RightsWrong:   wrong,
		InstallSealed: global.InstallSealed,
		CanSeal:       chainSecureInstalledHere(),
		CanRelease:    !chainSecureInstalledHere() && !global.InstallSealed,
		Root:          root,
	}
}

// chainSecureWantedSid is the account the descriptor is meant to let in: an
// empty answer means strict.
func chainSecureWantedSid(global ChainGlobalSettings) string {
	if global.DataAclOpen {
		return chainSecureOpenSid
	}
	return ""
}

// chainSecureRetry runs one step until the disk agrees with it. A step that
// fails is repeated five times, one second apart, and only then does the
// caller hear about it.
func chainSecureRetry(what string, step func() error) error {
	var err error
	for attempt := 1; attempt <= chainSecureTries; attempt++ {
		err = step()
		if err == nil {
			if attempt > 1 {
				log.Printf("[AwgChain] %s succeeded on attempt %d", what, attempt)
			}
			return nil
		}
		log.Printf("[AwgChain] %s did not succeed on attempt %d of %d: %v", what, attempt, chainSecureTries, err)
		if attempt < chainSecureTries {
			time.Sleep(chainSecureWait)
		}
	}
	return err
}

// chainSecureInstalledHere says whether the running program is the copy the
// installer put on this machine. The installer writes the folder it chose
// into the registry; a copy that was unpacked by hand has no such key.
//
// Pack 93: the answer used to be "no" for a perfectly installed copy. The
// external builder replaces wireguard.wxs with its own template, which had
// no InstallPath value, and the fallback compared the folder with
// "Program Files\AmneziaWG" while the builder installs into
// "Program Files\AwgChain". Now a missing key falls back to "the program
// lives inside a Program Files folder", whatever the subfolder is called,
// and both registry views are read, so a 32 bit package is found as well.
// A key that exists and names another folder still says no: that is a stale
// record of some other copy.
func chainSecureInstalledHere() bool {
	program, err := conf.ChainProgramDir()
	if err != nil {
		return false
	}
	program = strings.ToLower(filepath.Clean(program))

	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		key, openErr := registry.OpenKey(registry.LOCAL_MACHINE, chainSecureInstallKey, registry.QUERY_VALUE|view)
		if openErr != nil {
			continue
		}
		installed, _, readErr := key.GetStringValue(chainSecureInstallValue)
		key.Close()
		if readErr == nil && len(strings.TrimSpace(installed)) != 0 {
			return strings.ToLower(filepath.Clean(installed)) == program
		}
	}

	for _, name := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"} {
		root := strings.TrimSpace(os.Getenv(name))
		if len(root) == 0 {
			continue
		}
		root = strings.ToLower(filepath.Clean(root))
		if strings.HasPrefix(program, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// chainSecureNames is every tunnel the store knows about.
func chainSecureNames() ([]string, error) {
	return conf.ListConfigNames()
}

// chainSecureSealAll encrypts everything that is still plain text, chain
// hops included. Until this pack a hop was kept in plain text on purpose,
// so that awgchain.bat could read it; that tool is the one caller which
// loses its file, and the line below says so instead of leaving it to be
// discovered.
func chainSecureSealAll() (done, failed int, err error) {
	names, err := chainSecureNames()
	if err != nil {
		return 0, 0, err
	}
	var last error
	for _, name := range names {
		changed := false
		tryErr := chainSecureRetry("Encrypting the configuration of "+name, func() error {
			var sealErr error
			changed, sealErr = conf.ChainSealName(name)
			return sealErr
		})
		if tryErr != nil {
			failed++
			if last == nil {
				last = tryErr
			}
			continue
		}
		if changed {
			done++
			log.Printf("[AwgChain] The configuration of %s is now encrypted for this machine", name)
		}
	}
	if done != 0 {
		log.Printf("[AwgChain] %d configurations were encrypted, awgchain.bat cannot read them any more", done)
	}
	if failed != 0 {
		log.Printf("[AwgChain] %d configurations were left in plain text, the last reason was: %v", failed, last)
		return done, failed, last
	}
	return done, failed, nil
}

// chainSecureUnsealAll decrypts everything, which is what a folder has to
// look like before it is carried to another machine. Every file is read
// back before it is counted, so the number the window shows is the number
// of files that really changed on the disk.
func chainSecureUnsealAll() (done, failed int, err error) {
	names, err := chainSecureNames()
	if err != nil {
		return 0, 0, err
	}
	var last error
	for _, name := range names {
		changed := false
		tryErr := chainSecureRetry("Decrypting the configuration of "+name, func() error {
			var openErr error
			changed, openErr = conf.ChainUnsealName(name)
			return openErr
		})
		if tryErr != nil {
			failed++
			if last == nil {
				last = tryErr
			}
			continue
		}
		if changed {
			done++
			log.Printf("[AwgChain] The configuration of %s is now in plain text", name)
		}
	}
	saveErr := chainSecureSaveGlobal(func(global *ChainGlobalSettings) {
		global.EncryptConfigs = false
		global.EncryptConfigsSet = true
	})
	if saveErr != nil {
		return done, failed, saveErr
	}
	log.Printf("[AwgChain] %d configurations were decrypted, the folder can be carried to another machine", done)
	if failed != 0 {
		log.Printf("[AwgChain] %d configurations are still encrypted, the last reason was: %v", failed, last)
		return done, failed, last
	}
	return done, failed, nil
}

// ChainSecureApplyAcl puts the descriptor of the data folder back the way
// the flag in the settings says. It is called at every start of the manager
// as well, so a folder somebody changed the rights of by hand is repaired.
//
// Pack 91: the descriptor goes onto every file and folder inside the data
// folder and not only onto the folder itself, it is read back afterwards,
// and a failure is repeated five times before the caller hears about it.
// An open folder full of files nobody can read was not what the button
// promised.
func ChainSecureApplyAcl(open bool) error {
	sid := ""
	what := "Putting the strict rights on the data folder"
	if open {
		sid = chainSecureOpenSid
		what = "Opening the rights of the data folder"
	}
	conf.ChainSetAclSid(sid)
	return chainSecureRetry(what, func() error {
		_, _, applyErr := conf.ChainApplyDataTree(sid)
		if applyErr != nil {
			return applyErr
		}
		dirs, files, wrong, checkErr := conf.ChainCheckDataTree(sid)
		if checkErr != nil {
			return checkErr
		}
		if wrong != 0 {
			log.Printf("[AwgChain] %d items under the data folder did not take the new rights", wrong)
			return errors.New("some files under the data folder did not take the new rights")
		}
		if open {
			log.Printf("[AwgChain] The rights of the data folder are open: every user of this machine can read the settings and the configurations, %d folders and %d files", dirs, files)
		} else {
			log.Printf("[AwgChain] The rights of the data folder are strict: only the system and the administrators can read it, %d folders and %d files", dirs, files)
		}
		return nil
	})
}

// chainSecureSealInstall closes the installation from changes. It is the
// one action here that cannot be taken back from inside the program: the
// installer clears it, because the installer deletes the data folder.
//
// The checks come first and they are not a formality. A copy that was not
// installed cannot be removed by an installer, and a data folder that lies
// somewhere else would survive the removal with its flag and its strict
// rights intact, which is exactly the trap this must not build.
func chainSecureSealInstall() (done, failed int, err error) {
	if !chainSecureInstalledHere() {
		return 0, 0, errors.New("this copy of the program was not put here by its installer, so there is no installer that could undo this")
	}
	inside, err := conf.ChainDataUnderProgram()
	if err != nil {
		return 0, 0, err
	}
	if !inside {
		return 0, 0, errors.New("the data folder does not lie inside the folder of the program, so removing the program would not clear it")
	}

	done, failed, err = chainSecureSealAll()
	if err != nil {
		return done, failed, err
	}
	sealed, plain := chainSecureCount()
	if plain != 0 {
		return done, failed, errors.New("some configurations are still in plain text, the installation was left as it was")
	}

	err = ChainSecureApplyAcl(false)
	if err != nil {
		return done, failed, err
	}

	err = chainSecureSaveGlobal(func(global *ChainGlobalSettings) {
		global.InstallSealed = true
		global.EncryptConfigs = true
		global.EncryptConfigsSet = true
		global.DataAclOpen = false
		global.DataAclSid = ""
	})
	if err != nil {
		return done, failed, err
	}
	log.Printf("[AwgChain] The installation is sealed: %d configurations are encrypted, the rights of the whole data folder are strict, new configurations will be encrypted and none of it can be undone from inside the program", sealed)
	return done, failed, nil
}

func chainSecureSetAcl(open bool) error {
	err := ChainSecureApplyAcl(open)
	if err != nil {
		return err
	}
	sid := ""
	if open {
		sid = chainSecureOpenSid
	}
	return chainSecureSaveGlobal(func(global *ChainGlobalSettings) {
		global.DataAclOpen = open
		global.DataAclSid = sid
	})
}

// ChainSecure is the one call behind all of it.
func (s *ManagerService) ChainSecure(request ChainSecureRequest) (*ChainSecureReply, error) {
	action := strings.TrimSpace(strings.ToLower(request.Action))

	// A closed installation says no here and not in the window. The window
	// takes the two buttons away, but the answer must not depend on which
	// window asks: a request that arrives anyway is refused.
	if chainSecureGlobal().InstallSealed &&
		(action == ChainSecureActionUnseal || action == ChainSecureActionOpen) {
		log.Printf("[AwgChain] The request %s was refused: the installation is sealed", action)
		return chainSecureStatus(), errors.New("the installation is closed from changes, the only way back is to remove the program with its installer")
	}

	done := 0
	failed := 0
	var released *ChainReleaseResult
	var err error
	switch action {
	case ChainSecureActionStatus, "":
	case ChainSecureActionSeal:
		done, failed, err = chainSecureSealAll()
	case ChainSecureActionUnseal:
		done, failed, err = chainSecureUnsealAll()
	case ChainSecureActionOpen:
		err = chainSecureSetAcl(true)
	case ChainSecureActionStrict:
		err = chainSecureSetAcl(false)
	case ChainSecureActionSealInstall:
		done, failed, err = chainSecureSealInstall()
	case ChainSecureActionRelease:
		released, err = ChainReleaseFolder(request.Unseal)
		if released != nil {
			done = released.Unsealed
			failed = released.Left
		}
	default:
		err = errors.New("unknown action " + request.Action)
	}
	reply := chainSecureStatus()
	reply.Done = done
	reply.Failed = failed
	reply.Release = released
	if err != nil {
		return reply, err
	}
	// The list in the window shows the file names of the tunnels, so it is
	// told that they changed.
	if done != 0 {
		IPCServerNotifyTunnelsChange()
	}
	return reply, nil
}

func (s *ManagerService) chainServeSecure(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var request ChainSecureRequest
	err := decoder.Decode(&request)
	if err != nil {
		return err
	}
	reply, callErr := s.ChainSecure(request)
	if reply == nil {
		reply = &ChainSecureReply{}
	}
	err = encoder.Encode(*reply)
	if err != nil {
		return err
	}
	return encoder.Encode(errToString(callErr))
}

// IPCClientChainSecure is the client side of the call.
func IPCClientChainSecure(request ChainSecureRequest) (reply ChainSecureReply, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(ChainSecureMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(request)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&reply)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// ChainSecureInit is called once when the manager service starts. It points
// the store at the box, repairs the rights of the data folder and says in
// one line which folder everything is read from.
func ChainSecureInit() {
	conf.ChainEncryptWanted = chainEncryptConfigsWanted

	root, err := conf.ChainDataDir()
	if err != nil {
		log.Printf("[AwgChain] The data folder could not be opened (%v), %s", err, conf.ChainRootSource())
		return
	}
	log.Printf("[AwgChain] The data folder is %s, %s", root, conf.ChainRootSource())

	global := chainSecureGlobal()

	// Pack 91: the password is gone, so the value that was kept for it is
	// wiped from the settings at the first start after the update. Nothing
	// reads it any more, and a hash of a password nobody will ever be
	// asked for has no business lying in a file.
	if len(strings.TrimSpace(global.DpapiVerifier)) != 0 {
		wipeErr := chainSecureSaveGlobal(func(book *ChainGlobalSettings) {
			book.DpapiVerifier = ""
		})
		if wipeErr != nil {
			log.Printf("[AwgChain] The stored password check could not be removed: %v", wipeErr)
		} else {
			log.Printf("[AwgChain] The stored password check is removed, the configurations are no longer held behind a question nobody could answer")
		}
	}

	err = ChainSecureApplyAcl(global.DataAclOpen)
	if err != nil {
		log.Printf("[AwgChain] The rights of the data folder could not be set: %v", err)
	}
	sealed, plain := chainSecureCount()
	log.Printf("[AwgChain] Configurations: %d encrypted, %d in plain text, new ones will be %s", sealed, plain, chainSecureModeWord())
	if global.InstallSealed {
		log.Printf("[AwgChain] The installation is sealed, it can only be changed by removing the program with its installer")
	}
}

func chainSecureModeWord() string {
	if chainEncryptConfigsWanted() {
		return "encrypted"
	}
	return "in plain text"
}
