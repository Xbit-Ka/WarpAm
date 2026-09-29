//go:build windows

/* AwgChain pack 86: one folder for everything.
 *
 * Until this pack the program kept its data in three different places at
 * once. The root of the configurations came from the known folder of
 * Program Files with "AwgChain" appended (path_windows.go), while the
 * settings book, the split list and the state of the guard were each
 * joined onto the ProgramData environment variable on their own. A folder
 * that can be carried on a stick was therefore impossible, and a service
 * running as SYSTEM could not even be told where to look, because the
 * environment of that account is not the environment of the user.
 *
 * From this pack the rule is one line long: the root is the folder the
 * running executable lives in, and "Data" inside it holds everything. No
 * known folders, no environment variables, no search for any earlier
 * location. Installing into C:\Program Files\WarpAm is not a special
 * mode any more, it is simply where the file was put.
 *
 * A service is the same executable in the same folder, so it deduces the
 * same root by itself. The explicit key is kept all the same: after the
 * folder is moved or renamed the old service stays registered with the old
 * path, and "sc qc AwgChainManager" then shows plainly where that service
 * reads its data from.
 *
 * One thing the key brought with it, and it cost a start of the program.
 * PresetRootDirectory only remembers a path; RootDirectory then hands that
 * path out and creates nothing, because until this pack nobody ever preset
 * it. A service started with /rootdir therefore received the name of a
 * folder that did not exist yet, the log file could not be created inside
 * it, and the manager died before it could show a window: the tray icon
 * never appeared and the installer said so after thirty seconds. From here
 * on the folder is created together with the preset, with the same strict
 * descriptor RootDirectory gives it, and every reader makes sure of it
 * again before handing the path out.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ChainRootArg is the command line key that carries the data folder to a
// service. It is read before any file is touched.
const ChainRootArg = "/rootdir"

// chainRootPreset remembers that the root came from the command line, so the
// log can say so and so that nothing tries to deduce it again.
var chainRootPreset string

// chainRootError is what went wrong while the preset folder was being made.
var chainRootError error

// ChainDataStrictSd is the descriptor the Data folder is born with: full
// access for the system account and for administrators, nothing for anybody
// else. It is the reason a plain user cannot read a configuration.
const ChainDataStrictSd = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// ChainProgramDir is the folder the running executable lives in. Every path
// of the program is built from this one.
func ChainProgramDir() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if len(dir) == 0 {
		return "", errors.New("the folder of the executable cannot be determined")
	}
	return dir, nil
}

// ChainTakeRootArg pulls "/rootdir <path>" out of a command line and returns
// the path together with the arguments that are left. The pair is removed on
// purpose: every case of the switch in main.go checks an exact argument
// count, and those checks must keep working untouched.
func ChainTakeRootArg(args []string) (string, []string) {
	root := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if i > 0 && strings.EqualFold(args[i], ChainRootArg) && i+1 < len(args) {
			root = strings.TrimSpace(args[i+1])
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return root, rest
}

// ChainPresetRoot fixes the data folder for the whole process. It must be
// called before the log file is opened, because the log lives in the root as
// well.
func ChainPresetRoot(root string) {
	root = strings.TrimSpace(root)
	if len(root) == 0 {
		return
	}
	chainRootPreset = root
	PresetRootDirectory(root)
	// The folder is made right here, and not left to the first reader,
	// because the log file is opened before any reader runs. A failure is
	// remembered rather than thrown away: the manager prints it in its
	// first line, which is a better place for it than a process that has
	// no log yet.
	chainRootError = ChainMakeDataDir(root)
}

// ChainRootProblem is the failure of creating the preset folder, if there
// was one.
func ChainRootProblem() error {
	return chainRootError
}

// chainDataAttributes are the rights a freshly made data folder is born
// with: the system account and the administrators, nobody else.
func chainDataAttributes() (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(ChainDataStrictSd)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// ChainMakeDataDir creates the data folder and everything above it. The
// folders above are ordinary ones, they inherit their rights from the place
// the program lies in; the data folder itself is born strict.
func ChainMakeDataDir(path string) error {
	path = strings.TrimSpace(path)
	if len(path) == 0 {
		return errors.New("the data folder has no path")
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil
	}
	parent := filepath.Dir(path)
	if len(parent) != 0 && parent != path {
		err := os.MkdirAll(parent, 0o700)
		if err != nil {
			return err
		}
	}
	sa, err := chainDataAttributes()
	if err != nil {
		return err
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(path16, sa)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	return nil
}

// ChainRootArgForService is the value a freshly created service is given. It
// is the folder this executable uses right now, so an installed service and
// the window always read the same files.
func ChainRootArgForService() string {
	root, err := RootDirectory(false)
	if err != nil {
		return ""
	}
	return root
}

// ChainRootSource is one short phrase for the log: where the root came from.
func ChainRootSource() string {
	if len(chainRootPreset) != 0 {
		return "taken from " + ChainRootArg
	}
	return "the folder of the program"
}

// ChainDataDir is the data folder, created when it is missing. Everything
// the program writes goes under it: Configurations, settings.json, log.bin,
// the split list and the state of the guard.
func ChainDataDir() (string, error) {
	root, err := RootDirectory(true)
	if err != nil {
		return "", err
	}
	// A preset root is handed out by RootDirectory without being created,
	// so every reader makes sure of the folder itself. The check is a
	// stat of a folder that is almost always there, which costs nothing
	// next to the file this reader is about to open.
	err = ChainMakeDataDir(root)
	if err != nil {
		return "", err
	}
	return root, nil
}

// ChainDataDirIfPresent is the data folder without creating anything, for
// readers that must not bring a folder to life.
func ChainDataDirIfPresent() (string, error) {
	return RootDirectory(false)
}

// ChainDataSd builds the descriptor of the Data folder. Pack 91 moved the
// two strings into chainseal.go, which is the only place that knows how a
// folder and a file differ, and left this name standing for its callers.
func ChainDataSd(sid string) string {
	return ChainFolderSdText(sid)
}

// ChainApplyDataSd puts a descriptor on the Data folder and on everything
// inside it. Until pack 91 it stopped at the folder, so opening the folder
// for the Users group left every file in it closed and the button in the
// settings promised something that was not done. The wish is remembered
// for this process as well, so the next file the program writes is born
// with the same rights the tree now carries.
func ChainApplyDataSd(sid string) error {
	ChainSetAclSid(sid)
	_, _, err := ChainApplyDataTree(sid)
	return err
}
