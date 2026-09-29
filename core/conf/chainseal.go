//go:build windows

/* AwgChain pack 91: one descriptor for the whole data folder.
 *
 * Until this pack the rights of the data folder were three separate
 * stories. The folder itself got the descriptor of ChainDataSd, every
 * configuration written by writeLockedDownFile got a hand written string
 * of its own, and log.bin got whatever it inherited. Opening the folder
 * for the Users group therefore left the files inside it closed, which is
 * exactly the opposite of what the button in the settings promises.
 *
 * This file is the single source of truth. There are two strings, one for
 * folders and one for files, both built from the same wish: an empty sid
 * means strict, a sid means that account is granted full access as well.
 * Everything that writes a file under the data folder asks here, and the
 * whole tree can be walked and set in one call.
 *
 * Nothing here trusts the write. Every setter has a reader next to it, so
 * the caller can say what is really on the disk instead of what it asked
 * for. That is the lesson of the decryption that reported four files done
 * while one of them was untouched.
 */

package conf

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ChainAclOpenSid is the account an open folder is opened for: the built in
// Users group. Naming the group and not one user keeps the descriptor the
// same on a machine the folder is carried to.
const ChainAclOpenSid = "BU"

// chainFileStrictSd is the file half of the descriptor. It carries no
// inheritance flags, because a file inherits nothing to anybody, and it
// gives the administrators full access and not only delete: a folder that
// an administrator can enter must not hold files he cannot read.
const chainFileStrictSd = "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)"

var (
	chainAclMu   sync.RWMutex
	chainAclSid  string
	chainSdMu    sync.Mutex
	chainSdCache = make(map[string]*windows.SECURITY_DESCRIPTOR)
)

// ChainSetAclSid remembers the wish of the settings for this process. The
// manager calls it at every start and after every change of the button, so
// that a file written a second later is born with the same rights the
// folder carries.
func ChainSetAclSid(sid string) {
	chainAclMu.Lock()
	defer chainAclMu.Unlock()

	chainAclSid = strings.TrimSpace(sid)
}

// ChainAclSid is the wish as it stands. An empty answer means strict, which
// is also the answer inside the tunnel service and inside every tool that
// never heard of the settings.
func ChainAclSid() string {
	chainAclMu.RLock()
	defer chainAclMu.RUnlock()

	return chainAclSid
}

// ChainFolderSdText is the descriptor of a folder under the data folder.
func ChainFolderSdText(sid string) string {
	sid = strings.TrimSpace(sid)
	if len(sid) == 0 {
		return ChainDataStrictSd
	}
	return ChainDataStrictSd + "(A;OICI;FA;;;" + sid + ")"
}

// ChainFileSdText is the descriptor of a file under the data folder.
func ChainFileSdText(sid string) string {
	sid = strings.TrimSpace(sid)
	if len(sid) == 0 {
		return chainFileStrictSd
	}
	return chainFileStrictSd + "(A;;FA;;;" + sid + ")"
}

// chainSd turns a descriptor string into the thing the kernel wants. The
// result is kept, because the tree walk asks for the same two strings once
// per file and parsing them again for every file would be the slowest part
// of the walk.
func chainSd(text string) (*windows.SECURITY_DESCRIPTOR, error) {
	chainSdMu.Lock()
	defer chainSdMu.Unlock()

	if sd, ok := chainSdCache[text]; ok {
		return sd, nil
	}
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		return nil, err
	}
	chainSdCache[text] = sd
	return sd, nil
}

// ChainFileAttributes are the rights a file the program writes is born
// with. It is the one answer writeLockedDownFile and the log file both use.
func ChainFileAttributes() (*windows.SecurityAttributes, error) {
	sd, err := chainSd(ChainFileSdText(ChainAclSid()))
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// chainOpenForDacl opens a path for reading or changing its descriptor. A
// reparse point is opened as itself: the rights of a folder somewhere else
// are none of our business.
func chainOpenForDacl(path string, dir, write bool) (windows.Handle, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.READ_CONTROL)
	if write {
		access |= windows.WRITE_DAC | windows.WRITE_OWNER
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	return windows.CreateFile(path16, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, flags, 0)
}

// chainSetPathSd writes one descriptor onto one path.
func chainSetPathSd(path string, dir bool, text string) error {
	sd, err := chainSd(text)
	if err != nil {
		return err
	}
	handle, err := chainOpenForDacl(path, dir, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.SetKernelObjectSecurity(handle,
		windows.DACL_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.OWNER_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd)
}

// chainReadPathSd reads the descriptor of one path back as a string.
func chainReadPathSd(path string, dir bool) (string, error) {
	handle, err := chainOpenForDacl(path, dir, false)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}

// chainSdGrants says whether a descriptor read back from the disk has an
// entry for one account. The whole string is not compared with the one that
// was written: Windows is free to write the same descriptor in a different
// order, and the two questions that matter are whether the system account
// still owns the path and whether the Users group was let in.
func chainSdGrants(text, sid string) bool {
	return strings.Contains(strings.ToUpper(text), ";"+strings.ToUpper(sid)+")")
}

// chainWalkData visits the data folder and everything inside it. A folder
// that cannot be read is skipped instead of ending the walk: one unreadable
// corner must not leave the rest of the tree without rights.
func chainWalkData(visit func(path string, dir bool)) error {
	data, err := ChainDataDir()
	if err != nil {
		return err
	}
	visit(data, true)
	return filepath.WalkDir(data, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || path == data {
			return nil
		}
		switch {
		case entry.IsDir():
			visit(path, true)
		case entry.Type().IsRegular():
			visit(path, false)
		}
		return nil
	})
}

// ChainApplyDataTree puts the descriptor of the wish onto the data folder
// and onto every file and folder under it. It answers with how many folders
// and files were really set, and it does not stop at the first failure: a
// file somebody holds open must not leave the rest of the tree open too.
func ChainApplyDataTree(sid string) (dirs, files int, err error) {
	folderText := ChainFolderSdText(sid)
	fileText := ChainFileSdText(sid)
	var failed error
	walkErr := chainWalkData(func(path string, dir bool) {
		text := fileText
		if dir {
			text = folderText
		}
		if setErr := chainSetPathSd(path, dir, text); setErr != nil {
			if failed == nil {
				failed = errors.New(filepath.Base(path) + ": " + setErr.Error())
			}
			return
		}
		if dir {
			dirs++
		} else {
			files++
		}
	})
	if walkErr != nil {
		return dirs, files, walkErr
	}
	return dirs, files, failed
}

// ChainCheckDataTree reads the disk back. The two first numbers are the
// folders and the files that really carry the descriptor of the wish, the
// third is everything that does not. It is the call that lets a window say
// what is true instead of what was asked for.
func ChainCheckDataTree(sid string) (dirs, files, wrong int, err error) {
	open := len(strings.TrimSpace(sid)) != 0
	walkErr := chainWalkData(func(path string, dir bool) {
		text, readErr := chainReadPathSd(path, dir)
		if readErr != nil {
			wrong++
			return
		}
		if !chainSdGrants(text, "SY") || chainSdGrants(text, ChainAclOpenSid) != open {
			wrong++
			return
		}
		if dir {
			dirs++
		} else {
			files++
		}
	})
	if walkErr != nil {
		return dirs, files, wrong, walkErr
	}
	return dirs, files, wrong, nil
}

// ChainEnsureFile brings a file the program is about to open into the world
// with the descriptor of this pack. An existing file is left alone: it is
// the tree walk that puts old files right, and a file that is already open
// elsewhere must not be truncated here.
func ChainEnsureFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	sa, err := ChainFileAttributes()
	if err != nil {
		return err
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(path16, windows.GENERIC_WRITE, windows.FILE_SHARE_READ,
		sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if err == windows.ERROR_FILE_EXISTS {
			return nil
		}
		return err
	}
	return windows.CloseHandle(handle)
}

// ChainDataUnderProgram says whether the data folder lies inside the folder
// of the running program. Sealing an installation only makes sense when it
// does: a folder somewhere else is not what the installer removes.
func ChainDataUnderProgram() (bool, error) {
	program, err := ChainProgramDir()
	if err != nil {
		return false, err
	}
	data, err := ChainDataDirIfPresent()
	if err != nil {
		return false, err
	}
	program = strings.ToLower(filepath.Clean(program))
	data = strings.ToLower(filepath.Clean(data))
	return data == program || strings.HasPrefix(data, program+string(filepath.Separator)), nil
}
