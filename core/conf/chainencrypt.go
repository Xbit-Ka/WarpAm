//go:build windows

/* AwgChain pack 86: encrypting and decrypting the configurations on demand.
 *
 * Windows encryption takes no password. dpapi.Encrypt seals a file for the
 * account that calls it, and the manager service is the account that calls
 * it, so every file is sealed for the system account of this machine. That
 * is why a folder copied to another machine cannot be opened there, and it
 * is why going portable has to mean decrypting first.
 *
 * Pack 91 removed the password. It was never a key and it could never
 * become one, so all it ever did was stand between the user and his own
 * files. What it pretended to protect is protected by the rights of the
 * folder instead.
 *
 * Pack 91 also stopped this file from reporting work it did not do. Both
 * calls below used to write the new file, ask for the old one to be
 * removed without looking at the answer, and report success. A file that
 * could not be removed therefore stayed on the disk while the window said
 * every configuration had been decrypted. Now the removal is checked and
 * the folder is read back: the answer is yes only when exactly one file of
 * the tunnel is left and it is the right one.
 *
 * Every configuration is treated alike, hops of a chain included. Until
 * this pack a hop was written in plain text on purpose, so awgchain.bat
 * could read it; that is the one caller which loses its file, and the
 * manager says so in the log instead of leaving it to be discovered.
 */

package conf

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
)

// ChainEncryptWanted is asked before a configuration is written. The manager
// points it at the box in the settings. While it is nil, which is the case
// inside the tunnel service and inside any tool that only reads, the answer
// is yes: encryption is the default of this program.
var ChainEncryptWanted func() bool

func chainEncryptWanted() bool {
	if ChainEncryptWanted == nil {
		return true
	}
	return ChainEncryptWanted()
}

// chainDropOther removes the file of the other kind, and only once the file
// that is being kept is really there. A configuration is never allowed to
// disappear between two writes.
//
// Pack 91: the answer of the removal is no longer thrown away. A file that
// is held open by somebody else, or that the rights of the folder do not
// let us delete, stays where it is, and the caller has to know that: this
// is the step whose silence made the program say that four configurations
// were decrypted while one of them was still encrypted.
func chainDropOther(drop, kept string) error {
	if _, err := os.Stat(kept); err != nil {
		return err
	}
	if strings.EqualFold(drop, kept) {
		return nil
	}
	// Pack 92: the removal goes through the one place that says in the log
	// which file went and why.
	return chainRemoveFile(drop, "the configuration was written as "+filepath.Base(kept))
}

// chainConfirmOnly reads the folder back and says whether the tunnel is
// left with the one file it is meant to have. It is the difference between
// "the write returned no error" and "the disk looks the way we promised".
func chainConfirmOnly(keep, gone string) error {
	if _, err := os.Stat(keep); err != nil {
		return errors.New("the file that was written is not there: " + err.Error())
	}
	if strings.EqualFold(keep, gone) {
		return nil
	}
	if _, err := os.Stat(gone); err == nil {
		return errors.New("the old file " + filepath.Base(gone) + " is still there")
	}
	return nil
}

// chainConfigPaths gives both possible file names of one tunnel.
func chainConfigPaths(name string) (plain, sealed string, err error) {
	if !TunnelNameIsValid(name) {
		return "", "", errors.New("Tunnel name is not valid")
	}
	dir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(dir, name+configFileUnencryptedSuffix),
		filepath.Join(dir, name+configFileSuffix), nil
}

// ChainSealName encrypts the plain file of one tunnel. The answer says
// whether anything was done: a tunnel that is already encrypted is not an
// error, it is simply nothing to do.
func ChainSealName(name string) (bool, error) {
	// Pack 92: the same lock the store takes when it writes a
	// configuration. Two writers on one tunnel used to delete both of its
	// files between them.
	ChainStoreHold()
	defer ChainStoreRelease()

	plain, sealed, err := chainConfigPaths(name)
	if err != nil {
		return false, err
	}
	text, err := os.ReadFile(plain)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	blob, err := dpapi.Encrypt(text, name)
	if err != nil {
		return false, err
	}
	err = writeLockedDownFile(sealed, true, blob)
	if err != nil {
		return false, err
	}
	err = chainDropOther(plain, sealed)
	if err != nil {
		return false, err
	}
	err = chainConfirmOnly(sealed, plain)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ChainUnsealName writes the plain file of one tunnel and removes the
// encrypted one, which is what the portable mode needs.
func ChainUnsealName(name string) (bool, error) {
	ChainStoreHold()
	defer ChainStoreRelease()

	plain, sealed, err := chainConfigPaths(name)
	if err != nil {
		return false, err
	}
	blob, err := os.ReadFile(sealed)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	text, err := dpapi.Decrypt(blob, name)
	if err != nil {
		return false, err
	}
	err = writeLockedDownFile(plain, true, text)
	if err != nil {
		return false, err
	}
	err = chainDropOther(sealed, plain)
	if err != nil {
		return false, err
	}
	err = chainConfirmOnly(plain, sealed)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ChainCountConfigs counts what lies in the folder right now: how many
// configurations are encrypted and how many are still plain text. The
// button in the settings is named after these two numbers.
func ChainCountConfigs() (sealed, plain int, err error) {
	dir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return 0, 0, err
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, err
	}
	for _, file := range files {
		if !file.Type().IsRegular() {
			continue
		}
		name := file.Name()
		named := ""
		switch {
		case strings.HasSuffix(name, configFileSuffix):
			named = "sealed"
		case strings.HasSuffix(name, configFileUnencryptedSuffix):
			named = "plain"
		default:
			continue
		}
		// WarpAm pack 94: the name is only a claim, the first bytes decide.
		// The window said "5 encrypted, 0 plain" while the folder showed
		// .conf files, and nothing in the old count could tell a sealed
		// name with plain text inside from a real DPAPI blob.
		found := chainConfigKind(filepath.Join(dir, name))
		if found == "" {
			found = named
		}
		if found != named {
			chainCountMismatch(name, named, found)
		}
		if found == "sealed" {
			sealed++
		} else {
			plain++
		}
	}
	return sealed, plain, nil
}

// chainDPAPIMagic is how every DPAPI blob begins: version 1 and the provider
// GUID df9d8cd0-1501-11d1-8c7a-00c04fc297eb.
var chainDPAPIMagic = []byte{0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb}

// chainConfigKind reads the head of a configuration file and says what is
// really inside: "sealed" for a DPAPI blob, "plain" for text that opens with
// a section, and "" when the file cannot be read or is neither.
func chainConfigKind(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	head := make([]byte, 64)
	n, _ := io.ReadFull(file, head)
	head = head[:n]
	if bytes.HasPrefix(head, chainDPAPIMagic) {
		return "sealed"
	}
	text := bytes.TrimLeft(bytes.TrimPrefix(head, []byte{0xef, 0xbb, 0xbf}), " \t\r\n")
	if bytes.HasPrefix(text, []byte("[")) || bytes.HasPrefix(text, []byte("#")) {
		return "plain"
	}
	return ""
}

// chainCountMismatches remembers which files were already reported, so the
// window, which counts on every refresh, does not fill the log.
var chainCountMismatches sync.Map

func chainCountMismatch(name, named, found string) {
	if _, seen := chainCountMismatches.LoadOrStore(name+"|"+found, true); seen {
		return
	}
	log.Printf("[WarpAm] The configuration file %s is named %s but its content is %s, so it is counted as %s", name, named, found, found)
}
