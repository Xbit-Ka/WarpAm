//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 94: the move from AwgChain to WarpAm.
 *
 * Up to pack 93 the program lived in C:\Program Files\AwgChain, ran as
 * the service AwgChainManager and gave every tunnel a service named
 * AwgChainTunnel$<name>. From pack 94 it is C:\Program Files\WarpAm,
 * WarpAmManager and WarpAmTunnel$<name>. Everything of the program lives in
 * Data next to the executable (pack 86), so a new folder starts empty, and
 * the old services still point at the old folder.
 *
 * The installer copies Data over before the old version is removed
 * (customactions.c, MigrateLegacyData). This file is the second line: it
 * runs at every start of the manager, before anything is read, and does two
 * things.
 *
 *   1. The services of the old name are stopped and deleted. An old tunnel
 *      service still holding an adapter named like the tunnel would stop
 *      the new one from ever getting its adapter.
 *   2. When the Configurations folder here is empty and the old folder has
 *      configurations, the old Data is copied over, file by file, and a
 *      file that already exists here is never overwritten. The old folder
 *      is renamed to Data.moved-to-WarpAm only after every file was found
 *      here with the same size, so nothing is lost if the copy stops half
 *      way.
 *
 * The encrypted configurations need nothing: DPAPI seals them for the
 * system account and not for a path, so they open in the new folder as they
 * did in the old one. The rights of Data are repaired right after this by
 * ChainSecureInit, as at every start.
 */

package manager

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/amnezia-vpn/amneziawg-windows/v3/brand"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainLegacyStopWait is how long an old service is given to stop.
const chainLegacyStopWait = 15 * time.Second

// chainLegacyMovedName is what the old Data folder is renamed to once its
// content has been carried over.
const chainLegacyMovedName = "Data.moved-to-WarpAm"

// ChainLegacyCarryOver is called by the manager at start, before the
// configurations folder is read for the first time.
func ChainLegacyCarryOver() {
	chainLegacySweepServices()
	chainLegacyCarryData()
}

// chainLegacySweepServices stops and deletes every service of the old name.
func chainLegacySweepServices() {
	m, err := serviceManager()
	if err != nil {
		log.Printf("[WarpAm] The old AwgChain services cannot be looked for: %v", err)
		return
	}
	names, err := m.ListServices()
	if err != nil {
		log.Printf("[WarpAm] The old AwgChain services cannot be listed: %v", err)
		return
	}
	for _, name := range names {
		lower := strings.ToLower(name)
		if lower != strings.ToLower(brand.LegacyManagerService) && !strings.HasPrefix(lower, strings.ToLower(brand.LegacyTunnelServicePrefix)) {
			continue
		}
		chainLegacyRemoveService(m, name)
	}
}

func chainLegacyRemoveService(m *mgr.Mgr, name string) {
	service, err := m.OpenService(name)
	if err != nil {
		log.Printf("[WarpAm] The old service %s cannot be opened: %v", name, err)
		return
	}
	defer service.Close()
	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		log.Printf("[WarpAm] The old service %s is still running, so it is stopped before the new services start", name)
		service.Control(svc.Stop)
		deadline := time.Now().Add(chainLegacyStopWait)
		for time.Now().Before(deadline) {
			status, err = service.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if err == nil && status.State != svc.Stopped {
			log.Printf("[WarpAm] The old service %s did not stop within %v; it is marked for deletion and goes at the next restart of Windows", name, chainLegacyStopWait)
		}
	}
	if err := service.Delete(); err != nil {
		log.Printf("[WarpAm] The old service %s could not be deleted: %v", name, err)
		return
	}
	log.Printf("[WarpAm] The old service %s was deleted", name)
}

// chainLegacyDataFolders lists the Data folders an installation before pack
// 94 may have left. The old registry key is shared with the real AmneziaWG
// client, so its path is taken only when it names a folder called AwgChain.
func chainLegacyDataFolders() []string {
	var roots []string
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, brand.LegacyRegistryKey, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		path, _, err := key.GetStringValue(brand.InstallPathValue)
		key.Close()
		path = strings.TrimSpace(path)
		if err == nil && len(path) != 0 && strings.EqualFold(filepath.Base(filepath.Clean(path)), brand.LegacyFolderName) {
			roots = append(roots, filepath.Clean(path))
		}
	}
	for _, env := range []string{"ProgramW6432", "ProgramFiles"} {
		if base := strings.TrimSpace(os.Getenv(env)); len(base) != 0 {
			roots = append(roots, filepath.Join(base, brand.LegacyFolderName))
		}
	}
	seen := make(map[string]bool)
	var folders []string
	for _, root := range roots {
		data := filepath.Join(root, "Data")
		if seen[strings.ToLower(data)] {
			continue
		}
		seen[strings.ToLower(data)] = true
		folders = append(folders, data)
	}
	return folders
}

// chainLegacyConfigCount counts the configuration files in a Data folder.
func chainLegacyConfigCount(data string) int {
	entries, err := os.ReadDir(filepath.Join(data, "Configurations"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if entry.Type().IsRegular() && (strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".conf.dpapi")) {
			count++
		}
	}
	return count
}

func chainLegacyCarryData() {
	here, err := conf.RootDirectory(true)
	if err != nil {
		log.Printf("[WarpAm] The data folder cannot be found, so nothing is carried over from AwgChain: %v", err)
		return
	}
	if chainLegacyConfigCount(here) != 0 {
		return
	}
	for _, old := range chainLegacyDataFolders() {
		if strings.EqualFold(filepath.Clean(old), filepath.Clean(here)) {
			continue
		}
		count := chainLegacyConfigCount(old)
		if count == 0 {
			continue
		}
		log.Printf("[WarpAm] %s has %d configurations and %s has none, so the old data is carried over", old, count, here)
		copied, failed := chainLegacyCopyTree(old, here)
		if failed != 0 {
			log.Printf("[WarpAm] %d files were copied from %s and %d could not be; the old folder is left as it is", copied, old, failed)
			return
		}
		moved := filepath.Join(filepath.Dir(old), chainLegacyMovedName)
		if err := os.Rename(old, moved); err != nil {
			log.Printf("[WarpAm] %d files were copied from %s; the old folder could not be renamed (%v) and is left as it is", copied, old, err)
			return
		}
		log.Printf("[WarpAm] %d files were copied from %s, and the old folder is now %s", copied, old, moved)
		return
	}
}

// chainLegacyCopyTree copies every regular file below from into to. A file
// that is already there is left alone, and so is the old log.
func chainLegacyCopyTree(from, to string) (copied, failed int) {
	filepath.WalkDir(from, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			failed++
			return nil
		}
		rel, relErr := filepath.Rel(from, path)
		if relErr != nil {
			failed++
			return nil
		}
		target := filepath.Join(to, rel)
		if entry.IsDir() {
			if err := os.MkdirAll(target, 0700); err != nil {
				failed++
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if strings.EqualFold(rel, "log.bin") {
			return nil
		}
		if _, err := os.Stat(target); err == nil {
			return nil
		}
		if err := chainLegacyCopyFile(path, target); err != nil {
			log.Printf("[WarpAm] %s could not be copied: %v", path, err)
			failed++
			return nil
		}
		copied++
		return nil
	})
	return copied, failed
}

func chainLegacyCopyFile(from, to string) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	target, err := os.OpenFile(to+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(target, source)
	closeErr := target.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		if written, statErr := os.Stat(to + ".part"); statErr != nil || written.Size() != info.Size() {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = os.Rename(to+".part", to)
	}
	if err != nil {
		os.Remove(to + ".part")
	}
	return err
}
