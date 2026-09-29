//go:build windows

/* AwgChain pack 86: the sweep of leftovers at the start of the manager.
 *
 * Two kinds of leftovers were seen on this machine. Five processes of
 * amneziawg.exe stood in the task list at once, and adapters of tunnels that
 * no longer had a configuration stayed in the network list with a tunnel
 * service still registered behind them. Both come from the same thing: a
 * tunnel service that was never stopped in an orderly way, after a crash, a
 * hard reset or a deleted configuration.
 *
 * What is done here is deliberately narrow, because a wrong sweep would kill
 * a working tunnel. Only a tunnel service whose configuration is gone and
 * which is not running is deleted. Anything else is written into the log with
 * a name, so the next report says plainly what is left and why nothing was
 * done about it. The processes are counted and reported, never killed: the
 * manager, every open window and every tunnel service are all the same
 * executable, so a count is the only honest statement that can be made about
 * them from here.
 */

package manager

import (
	"log"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainOrphanExeName is the name of our own executable, under which the
// manager, the windows and the tunnel services all appear.
const chainOrphanExeName = "amneziawg.exe"

// chainOrphanCountProcesses counts the processes of our executable.
func chainOrphanCountProcesses() int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	count := 0
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), chainOrphanExeName) {
			count++
		}
	}
	return count
}

// chainOrphanConfigured is the set of tunnels that still have a
// configuration, by lower case name.
func chainOrphanConfigured() (map[string]bool, error) {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(names))
	for _, name := range names {
		known[strings.ToLower(name)] = true
	}
	return known, nil
}

// chainOrphanAdapters names the adapters that look like ours but have no
// configuration behind them any more.
func chainOrphanAdapters(known map[string]bool) []string {
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagDefault)
	if err != nil {
		return nil
	}
	left := make([]string, 0, 2)
	for _, adapter := range adapters {
		name := strings.TrimSpace(adapter.FriendlyName())
		if len(name) == 0 || known[strings.ToLower(name)] {
			continue
		}
		if !conf.TunnelNameIsValid(name) {
			continue
		}
		// Pack 87: only an adapter of ours counts. The check used to be the
		// name alone, so the physical Ethernet card of the machine passed
		// it and every start of the manager wrote "the adapter Ethernet has
		// no configuration and no service any more" and then "1 leftovers
		// were found". A tunnel of ours is a Wintun adapter, and Wintun
		// says so both in its type and in its description.
		if adapter.IfType != winipcfg.IfTypePropVirtual &&
			!strings.Contains(strings.ToLower(adapter.Description()), "wintun") {
			continue
		}
		left = append(left, name)
	}
	return left
}

// chainOrphanSweepName deals with one name: a tunnel service that is
// registered while its configuration is gone. A service that is stopped is
// deleted, a service that is still running is only reported, because a
// chain that is carrying traffic right now must not be pulled away under
// the user.
func chainOrphanSweepName(name string) (deleted bool) {
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return false
	}
	m, err := serviceManager()
	if err != nil {
		return false
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		// No service behind it. The adapter is the only leftover, and it is
		// not ours to remove: the driver deletes it when the tunnel that
		// created it is started and stopped once more.
		log.Printf("[AwgChain] The adapter %s has no configuration and no service any more, nothing was changed", name)
		return false
	}
	defer service.Close()

	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		log.Printf("[AwgChain] The service of %s is still running while its configuration is gone, it was left alone", name)
		return false
	}
	err = service.Delete()
	if err != nil {
		log.Printf("[AwgChain] The leftover service of %s could not be deleted: %v", name, err)
		return false
	}
	log.Printf("[AwgChain] The leftover service of %s was deleted, its configuration is gone", name)
	return true
}

// ChainOrphanSweep is called once when the manager service starts.
func ChainOrphanSweep() {
	known, err := chainOrphanConfigured()
	if err != nil {
		log.Printf("[AwgChain] The leftovers could not be looked for, the configurations are unreadable: %v", err)
		return
	}
	left := chainOrphanAdapters(known)
	deleted := 0
	for _, name := range left {
		if chainOrphanSweepName(name) {
			deleted++
		}
	}
	if count := chainOrphanCountProcesses(); count > 1 {
		// One is this manager. Every window and every tunnel service adds
		// one more, so a number well above the tunnels that are up is the
		// sign of processes nobody is waiting for any more.
		log.Printf("[AwgChain] %d processes of %s are running: this manager, the open windows and the tunnel services", count, chainOrphanExeName)
	}
	if len(left) == 0 {
		log.Printf("[AwgChain] No leftovers of earlier runs were found")
		return
	}
	log.Printf("[AwgChain] %d leftovers were found, %d services were deleted", len(left), deleted)
}
