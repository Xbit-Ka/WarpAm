/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
)

var cachedServiceManager *mgr.Mgr

func serviceManager() (*mgr.Mgr, error) {
	if cachedServiceManager != nil {
		return cachedServiceManager, nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	cachedServiceManager = m
	return cachedServiceManager, nil
}

var ErrManagerAlreadyRunning = errors.New("Manager already installed and running")

func InstallManager() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	// TODO: Do we want to bail if executable isn't being run from the right location?

	serviceName := "AwgChainManager"
	service, err := m.OpenService(serviceName)
	if err == nil {
		status, err := service.Query()
		if err != nil {
			service.Close()
			return err
		}
		if status.State != svc.Stopped {
			service.Close()
			if status.State == svc.StartPending {
				// We were *just* started by something else, so return success here, assuming the other program
				// starting this does the right thing. This can happen when, e.g., the updater relaunches the
				// manager service and then invokes amneziawg.exe to raise the UI.
				return nil
			}
			return ErrManagerAlreadyRunning
		}
		err = service.Delete()
		service.Close()
		if err != nil {
			return err
		}
		for {
			service, err = m.OpenService(serviceName)
			if err != nil {
				break
			}
			service.Close()
			time.Sleep(time.Second / 3)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		// AwgChain pack 67: the manager raises tunnels at boot itself now, so
		// it waits for the network stack the same way a tunnel service does.
		Dependencies: []string{"Nsi", "TcpIp"},
		// AwgChain pack 86: the name the list of services shows. Only the
		// display name changes, the service is still registered as
		// AwgChainManager: the internal name is what every other part of
		// the program opens the service by, and renaming it would leave
		// the old service of every machine standing with nobody to stop
		// it.
		DisplayName:  "WarpAm Manager",
	}

	// AwgChain pack 86: the data folder is handed to the service in writing.
	// The service is the same executable in the same folder, so it would
	// deduce the same root by itself, but once the folder is moved or renamed
	// the old service stays registered with the old path, and sc qc then says
	// plainly which folder that service reads.
	if root := conf.ChainRootArgForService(); len(root) != 0 {
		service, err = m.CreateService(serviceName, path, config, conf.ChainRootArg, root, "/managerservice")
	} else {
		service, err = m.CreateService(serviceName, path, config, "/managerservice")
	}
	if err != nil {
		return err
	}
	// Pack 70: the manager holds the kill switch and raises the chain at
	// boot. If it dies there is nobody to lift the lock and nobody to raise
	// anything, so Windows is asked to start it again.
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400); err != nil {
		log.Printf("[AwgChain] The manager service was created, but Windows would not take the restart-on-failure settings (%v)", err)
	}
	// AwgChain pack 67: a freshly created service is always automatic. If the
	// user switched the "start with Windows" box off, that wish lives in
	// settings.json and is applied again right here.
	chainApplyAutoStartIntent()
	service.Start()
	return service.Close()
}

func UninstallManager() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	serviceName := "AwgChainManager"
	service, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	service.Control(svc.Stop)
	err = service.Delete()
	err2 := service.Close()
	if err != nil {
		return err
	}
	return err2
}

func InstallTunnel(configPath string) error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	name, err := conf.NameFromPath(configPath)
	if err != nil {
		return err
	}

	// AwgChain pack 90: a service is never pointed at a file that is not
	// there. The tunnel service reads its configuration as its very first
	// act, so a wrong path showed up only as "Unable to load configuration
	// from path ... The system cannot find the file specified" followed by
	// "Shutting down", once for every attempt, while the window showed a
	// raise that went nowhere and the manager said nothing at all.
	if info, statErr := os.Stat(configPath); statErr != nil || !info.Mode().IsRegular() {
		log.Printf("[%s] The configuration file %s is not there, so no service is created for it", name, configPath)
		// Shown in a window, so Russian. The log stays English.
		return fmt.Errorf("\u0424\u0430\u0439\u043b \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a \u0442\u0443\u043d\u043d\u0435\u043b\u044f %s \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d, \u043f\u043e\u0434\u043d\u044f\u0442\u044c \u0435\u0433\u043e \u043d\u0435\u0447\u0435\u043c", name)
	}

	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	service, err := m.OpenService(serviceName)
	if err == nil {
		status, err := service.Query()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			return err
		}
		if status.State != svc.Stopped && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			if chainHopByName(name) {
				// AwgChain: this hop is already up, most likely started by awgchain.bat or
				// by the chain watchdog. Adopt the existing service instead of refusing:
				// recreating it would drop its Nsi/TcpIp dependencies and bounce the chain.
				log.Printf("[%s] Adopting the running tunnel service", name)
				go trackTunnelService(name, service) // Pass off reference to handle.
				return nil
			}
			service.Close()
			return errors.New("Tunnel already installed and running")
		}
		err = service.Delete()
		service.Close()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			return err
		}
		// AwgChain pack 87: the wait for the old service has a limit now.
		// Windows keeps a deleted service openable while any handle to it
		// is left, and one of those handles is ours: the watcher of the
		// service database wakes on our own deletion and opens the service
		// again. The loop that stood here had no way out of that, so a
		// start after a reboot never returned, the window kept its
		// "connecting" look and nothing came up. It also called Close on a
		// service it did not get whenever OpenService itself answered
		// "marked for delete".
		ChainSweepHold(name)
		gone := ChainSweepGone(m, serviceName)
		ChainSweepRelease(name)
		if !gone {
			log.Printf("[%s] The old service is still marked for deletion after %v, so the tunnel is not raised now", name, chainSweepWait)
			// Shown in a window, so Russian. The log stays English.
			return errors.New("\u041f\u0440\u0435\u0436\u043d\u044f\u044f \u0441\u043b\u0443\u0436\u0431\u0430 \u0442\u0443\u043d\u043d\u0435\u043b\u044f \u0435\u0449\u0451 \u0443\u0434\u0430\u043b\u044f\u0435\u0442\u0441\u044f, \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u043f\u043e\u043f\u044b\u0442\u043a\u0443 \u0447\u0435\u0440\u0435\u0437 \u043d\u0435\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u0435\u043a\u0443\u043d\u0434")
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		// AwgChain pack 67: manual on purpose. An automatic tunnel service
		// is what raised the last tunnel at boot behind the settings' back:
		// Windows started it before the manager could read the settings.
		// From now on the manager alone decides what is raised.
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp"},
		// Pack 86: same here, the display name only. The service keeps its
		// name AwgChainTunnel$<tunnel>, which is what the tracker, the pin
		// wait and the rename below look for.
		DisplayName:  "WarpAm Tunnel: " + name,
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	// AwgChain pack 86: same as the manager service, the tunnel service is
	// told where the data folder is. The config path stays the last word of
	// the command line, which is what the rename below looks for.
	if root := conf.ChainRootArgForService(); len(root) != 0 {
		service, err = m.CreateService(serviceName, path, config, conf.ChainRootArg, root, "/tunnelservice", configPath)
	} else {
		service, err = m.CreateService(serviceName, path, config, "/tunnelservice", configPath)
	}
	if err != nil {
		return err
	}

	err = service.Start()
	go trackTunnelService(name, service) // Pass off reference to handle.
	return err
}

func UninstallTunnel(name string) error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	service.Control(svc.Stop)
	err = service.Delete()
	err2 := service.Close()
	if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
		return err
	}
	return err2
}

func changeTunnelServiceConfigFilePath(name, oldPath, newPath string) {
	var err error
	defer func() {
		if err != nil {
			log.Printf("Unable to change tunnel service command line argument from %#q to %#q: %v", oldPath, newPath, err)
		}
	}()
	m, err := serviceManager()
	if err != nil {
		return
	}
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return
	}
	service, err := m.OpenService(serviceName)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		err = nil
		return
	} else if err != nil {
		return
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(args) < 3 || !strings.EqualFold(args[0], exePath) {
		err = nil
		return
	}
	// AwgChain pack 86: the command line of a tunnel service can now carry
	// /rootdir as well, so the config path is not always the third word. The
	// old check demanded exactly three words and gave up in silence, which
	// left the service pointing at a file name that a rename had already
	// changed. The word after /tunnelservice is searched for instead.
	at := -1
	for i := 1; i < len(args)-1; i++ {
		if args[i] == "/tunnelservice" {
			at = i + 1
			break
		}
	}
	if at < 0 || !strings.EqualFold(args[at], oldPath) {
		err = nil
		return
	}
	args[at] = newPath
	config.BinaryPathName = windows.ComposeCommandLine(args)
	err = service.UpdateConfig(config)
}
