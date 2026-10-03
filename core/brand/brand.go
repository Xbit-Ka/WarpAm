/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 94: every name the program is known by, in one place.
 *
 * Until this pack the program answered to four names at once. The windows
 * said Warpam, the services and the log said AwgChain, the file was
 * amneziawg.exe and the registry key was Software\AmneziaWG, the same key
 * and the same file name the real AmneziaWG client uses. With both programs
 * on one machine they overwrote each other's install path, and a second
 * start of our window could raise theirs. From here on the program is WarpAm
 * everywhere, and every system name is read from this file.
 *
 * The Legacy names are what an installation before pack 94 left behind. They
 * are read only to carry that installation over and to clear it away.
 */

package brand

const (
	// Name is the name of the program, as a person reads it.
	Name = "WarpAm"
	// ExeName is the file of the program.
	ExeName = "WarpAm.exe"
	// FolderName is the folder under Program Files.
	FolderName = "WarpAm"

	// ManagerService is the service that runs the manager.
	ManagerService = "WarpAmManager"
	// TunnelServicePrefix starts the name of the service of every tunnel.
	TunnelServicePrefix = "WarpAmTunnel$"
	// TunnelServiceDisplayPrefix starts the name the service list shows.
	TunnelServiceDisplayPrefix = "WarpAm Tunnel: "
	// ManagerServiceDisplayName is the name the service list shows.
	ManagerServiceDisplayName = "WarpAm Manager"

	// PipeFolder holds the control pipe of every tunnel. The engine in
	// amneziawg-go/ipc/uapi_windows.go listens on the same folder; that
	// module cannot import this one, so the string is written there too.
	PipeFolder = `\\.\pipe\ProtectedPrefix\Administrators\WarpAm\`

	// RegistryKey is the key of the program under HKLM and HKCU.
	RegistryKey = `Software\WarpAm`
	// InstallPathValue is the value the installer writes the folder into.
	InstallPathValue = "InstallPath"

	// WindowClass is the class of the main window, how a second start
	// finds the first one.
	WindowClass = "WarpAm UI Manage Tunnels"

	// LegacyGuardStopEvent is left as it was on purpose: awgchain.bat and
	// the old guard signal this very name, and renaming it would silently
	// break "ks off" of a script the user may still keep.
	LegacyGuardStopEvent = `Global\AwgChainGuardStop`

	// LegacyFolderName is the folder under Program Files before pack 94.
	LegacyFolderName = "AwgChain"
	// LegacyExeName is the file of the program before pack 94.
	LegacyExeName = "amneziawg.exe"
	// LegacyManagerService is the manager service before pack 94.
	LegacyManagerService = "AwgChainManager"
	// LegacyTunnelServicePrefix starts a tunnel service before pack 94.
	LegacyTunnelServicePrefix = "AwgChainTunnel$"
	// LegacyRegistryKey is the key before pack 94. It is shared with the
	// real AmneziaWG client, so it is only ever read, never deleted here.
	LegacyRegistryKey = `Software\AmneziaWG`
)
