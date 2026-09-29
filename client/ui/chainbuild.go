//go:build windows

/* AwgChain patch 17 - the chain looks and behaves like a single tunnel.
 *
 *   - the outer WARP hop is hidden from the list (see listview.go)
 *   - the pair is named automatically: warpam, warpam1, warpam2 ...
 *   - editing, renaming and deleting work exactly like for a plain tunnel
 *   - every string added by AwgChain is in Russian
 */

package ui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/lxn/walk"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// chainMenuText is the label of the menu entry, kept here so the patch script
// stays free of non-ASCII text.
const chainMenuText = "Собрать ц&епочку из двух конфигов (WARP + Amnezia)..."

var (
	chainNL    = string([]byte{10})
	chainNL2   = string([]byte{10, 10})
	chainTitle = "AwgChain"
)

func (tp *TunnelsPage) onBuildChain() {
	// Pack 67: two files, two questions, in the order of the chain. Step 1 is
	// the outer link (WARP), step 2 the inner one (Amnezia). The roles come
	// from the order of the questions, not from guessing at the contents.
	warpPath, ok := chainAskConfigFile(tp.Form(), chainPickWarpTitle)
	if !ok {
		return
	}
	warpConfig, err := chainLoadConfigFile(warpPath)
	if err != nil {
		showErrorCustom(tp.Form(), chainTitle, chainReadWarpError+err.Error())
		return
	}

	innerPath, ok := chainAskConfigFile(tp.Form(), chainPickInnerTitle)
	if !ok {
		return
	}
	if strings.EqualFold(innerPath, warpPath) {
		showErrorCustom(tp.Form(), chainTitle, chainSameFileText)
		return
	}
	innerConfig, err := chainLoadConfigFile(innerPath)
	if err != nil {
		showErrorCustom(tp.Form(), chainTitle, chainReadInnerError+err.Error())
		return
	}

	if !chainConfirmRoles(tp.Form(), warpConfig, innerConfig) {
		return
	}

	outerAlias, err := chainOuterAdapter()
	if err != nil {
		showErrorCustom(tp.Form(), chainTitle,
			"Не удалось найти адаптер с выходом в интернет: "+err.Error())
		return
	}

	pairName := conf.ChainNextPairName(chainTakenNames())
	hop1, hop2, err := conf.ChainBuild(warpConfig, innerConfig, outerAlias, pairName)
	if err != nil {
		showErrorCustom(tp.Form(), chainTitle, "Не удалось собрать цепочку: "+err.Error())
		return
	}

	message := "Будет создан один туннель из двух звеньев:" + chainNL2 +
		conf.ChainSummary(hop1, hop2) + chainNL +
		"В списке появится одна запись, она называется " + hop2.Name + "." + chainNL +
		"Создать?"
	if walk.DlgCmdYes != walk.MsgBox(tp.Form(), chainTitle, message,
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) {
		return
	}

	go func() {
		tp.listView.SetSuspendTunnelsUpdate(true)
		err := chainCreatePair(hop1, hop2)
		tp.listView.SetSuspendTunnelsUpdate(false)
		tp.Synchronize(func() {
			if err != nil {
				showErrorCustom(tp.Form(), chainTitle, "Не удалось создать цепочку: "+err.Error())
				return
			}
			walk.MsgBox(tp.Form(), chainTitle,
				"Цепочка \""+hop2.Name+"\" готова." + chainNL +
					"Нажмите на неё, чтобы подключиться: внешнее звено поднимется само, замок встанет на место и цепочка будет автоматически восстанавливаться.",
				walk.MsgBoxIconInformation)
		})
	}()
}

// ---------------------------------------------------------------------------
// Pack 67: picking the two configs one at a time.
// ---------------------------------------------------------------------------

const (
	chainFileFilter     = "Конфигурации (*.conf)|*.conf|Все файлы (*.*)|*.*"
	chainPickWarpTitle  = "Шаг 1 из 2: выберите конфиг WARP (внешнее звено)"
	chainPickInnerTitle = "Шаг 2 из 2: выберите конфиг Amnezia (внутреннее звено)"
	chainOneFileText    = "На этом шаге нужен ровно один файл."
	chainSameFileText   = "Это тот же самый файл. Для второго звена нужен другой конфиг."
	chainReadWarpError  = "Не удалось прочитать конфиг WARP: "
	chainReadInnerError = "Не удалось прочитать конфиг Amnezia: "
)

// chainAskConfigFile shows one file dialog and returns the chosen path. The
// dialog is the same ShowOpenMultiple the import menu uses, because that is
// the call this program is built against; picking more than one file at a
// step is simply refused.
func chainAskConfigFile(owner walk.Form, title string) (string, bool) {
	dlg := walk.FileDialog{
		Filter: chainFileFilter,
		Title:  title,
	}
	if ok, _ := dlg.ShowOpenMultiple(owner); !ok {
		return "", false
	}
	if len(dlg.FilePaths) != 1 {
		showErrorCustom(owner, chainTitle, chainOneFileText)
		return "", false
	}
	return dlg.FilePaths[0], true
}

// chainLoadConfigFile reads one .conf file into a config.
func chainLoadConfigFile(path string) (*conf.Config, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return conf.FromWgQuickWithUnknownEncoding(string(text), name)
}

// chainTakenNames lists every tunnel name the manager knows about, so the
// automatic name never collides with an existing one.
func chainTakenNames() []string {
	names := []string{}
	if tunnels, err := manager.IPCClientTunnels(); err == nil {
		for _, tunnel := range tunnels {
			names = append(names, tunnel.Name)
		}
	}
	if stored, err := conf.ListConfigNames(); err == nil {
		names = append(names, stored...)
	}
	return names
}

// chainCreatePair stores the outer hop first, then the visible one.
func chainCreatePair(hop1, hop2 *conf.Config) error {
	chainRemoveByName(hop2.Name)
	chainRemoveByName(hop1.Name)
	if _, err := manager.IPCClientNewTunnel(hop1); err != nil {
		return err
	}
	if _, err := manager.IPCClientNewTunnel(hop2); err != nil {
		return err
	}
	return nil
}

func chainRemoveByName(name string) {
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return
	}
	for _, tunnel := range tunnels {
		if strings.EqualFold(tunnel.Name, name) {
			victim := tunnel
			victim.Delete()
			victim.WaitForStop()
		}
	}
}

// chainDeleteTunnel removes a tunnel and, when it is the visible end of a
// chain, its hidden outer hop as well.
func chainDeleteTunnel(tunnel manager.Tunnel) error {
	err := tunnel.Delete()
	tunnel.WaitForStop()
	hidden := conf.ChainHiddenHopName(tunnel.Name)
	if !strings.EqualFold(hidden, tunnel.Name) {
		chainRemoveByName(hidden)
	}
	return err
}

// chainBeforeEdit keeps the hidden hop in step when the visible tunnel is
// edited, renamed, or when its WARP half was changed in the editor.
// config is the edited config, oldName the previous name.
func chainBeforeEdit(oldName string, config *conf.Config) {
	if config == nil {
		return
	}
	pending := chainPendingHop1
	chainPendingHop1 = nil

	oldHidden := conf.ChainHiddenHopName(oldName)
	if strings.EqualFold(oldHidden, oldName) {
		return
	}
	newHidden := conf.ChainHiddenHopName(config.Name)
	existing, err := chainStoredHopConfig(oldHidden)
	if err != nil && pending == nil {
		return // an ordinary tunnel, nothing to keep in step
	}

	hopConfig := pending
	if hopConfig == nil {
		if strings.EqualFold(newHidden, oldHidden) {
			// nothing changed about the outer hop
			config.Interface.PinEndpointVia = oldHidden
			return
		}
		hopConfig = existing
	}
	hopConfig.Name = newHidden
	hopConfig.Interface.TableOff = true

	chainRemoveByName(oldHidden)
	if !strings.EqualFold(newHidden, oldHidden) {
		chainRemoveByName(newHidden)
	}
	if _, err := manager.IPCClientNewTunnel(hopConfig); err != nil {
		return
	}
	config.Interface.PinEndpointVia = newHidden
}

// ---------------------------------------------------------------------------
// One editor window for both halves of the chain.
//
// The visible tunnel is shown as usual, and the outer WARP hop is appended
// below it with every line prefixed by "#!". The stock parser treats those
// lines as comments, so nothing else in the program has to know about them,
// while the user can read and change both configs in one place.
// ---------------------------------------------------------------------------

const chainHopPrefix = "#!"

// chainHopErrorText prefixes parse errors coming from the "#!" half.
const chainHopErrorText = "Внешнее звено (строки #!): "

// chainPendingHop1 holds the outer hop parsed out of the editor window,
// waiting for the edit to be applied. The edit dialog is modal, so a single
// slot is enough.
var chainPendingHop1 *conf.Config

// chainStoredHopConfig reads the config of a hidden hop the only way the
// interface can: through the manager. The window runs unprivileged, so it is
// not allowed to open the configuration files itself, which is why the WARP
// half used to be missing from the editor.
func chainStoredHopConfig(name string) (*conf.Config, error) {
	tunnels, ipcErr := manager.IPCClientTunnels()
	if ipcErr == nil {
		for _, tunnel := range tunnels {
			if !strings.EqualFold(tunnel.Name, name) {
				continue
			}
			holder := tunnel
			stored, err := holder.StoredConfig()
			if err != nil {
				return nil, err
			}
			copied := stored
			return &copied, nil
		}
	}
	stored, err := conf.LoadFromName(name)
	if err == nil {
		return stored, nil
	}
	if ipcErr != nil {
		return nil, ipcErr
	}
	return nil, err
}

// chainEditorText builds the text shown in the edit window.
func chainEditorText(tunnel *manager.Tunnel, config *conf.Config) string {
	chainPendingHop1 = nil
	text := config.ToWgQuick()
	if tunnel == nil {
		return text
	}
	hidden := conf.ChainHiddenHopName(tunnel.Name)
	if strings.EqualFold(hidden, tunnel.Name) {
		return text
	}
	hopConfig, err := chainStoredHopConfig(hidden)
	if err != nil {
		return text
	}
	return chainComposeEditorText(text, hopConfig.ToWgQuick())
}

// chainComposeEditorText glues the inner config and the prefixed outer one.
func chainComposeEditorText(mainText string, hopText string) string {
	cr := string([]byte{13})
	var b strings.Builder
	b.WriteString("# ===== ЦЕПОЧКА, ЗВЕНО 2: Amnezia (внутреннее) =====" + chainNL)
	b.WriteString(strings.TrimRight(strings.ReplaceAll(mainText, cr, ""), " \t"+chainNL) + chainNL2)
	b.WriteString("# ===== ЦЕПОЧКА, ЗВЕНО 1: WARP (внешнее) =====" + chainNL)
	b.WriteString("# Строки ниже начинаются с \"#!\", это второй конфиг цепочки." + chainNL)
	b.WriteString("# Меняй их как обычные строки, но префикс \"#!\" сохраняй." + chainNL)
	b.WriteString("# Удалишь все такие строки, и внешнее звено останется как было." + chainNL)
	for _, line := range strings.Split(strings.ReplaceAll(hopText, cr, ""), chainNL) {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			b.WriteString(chainHopPrefix + chainNL)
			continue
		}
		b.WriteString(chainHopPrefix + " " + line + chainNL)
	}
	return b.String()
}

// chainSplitEditorText separates the ordinary config from the "#!" lines.
func chainSplitEditorText(text string) (string, string) {
	cr := string([]byte{13})
	var main strings.Builder
	var hop strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(text, cr, ""), chainNL) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, chainHopPrefix) {
			rest := strings.TrimPrefix(trimmed, chainHopPrefix)
			rest = strings.TrimPrefix(rest, " ")
			hop.WriteString(rest + chainNL)
			continue
		}
		main.WriteString(line + chainNL)
	}
	return main.String(), hop.String()
}

// chainStashHop1 parses the "#!" half and keeps it until the edit is applied.
func chainStashHop1(hopText string, visibleName string) error {
	chainPendingHop1 = nil
	if strings.TrimSpace(hopText) == "" {
		return nil
	}
	hidden := conf.ChainHiddenHopName(visibleName)
	hopConfig, err := conf.FromWgQuick(hopText, hidden)
	if err != nil {
		return err
	}
	hopConfig.Interface.TableOff = true
	if strings.TrimSpace(hopConfig.Interface.PinEndpointVia) == "" {
		alias, err := chainOuterAdapter()
		if err != nil {
			return err
		}
		hopConfig.Interface.PinEndpointVia = alias
	}
	chainPendingHop1 = hopConfig
	return nil
}

// chainKeepHop1 re-attaches the "#!" half after the editor rewrote the text
// on its own, for example when the kill-switch checkbox is toggled.
func chainKeepHop1(oldText string, newMainText string) string {
	_, hop := chainSplitEditorText(oldText)
	if strings.TrimSpace(hop) == "" {
		return newMainText
	}
	return chainComposeEditorText(newMainText, hop)
}

// chainOuterAdapter names the adapter that currently owns the default route,
// which is the one the outer hop has to be pinned to. Tunnel adapters are
// skipped, so rebuilding a chain while it is up still finds the real card.
func chainOuterAdapter() (string, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagDefault)
	if err != nil {
		return "", err
	}
	names := make(map[winipcfg.LUID]string, len(adapters))
	for _, adapter := range adapters {
		names[adapter.LUID] = adapter.FriendlyName()
	}
	rows, err := winipcfg.GetIPForwardTable2(winipcfg.AddressFamily(windows.AF_INET))
	if err != nil {
		return "", err
	}
	bestName := ""
	var bestMetric uint32
	for i := range rows {
		row := &rows[i]
		prefix := row.DestinationPrefix.IPNet()
		ones, _ := prefix.Mask.Size()
		if ones != 0 || prefix.IP == nil || !prefix.IP.IsUnspecified() {
			continue
		}
		nextHop := row.NextHop.IP()
		if nextHop == nil || nextHop.IsUnspecified() {
			continue
		}
		name := names[row.InterfaceLUID]
		if name == "" || conf.ChainIsHiddenHopName(name) || chainIsKnownTunnel(name) {
			continue
		}
		if bestName == "" || row.Metric < bestMetric {
			bestName = name
			bestMetric = row.Metric
		}
	}
	if bestName == "" {
		return "", errors.New("ни на одном адаптере сейчас нет маршрута по умолчанию")
	}
	return bestName, nil
}

// chainIsKnownTunnel keeps the builder from pinning hop 1 to another tunnel.
func chainIsKnownTunnel(name string) bool {
	stored, err := conf.ListConfigNames()
	if err != nil {
		return false
	}
	for _, candidate := range stored {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}
