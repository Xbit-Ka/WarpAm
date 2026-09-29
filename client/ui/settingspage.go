/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 62: the Settings tab.
 *
 * Against pack 57 only the order and the alignment change, nothing is
 * renamed:
 *   * the heading of the tab is gone
 *   * "start the program with Windows" is the first line of the tab
 *   * the box that lifts the lock when the program is closed stands above
 *     the lock mode
 *   * every control starts at the same left edge: each check box sits in its
 *     own strip with a spacer behind it, because walk centres a child that is
 *     narrower than the column
 *
 * The names NewSettingsPage, reload and save are kept, managewindow.go calls
 * them.
 */

package ui

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

var chainRaiseValues = []string{
	manager.ChainRaiseNone,
	manager.ChainRaiseLast,
	manager.ChainRaiseSelected,
}

var chainRaiseTexts = []string{
	chainSettingsRaiseNone,
	chainSettingsRaiseLast,
	chainSettingsRaisePick,
}

var chainModeValues = []string{
	manager.ChainLockModeNormal,
	manager.ChainLockModeStrict,
	manager.ChainLockModeParanoid,
}

// Pack 70: the "lock engine" setting is gone. The only engine is the
// service, so there is nothing left to choose and nothing on screen that
// can silently turn the kill switch off.

var chainModeTexts = []string{
	chainSettingsModeNormal,
	chainSettingsModeStrict,
	chainSettingsModeParanoid,
}

// Pack 79: the lists of the proxy moved to chainproxypage.go together
// with the settings behind them. The proxy is not a setting of the
// program any more, every tunnel carries its own.

type SettingsPage struct {
	*walk.TabPage
	raiseCombo  *walk.ComboBox
	tunnelCombo *walk.ComboBox
	modeCombo   *walk.ComboBox
	autoCB      *walk.CheckBox
	quitCB      *walk.CheckBox
	lockLabel   *walk.TextLabel
	liftButton  *walk.PushButton
	// lockArms remembers which way the lock button works right now.
	// Pack 71: the button used to lift only.
	lockArms bool
	names       []string
	last        string
	loading     bool
	// loaded is set once reload has really read the settings from the
	// manager. Pack 68 (G5): until then the widgets hold nothing but
	// their defaults, and writing those back is how an unreachable
	// service turned into "the tab forgot everything".
	loaded      bool

	saveMu    sync.Mutex
	saveTimer *time.Timer
}

// chainFlatRow is a one line strip with no indent, so the control inside it
// starts at the same left edge as the controls above and below.
func chainFlatRow(parent walk.Container) (*walk.Composite, error) {
	row, err := walk.NewComposite(parent)
	if err != nil {
		return nil, err
	}
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{0, 0, 0, 0})
	layout.SetSpacing(6)
	if err = row.SetLayout(layout); err != nil {
		return nil, err
	}
	return row, nil
}

func NewSettingsPage() (*SettingsPage, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	sp := new(SettingsPage)
	var err error
	if sp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(sp)

	sp.SetTitle(chainSettingsTabTitle)

	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{18, 18, 18, 18})
	layout.SetSpacing(8)
	if err = sp.SetLayout(layout); err != nil {
		return nil, err
	}

	// 1. Start the program with Windows. First line of the tab, no heading
	// above it. The box lives in its own strip with a spacer behind it,
	// otherwise walk centres it, because it is narrower than the tab.
	autoRow, err := chainFlatRow(sp)
	if err != nil {
		return nil, err
	}
	if sp.autoCB, err = walk.NewCheckBox(autoRow); err != nil {
		return nil, err
	}
	sp.autoCB.SetText(chainSettingsAutoLabel)
	sp.autoCB.SetToolTipText(chainSettingsAutoHint)
	sp.autoCB.CheckedChanged().Attach(sp.queueSave)
	if _, err = walk.NewHSpacer(autoRow); err != nil {
		return nil, err
	}

	// 2. What is raised when Windows starts.
	if sp.raiseCombo, err = walk.NewComboBox(sp); err != nil {
		return nil, err
	}
	sp.raiseCombo.SetModel(chainRaiseTexts)
	sp.raiseCombo.SetCurrentIndex(0)
	sp.raiseCombo.SetToolTipText(chainSettingsRaiseHint)
	sp.raiseCombo.CurrentIndexChanged().Attach(func() {
		sp.followMode()
		sp.queueSave()
	})

	pick, err := chainFlatRow(sp)
	if err != nil {
		return nil, err
	}

	pickLabel, err := walk.NewTextLabel(pick)
	if err != nil {
		return nil, err
	}
	pickLabel.SetText(chainSettingsPickLabel)

	if sp.tunnelCombo, err = walk.NewComboBox(pick); err != nil {
		return nil, err
	}
	sp.tunnelCombo.CurrentIndexChanged().Attach(sp.queueSave)

	if _, err = walk.NewHSpacer(pick); err != nil {
		return nil, err
	}

	// 3. The box that lifts the lock on exit, above the lock mode, in its
	// own strip for the same reason.
	quitRow, err := chainFlatRow(sp)
	if err != nil {
		return nil, err
	}
	if sp.quitCB, err = walk.NewCheckBox(quitRow); err != nil {
		return nil, err
	}
	sp.quitCB.SetText(chainSettingsQuitLabel)
	sp.quitCB.SetToolTipText(chainSettingsQuitHint)
	sp.quitCB.CheckedChanged().Attach(sp.queueSave)
	if _, err = walk.NewHSpacer(quitRow); err != nil {
		return nil, err
	}

	// 4. The lock mode.
	modeRow, err := chainFlatRow(sp)
	if err != nil {
		return nil, err
	}

	modeLabel, err := walk.NewTextLabel(modeRow)
	if err != nil {
		return nil, err
	}
	// Пак 73: режимы закрыты, подпись говорит об этом прямо.
	modeLabel.SetText(chainSettingsModeLabel + chainSettingsModePlanned)

	if sp.modeCombo, err = walk.NewComboBox(modeRow); err != nil {
		return nil, err
	}
	sp.modeCombo.SetModel(chainModeTexts)
	sp.modeCombo.SetCurrentIndex(0)
	// Пак 73: список показан, но выбрать в нём нечего. Строгий и
	// параноидальный режимы отключены целиком (см. chainLockModesEnabled
	// в chainsettings.go), поэтому список заблокирован и всегда стоит на
	// обычном режиме, а подсказка объясняет почему.
	sp.modeCombo.SetEnabled(false)
	sp.modeCombo.SetToolTipText(chainSettingsModeOffHint)
	sp.modeCombo.CurrentIndexChanged().Attach(sp.queueSave)
	// Pack 71: the exit box does nothing in strict and paranoid mode, so
	// it follows the mode on screen instead of lying quietly.
	sp.modeCombo.CurrentIndexChanged().Attach(sp.followLockMode)

	if _, err = walk.NewHSpacer(modeRow); err != nil {
		return nil, err
	}

	// Pack 70: the "lock engine" row used to sit here. It was the only
	// control that could switch the kill switch off for good, and it was
	// removed together with the setting behind it.

	// 5. The state of the lock and the emergency button.
	lockRow, err := chainFlatRow(sp)
	if err != nil {
		return nil, err
	}

	if sp.lockLabel, err = walk.NewTextLabel(lockRow); err != nil {
		return nil, err
	}
	sp.lockLabel.SetText(chainSettingsLockTitle + chainSettingsLockNoSvc)

	if sp.liftButton, err = walk.NewPushButton(lockRow); err != nil {
		return nil, err
	}
	sp.liftButton.SetText(chainSettingsLiftButton)
	sp.liftButton.SetToolTipText(chainSettingsLiftHint)
	sp.liftButton.Clicked().Attach(sp.toggleLock)

	if _, err = walk.NewHSpacer(lockRow); err != nil {
		return nil, err
	}

	// Pack 79: the proxy section of this tab is gone. Protocol, port,
	// binding, login, split mode and what happens when the tunnel is
	// lost now live on the "Proxy" tab, once for every tunnel. The
	// program keeps no proxy setting of its own any more.

	// AwgChain pack 66: the lower part of the tab is hidden on purpose.
	// Hidden: the box that lifts the tunnel and the lock on exit, the lock
	// mode row and the lock state row with its button. The controls are still
	// built and still keep their saved values, only the strips are invisible,
	// so the behaviour of the program does not change.
	// TODO: this block is waiting for more work. To show it again set
	// chainSettingsHideLockUI to false in chainstrings.go and rebuild.
	// Do not delete this code, it is a hide, not a removal.
	if chainSettingsHideLockUI {
		quitRow.SetVisible(false)
		modeRow.SetVisible(false)
		lockRow.SetVisible(false)
	}

	// AwgChain pack 86: the Configs section. It builds its own strips and
	// keeps its state in chainsecurepage.go, so this page needs no new
	// field and nothing above this line changes.
	if err = chainSecureBuild(sp); err != nil {
		return nil, err
	}

	if _, err = walk.NewVSpacer(sp); err != nil {
		return nil, err
	}

	sp.VisibleChanged().Attach(func() {
		if sp.Visible() {
			sp.reload()
			sp.showLock()
		}
	})

	sp.reload()
	sp.watchLock()

	disposables.Spare()
	return sp, nil
}

// mode reads the raise mode the list is showing.
func (sp *SettingsPage) mode() string {
	index := sp.raiseCombo.CurrentIndex()
	if index < 0 || index >= len(chainRaiseValues) {
		return manager.ChainRaiseNone
	}
	return chainRaiseValues[index]
}

// lockMode reads the lock mode the list is showing.
func (sp *SettingsPage) lockMode() string {
	index := sp.modeCombo.CurrentIndex()
	if index < 0 || index >= len(chainModeValues) {
		return manager.ChainLockModeNormal
	}
	return chainModeValues[index]
}

// followMode enables the tunnel list only in the "chosen tunnel" mode.
func (sp *SettingsPage) followMode() {
	enabled := sp.mode() == manager.ChainRaiseSelected && len(sp.names) > 0
	sp.tunnelCombo.SetEnabled(enabled)
}

// reload fills the page from the manager without writing anything back.
func (sp *SettingsPage) reload() {
	sp.loading = true
	defer func() {
		sp.loading = false
		sp.followMode()
	}()

	global, err := manager.IPCClientChainGlobal()
	if err != nil {
		// Pack 70: a failed reload leaves the page with stale or empty
		// boxes, so it must not be allowed to save them back. sp.loaded was
		// only ever set, never cleared.
		sp.loaded = false
		return
	}
	sp.last = global.LastTunnel

	names, err := manager.IPCClientChainPickList()
	if err != nil || len(names) == 0 {
		names = nil
		tunnels, tunnelsErr := manager.IPCClientTunnels()
		if tunnelsErr == nil {
			for i := range tunnels {
				if manager.ChainIsHiddenHop(tunnels[i].Name) {
					continue
				}
				names = append(names, tunnels[i].Name)
			}
		}
	}
	// Pack 70: the tunnel chosen for the start stays in the list even when
	// the pick list does not offer it (its config is gone, it became a
	// hop). The box used to fall back to the first name, and the next save
	// - one click on any other box was enough - silently re-pointed the
	// start-up raise at that first tunnel.
	if want := strings.TrimSpace(global.RaiseTunnel); len(want) != 0 {
		found := false
		for i := range names {
			if strings.EqualFold(names[i], want) {
				found = true
				break
			}
		}
		if !found {
			names = append(names, want)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})
	sp.names = names

	if len(names) == 0 {
		sp.tunnelCombo.SetModel([]string{chainSettingsNoTunnels})
		sp.tunnelCombo.SetCurrentIndex(0)
	} else {
		sp.tunnelCombo.SetModel(names)
		index := 0
		for i := range names {
			if strings.EqualFold(names[i], global.RaiseTunnel) {
				index = i
				break
			}
		}
		sp.tunnelCombo.SetCurrentIndex(index)
	}

	raise := global.Mode()
	for i := range chainRaiseValues {
		if chainRaiseValues[i] == raise {
			sp.raiseCombo.SetCurrentIndex(i)
			break
		}
	}

	// Пак 73: что бы ни лежало в файле настроек, на экране стоит обычный
	// режим, потому что работает именно он. Показывать «паранойя» над
	// выключенным режимом было бы обманом.
	sp.modeCombo.SetCurrentIndex(0)

	sp.autoCB.SetChecked(global.AutoStart)
	sp.quitCB.SetChecked(global.LiftLockOnQuit)

	// Pack 71: the exit box is greyed out in the modes that ignore it.
	sp.followLockMode()

	// Pack 68 (G5): from here on the page really shows the settings, so
	// it is allowed to write them back.
	sp.loaded = true
}

// queueSave writes the page back once, a short moment after the last change,
// so one click on a box is one write and not three.
func (sp *SettingsPage) queueSave() {
	if sp.loading {
		return
	}

	sp.saveMu.Lock()
	if sp.saveTimer != nil {
		sp.saveTimer.Stop()
	}
	sp.saveTimer = time.AfterFunc(400*time.Millisecond, func() {
		sp.Synchronize(sp.save)
	})
	sp.saveMu.Unlock()
}

// save writes the page back to the manager, unless the page is being
// filled or was never filled in the first place.
func (sp *SettingsPage) save() {
	if sp.loading {
		return
	}
	if !sp.loaded {
		// Pack 68 (G5): reload returns silently when the pipe to the
		// service is not there, which happens while the service is being
		// restarted. The page then held empty boxes, and any click, or
		// even the tab becoming visible, saved that emptiness over the
		// real settings: autostart off, raise mode none.
		return
	}

	raise := sp.mode()
	global := manager.ChainGlobalSettings{
		RaiseMode:      raise,
		RaiseOnStart:   raise != manager.ChainRaiseNone,
		LastTunnel:     sp.last,
		AutoStart:      sp.autoCB.Checked(),
		LiftLockOnQuit: sp.quitCB.Checked(),
		// Пак 73: страница всегда пишет обычный режим, так старая
		// «паранойя» в файле настроек лечится первым же сохранением.
		LockMode:       manager.ChainLockModeNormal,
		// Pack 70: the engine is not a setting any more. The page always
		// writes the service engine back, so an old "off" left in the file
		// is healed by the first save.
		LockEngine:     manager.ChainLockEngineService,
	}
	index := sp.tunnelCombo.CurrentIndex()
	if index >= 0 && index < len(sp.names) {
		global.RaiseTunnel = sp.names[index]
	}

	err := manager.IPCClientChainGlobalSave(global)
	if err != nil {
		showErrorCustom(nil, chainSettingsTabTitle, chainSettingsSaveError+err.Error())
	}
}

// toggleLock is the lock button. Pack 71: it works both ways now. With the
// machine closed it opens it, with the machine open it closes it, so a lock
// lifted by hand can be put back without raising a tunnel first.
func (sp *SettingsPage) toggleLock() {
	if sp.lockArms {
		if err := manager.IPCClientChainArmLock(); err != nil {
			showErrorCustom(nil, chainSettingsTabTitle, chainSettingsArmError+err.Error())
			return
		}
		sp.showLock()
		return
	}

	if err := manager.IPCClientChainLiftLock(); err != nil {
		showErrorCustom(nil, chainSettingsTabTitle, chainSettingsLiftError+err.Error())
		return
	}
	sp.showLock()
}

// Pack 79: chainPickValue and chainPickedValue moved to
// chainproxypage.go as chainProxyPick and chainProxyPicked, and the three
// proxy helpers of this page (the password hash, the greying of the login
// boxes and the state line) went with the section they served.

// followLockMode greys out the exit box in the modes that ignore it.
func (sp *SettingsPage) followLockMode() {
	mode := sp.lockMode()
	if mode == manager.ChainLockModeStrict || mode == manager.ChainLockModeParanoid {
		sp.quitCB.SetEnabled(false)
		sp.quitCB.SetText(chainSettingsQuitLabel + chainSettingsQuitNoop)
		sp.quitCB.SetToolTipText(chainSettingsQuitNoopHint)
		return
	}
	sp.quitCB.SetEnabled(true)
	sp.quitCB.SetText(chainSettingsQuitLabel)
	sp.quitCB.SetToolTipText(chainSettingsQuitHint)
}

// showLock asks the manager about the lock and writes the answer on the line.
func (sp *SettingsPage) showLock() {
	// AwgChain pack 66: the lock line is hidden, there is nothing to write
	// on it and no reason to ask the manager.
	if chainSettingsHideLockUI {
		return
	}

	text := chainSettingsLockTitle + chainSettingsLockNoSvc
	closed := false
	plain := false
	answered := false

	info, err := manager.IPCClientChainStatus()
	if err == nil {
		answered = true
		// Pack 71: a tunnel that is not a chain never gets a kill switch,
		// and saying "open" about it reads like something is broken.
		plain = len(info.Leaf) > 0 && !info.LeafIsChain && !info.BootLockOn
		switch {
		case plain:
			text = chainSettingsLockTitle + chainSettingsLockPlain
		case !info.LockOn:
			text = chainSettingsLockTitle + chainSettingsLockOff
		case len(info.LockLeaf) > 0:
			text = chainSettingsLockTitle + fmt.Sprintf(chainSettingsLockOnLeaf, info.LockLeaf)
			closed = true
		default:
			text = chainSettingsLockTitle + chainSettingsLockOn
			closed = true
		}
	}

	sp.lockLabel.SetText(text)

	// Pack 71: the button follows the state. Closed machine - it opens;
	// open machine - it closes. For a plain tunnel there is nothing to
	// close, so it stays grey.
	sp.lockArms = !closed
	if closed {
		sp.liftButton.SetText(chainSettingsLiftButton)
		sp.liftButton.SetToolTipText(chainSettingsLiftHint)
	} else {
		sp.liftButton.SetText(chainSettingsArmButton)
		sp.liftButton.SetToolTipText(chainSettingsArmHint)
	}
	sp.liftButton.SetEnabled(answered && !plain)
}

// watchLock keeps the lock line fresh while the tab is on screen.
func (sp *SettingsPage) watchLock() {
	// AwgChain pack 66: nothing to refresh while the lock line is hidden.
	if chainSettingsHideLockUI {
		return
	}

	go func() {
		for {
			time.Sleep(2 * time.Second)
			sp.Synchronize(func() {
				if sp.Visible() {
					sp.showLock()
				}
			})
		}
	}()
}
