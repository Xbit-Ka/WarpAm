//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the "MTU" tab, after the mockup of 8 October.
 *
 *   Сеть: Ethernet, шлюз 192.168.1.1. Свой максимум у каждой сети свой.
 *   [Свой максимум и значение в цепочке]
 *     [Пересчитать] WARPv2_84            [1420] 1420  проверено 07.10 16:50, путь 1500
 *     [Пересчитать] warpam, первое звено [1420] 1420  ...
 *     [Пересчитать] warpam, второе звено [1420] 1345  через первое звено
 *   [Проверить все туннели] [Сбросить MTU] удаляет значения этой сети
 *   four lines of memo, the last one red.
 *
 * The own maximum can be typed in: then it is "set by hand"; an empty field
 * takes the hand number away. WarpAm pack 113: the buttons of the tab and
 * the check inside replace a hand number with what they found. The value in the
 * chain is grey, red below 1280. All numbers come from the manager (116),
 * the buttons go to it (117); a check runs there in the background and
 * the tab asks for the table again every two seconds while it is shown.
 */

package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

const (
	chainMTUTabTitle     = "MTU"
	chainMTUNetwork      = "Сеть: %s. Свой максимум у каждой сети свой."
	chainMTUNoNetwork    = "Сеть не найдена: нет адаптера со шлюзом. Проверить MTU сейчас нельзя."
	chainMTUGroup        = "Свой максимум и значение в цепочке"
	chainMTUCheck        = "Пересчитать"
	chainMTUCheckAll     = "Проверить все туннели"
	chainMTUReset        = "Сбросить MTU"
	chainMTUResetNote    = "удаляет значения этой сети"
	chainMTUFirst        = "%s, первое звено"
	chainMTUSecond       = "%s, второе звено"
	chainMTUViaFirst     = "через первое звено"
	chainMTUVia          = "через %s"
	chainMTUChecked      = "проверено %s, путь %d"
	chainMTUInner        = "снижено по проверке изнутри"
	chainMTUManual       = "задано вручную"
	chainMTUFailed       = "проверка не удалась, сервер и запасной адрес не ответили"
	chainMTUNotYet       = "ещё не проверено"
	chainMTUBusy         = "проверяется…"
	chainMTUNoTunnels    = "Туннелей пока нет."
	chainMTUMemoManual   = "Свой максимум можно задать вручную, пересчёт заменит его проверенным."
	chainMTUMemoChain    = "Значение в цепочке считается при каждом подъёме: свой максимум или меньше."
	chainMTUMemoInner    = "«Снижено по проверке изнутри»: сервер туннеля принимает пакеты меньше, чем пропускает путь."
	chainMTUMemoIPv6     = "Красное число ниже 1280: IPv6 внутри этого туннеля работать не будет."
	chainMTURange        = "Свой максимум должен быть от 576 до 1500."
	chainMTUActionError  = "Служба не выполнила действие: "
	chainMTUTableError   = "Служба не отдала таблицу MTU: "
	chainMTUIPv6Floor    = 1280
	chainMTUManualFloor  = 576
	chainMTUManualTop    = 1500
	chainMTURefreshEvery = 2 * time.Second
)

var (
	chainMTUGrey = walk.RGB(120, 120, 120)
	chainMTURed  = walk.RGB(200, 0, 0)
)

// mtuLine is the widgets of one row of the table.
type mtuLine struct {
	tunnel string
	check  *walk.PushButton
	name   *walk.TextLabel
	own    *walk.LineEdit
	chain  *walk.TextLabel
	from   *walk.TextLabel
	// shown is the own maximum the field was last filled with.
	shown string
	// WarpAm pack 113: dirty is true only when the user typed in the
	// field; filling is true while refresh puts a number there. On 8.10 a
	// click on "Пересчитать" disabled the button, the focus jumped into
	// the field of the row, refresh left the focused field with the old
	// 1265, and when the focus left it, 1265 was saved as set by hand.
	dirty   bool
	filling bool
}

// MTUPage is the tab.
type MTUPage struct {
	*walk.TabPage

	network *walk.TextLabel
	group   *walk.GroupBox
	grid    *walk.Composite
	lines   []*mtuLine
	keys    string
	empty   *walk.TextLabel
}

func NewMTUPage() (*MTUPage, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	mp := new(MTUPage)
	var err error
	if mp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(mp)
	mp.SetTitle(chainMTUTabTitle)

	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{18, 18, 18, 18})
	layout.SetSpacing(8)
	if err = mp.SetLayout(layout); err != nil {
		return nil, err
	}

	if mp.network, err = walk.NewTextLabel(mp); err != nil {
		return nil, err
	}

	if mp.group, err = walk.NewGroupBox(mp); err != nil {
		return nil, err
	}
	mp.group.SetTitle(chainMTUGroup)
	groupLayout := walk.NewVBoxLayout()
	groupLayout.SetMargins(walk.Margins{10, 5, 10, 5})
	if err = mp.group.SetLayout(groupLayout); err != nil {
		return nil, err
	}
	if mp.empty, err = walk.NewTextLabel(mp.group); err != nil {
		return nil, err
	}
	mp.empty.SetText(chainMTUNoTunnels)

	buttons, err := chainProxyRow(mp)
	if err != nil {
		return nil, err
	}
	checkAll, err := walk.NewPushButton(buttons)
	if err != nil {
		return nil, err
	}
	checkAll.SetText(chainMTUCheckAll)
	checkAll.Clicked().Attach(func() { mp.act(manager.ChainMTUAction{Do: "checkall"}) })
	reset, err := walk.NewPushButton(buttons)
	if err != nil {
		return nil, err
	}
	reset.SetText(chainMTUReset)
	reset.Clicked().Attach(func() { mp.act(manager.ChainMTUAction{Do: "reset"}) })
	resetNote, err := walk.NewTextLabel(buttons)
	if err != nil {
		return nil, err
	}
	resetNote.SetText(chainMTUResetNote)
	resetNote.SetTextColor(chainMTUGrey)
	if _, err = walk.NewHSpacer(buttons); err != nil {
		return nil, err
	}

	for i, text := range []string{chainMTUMemoManual, chainMTUMemoChain, chainMTUMemoInner, chainMTUMemoIPv6} {
		memo, err := walk.NewTextLabel(mp)
		if err != nil {
			return nil, err
		}
		memo.SetText(text)
		if i == 3 {
			memo.SetTextColor(chainMTURed)
		}
	}

	if _, err = walk.NewVSpacer(mp); err != nil {
		return nil, err
	}

	mp.VisibleChanged().Attach(func() {
		if mp.Visible() {
			mp.refresh()
		}
	})
	go func() {
		for {
			time.Sleep(chainMTURefreshEvery)
			mp.Synchronize(func() {
				if mp.Visible() {
					mp.refresh()
				}
			})
		}
	}()

	disposables.Spare()
	return mp, nil
}

// chainMTUShownName is the name of a row.
func chainMTUShownName(r manager.ChainMTURow) string {
	switch r.Hop {
	case 1:
		return fmt.Sprintf(chainMTUFirst, r.Shown)
	case 2:
		return fmt.Sprintf(chainMTUSecond, r.Shown)
	}
	return r.Shown
}

// chainMTUFromText is the last column of a row.
func chainMTUFromText(r manager.ChainMTURow) string {
	via := ""
	if len(r.Parent) != 0 {
		via = fmt.Sprintf(chainMTUVia, r.Parent)
		if r.Hop == 2 {
			via = chainMTUViaFirst
		}
	}
	switch {
	case r.Busy:
		return chainMTUBusy
	case r.Manual:
		if len(via) != 0 {
			return chainMTUManual + ", " + via
		}
		return chainMTUManual
	case r.Failed:
		return chainMTUFailed
	case r.Inner:
		return chainMTUInner
	case r.Own == 0:
		return chainMTUNotYet
	case len(via) != 0:
		return via
	case r.Path > 0:
		return fmt.Sprintf(chainMTUChecked, r.When.Local().Format("02.01 15:04"), r.Path)
	}
	return ""
}

// build makes the rows anew when the set of tunnels has changed.
func (mp *MTUPage) build(rows []manager.ChainMTURow) {
	if mp.grid != nil {
		mp.grid.Dispose()
		mp.grid = nil
	}
	mp.lines = nil
	mp.empty.SetVisible(len(rows) == 0)
	if len(rows) == 0 {
		return
	}
	grid, err := walk.NewComposite(mp.group)
	if err != nil {
		return
	}
	layout := walk.NewGridLayout()
	layout.SetMargins(walk.Margins{0, 0, 0, 0})
	layout.SetSpacing(6)
	if err = grid.SetLayout(layout); err != nil {
		grid.Dispose()
		return
	}
	mp.grid = grid
	for i, r := range rows {
		line := &mtuLine{tunnel: r.Tunnel}
		if line.check, err = walk.NewPushButton(grid); err != nil {
			return
		}
		line.check.SetText(chainMTUCheck)
		tunnel := r.Tunnel
		line.check.Clicked().Attach(func() { mp.act(manager.ChainMTUAction{Do: "check", Name: tunnel}) })
		if line.name, err = walk.NewTextLabel(grid); err != nil {
			return
		}
		line.name.SetText(chainMTUShownName(r))
		if line.own, err = walk.NewLineEdit(grid); err != nil {
			return
		}
		line.own.SetMaxLength(4)
		line.own.SetMinMaxSizePixels(walk.Size{line.own.IntFrom96DPI(56), 0}, walk.Size{line.own.IntFrom96DPI(56), 0})
		edit := line
		line.own.EditingFinished().Attach(func() { mp.typed(edit) })
		line.own.TextChanged().Attach(func() {
			if !edit.filling {
				edit.dirty = true
			}
		})
		if line.chain, err = walk.NewTextLabel(grid); err != nil {
			return
		}
		if line.from, err = walk.NewTextLabel(grid); err != nil {
			return
		}
		for col, w := range []walk.Widget{line.check, line.name, line.own, line.chain, line.from} {
			layout.SetRange(w, walk.Rectangle{col, i, 1, 1})
		}
		mp.lines = append(mp.lines, line)
	}
}

// refresh reads the table and puts it on screen.
func (mp *MTUPage) refresh() {
	table, err := manager.IPCClientChainMTUTable()
	if err != nil {
		mp.network.SetText(chainMTUTableError + err.Error())
		return
	}
	if len(table.Network) == 0 {
		mp.network.SetText(chainMTUNoNetwork)
	} else {
		mp.network.SetText(fmt.Sprintf(chainMTUNetwork, table.Network))
	}
	keys := make([]string, 0, len(table.Rows))
	for _, r := range table.Rows {
		keys = append(keys, strings.ToLower(r.Tunnel))
	}
	if joined := strings.Join(keys, "|"); joined != mp.keys || len(mp.lines) != len(table.Rows) {
		mp.keys = joined
		mp.build(table.Rows)
	}
	for i, r := range table.Rows {
		if i >= len(mp.lines) {
			break
		}
		line := mp.lines[i]
		own := ""
		if r.Own > 0 && (r.OwnFrom == "check" || r.OwnFrom == "inner" || r.OwnFrom == "manual") {
			own = strconv.Itoa(r.Own)
		}
		// Pack 113: a field the user is not typing in follows the table
		// even when it has the focus.
		if (!line.own.Focused() || !line.dirty) && line.own.Text() != own {
			line.filling = true
			line.own.SetText(own)
			line.filling = false
			line.dirty = false
		}
		line.shown = own
		chain := ""
		if r.Chain > 0 && (len(own) != 0 || len(r.Parent) != 0) {
			chain = strconv.Itoa(r.Chain)
		}
		line.chain.SetText(chain)
		if r.Chain > 0 && r.Chain < chainMTUIPv6Floor {
			line.chain.SetTextColor(chainMTURed)
		} else {
			line.chain.SetTextColor(chainMTUGrey)
		}
		line.from.SetText(chainMTUFromText(r))
		// Pack 113: the button is not disabled while the check runs, so the
		// focus stays on it and never jumps into the field. A second click
		// does nothing while the check of the row is still running.
		line.check.SetEnabled(len(table.Network) != 0)
	}
}

// typed takes the number of a field: a new number is set by hand, an
// empty field takes the hand number away.
func (mp *MTUPage) typed(line *mtuLine) {
	// Pack 113: only what the user typed is a number set by hand.
	if !line.dirty {
		return
	}
	line.dirty = false
	text := strings.TrimSpace(line.own.Text())
	if text == line.shown {
		return
	}
	if len(text) == 0 {
		mp.act(manager.ChainMTUAction{Do: "manual", Name: line.tunnel})
		return
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < chainMTUManualFloor || value > chainMTUManualTop {
		showErrorCustom(mp.Form(), chainTitle, chainMTURange)
		line.filling = true
		line.own.SetText(line.shown)
		line.filling = false
		return
	}
	mp.act(manager.ChainMTUAction{Do: "manual", Name: line.tunnel, Value: value})
}

// act sends a button to the manager and reads the table again.
func (mp *MTUPage) act(a manager.ChainMTUAction) {
	if err := manager.IPCClientChainMTUAction(a); err != nil {
		showErrorCustom(mp.Form(), chainTitle, chainMTUActionError+err.Error())
	}
	mp.refresh()
}
