/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 85: the visible strings of the log page and of the error
 * window hub.
 *
 * The patch scripts are pure ASCII by project rule, so Russian text cannot
 * travel inside a patch. Files like this one are copied byte for byte, the
 * same way chainstrings.go is.
 */

package ui

const (
	chainLogClearButton  = "Очистить журнал"
	chainLogClearMenu    = "Очистить журнал"
	chainLogClearAsk     = "Очистить журнал? Записи будут удалены без возможности вернуть их. Если журнал ещё нужен, сначала сохраните его в файл."
	chainLogClearError   = "Журнал не очищен: "
	chainLogClearedLine  = "Журнал очищен из окна программы."

	// Pack 85: the error window hub. A repeated error is not shown again
	// while the same window is still open, and the line below tells how many
	// times it came back, so that nothing is quietly lost.
	chainNoticeTitle     = "AwgChain"
	chainNoticeRepeatOne = "Эта ошибка повторилась ещё один раз, пока окно было открыто."
	chainNoticeRepeatMan = "Эта ошибка повторилась ещё %d раз, пока окно было открыто. Подробности в журнале."

	// Pack 85: the toggle button while a chain is coming up.
	chainStopRaiseButton = "Остановить подъём"
	chainStopRaiseError  = "Подъём не остановлен: "
)
