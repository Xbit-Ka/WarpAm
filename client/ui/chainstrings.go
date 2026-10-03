/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 57: every visible string of the interface lives here.
 *
 * The patch scripts are pure ASCII by project rule, so they cannot carry
 * Russian text. This file is copied byte for byte instead.
 *
 * Everything pack 55 and pack 56 declared is kept, other files depend on
 * these names.
 */

package ui

const (
	chainProtectLabel = "Защита от утечек:"
	chainProtectOn    = "включена"
	chainProtectOff   = "выключена"
	chainProtectOther = "включена для %s"
	chainProtectGuard = "включена (отдельной охраной)"
	chainProtectNoSvc = "неизвестна: служба не отвечает"

	chainCheckLockLabel = "Блокировать трафик мимо туннеля (kill switch)"
	chainCheckLockHint  = "Пока туннель поднят, наружу выпускаются только пакеты самой цепочки. Режим замка выбирается на вкладке «Настройки»."
	chainCheckIPv6Label = "Блокировать IPv6"
	chainCheckIPv6Hint  = "IPv6 блокируется фильтром, пока туннель поднят. Адаптеры и настройки Windows не трогаются."
	chainCheckLANLabel  = "Разрешить локальную сеть"
	chainCheckLANHint   = "Принтеры, NAS, роутер и доступ к этой машине по локальной сети при закрытом замке."
	chainCheckChainOnlyHint = "Работает только для сдвоенного туннеля (цепочки). У обычного туннеля эта настройка ничего не меняет."
	chainCheckSaveError = "Настройки туннеля не сохранены: "

	chainSettingsTabTitle   = "Настройки"
	chainSettingsHeader     = "Защита и автозапуск"
	chainSettingsRaiseLabel = "Поднимать туннель при старте Windows"
	chainSettingsRaiseHint  = "Служба поднимет выбранный туннель после загрузки, не дожидаясь входа в систему."
	chainSettingsPickLabel  = "Туннель:"
	chainSettingsQuitLabel  = "При выходе из программы опускать туннель и снимать замок"
	chainSettingsQuitHint   = "Срабатывает только на «Выход» в меню трея. Закрытие окна крестиком и выключение Windows замок не снимают."
	chainSettingsNoTunnels  = "(туннелей нет)"
	chainSettingsSaveError  = "Настройки не сохранены: "

	// Pack 56: the three raise modes, the autostart box and the lock line.
	chainSettingsRaiseNone  = "При старте Windows ничего не подключать"
	chainSettingsRaiseLast  = "Подключать последний использованный туннель"
	chainSettingsRaisePick  = "Подключать выбранный туннель:"
	chainSettingsAutoLabel  = "Запускать программу вместе с Windows"
	chainSettingsAutoHint   = "Переключает тип запуска службы WarpAmManager: автоматически или вручную."
	chainSettingsLockTitle  = "Замок сейчас: "
	chainSettingsLockOn     = "закрыт"
	chainSettingsLockOnLeaf = "закрыт для %s"
	chainSettingsLockOff    = "открыт"
	chainSettingsLockNoSvc  = "неизвестно, служба не отвечает"
	chainSettingsLiftButton = "Снять замок сейчас"
	chainSettingsLiftHint   = "Открывает машину, не дожидаясь подъёма туннеля. Нужно в строгом и параноидальном режиме."
	chainSettingsLiftError  = "Замок не снят: "

	// Пак 71: кнопка замка работает в обе стороны, а не только на снятие.
	chainSettingsArmButton = "Поставить замок сейчас"
	chainSettingsArmHint   = "Закрывает машину прямо сейчас. Если цепочка поднята, замок встаёт вокруг неё. Если цепочки нет и выбран параноидальный режим, ставится замок без туннеля, наружу не уходит ничего."
	chainSettingsArmError  = "Замок не поставлен: "

	// Пак 71: одиночный (не цепочный) туннель замком не защищается,
	// и об этом надо говорить прямо, а не молчать.
	chainSettingsLockPlain = "для одиночного туннеля замок не предусмотрен"

	// Пак 71: в строгом и параноидальном режиме галочка выхода не
	// действует, поэтому она гасится и подписывается.
	chainSettingsQuitNoop = " (в строгом и параноидальном режиме не действует)"
	chainSettingsQuitNoopHint = "В строгом и параноидальном режиме выход из программы намеренно оставляет цепочку поднятой, а замок закрытым. Смените режим замка на обычный, чтобы галочка заработала."

	// Pack 57: the lock mode moved here, next to the other lock settings.
	chainSettingsModeLabel    = "Режим замка:"
	chainSettingsModeHint     = "Обычный режим открывает машину сразу после отключения туннеля. Строгий и параноидальный оставляют замок закрытым, пока его не снять кнопкой ниже."
	chainSettingsModeNormal   = "Обычный: замок снимается вместе с туннелем"
	chainSettingsModeStrict   = "Строгий: замок остаётся после отключения"
	chainSettingsModeParanoid = "Паранойя: замок и при старте Windows, до подъёма цепочки"
	// Пак 73: режимы выключены до того, как служба перестанет гасить себя
	// при выходе из окна, а фильтры замка станут постоянными.
	chainSettingsModePlanned = " (в планах)"
	chainSettingsModeOffHint = "Строгий и параноидальный режимы временно отключены. Замок живёт вместе со службой: он встаёт с цепочкой и снимается с ней. Режимы вернутся, когда служба перестанет выключаться вместе с окном, а фильтры замка станут постоянными."

	// Пак 74: локальный прокси. Сначала то, что видно в редакторе туннеля.
	// Пак 79: строки прокси переехали на свою вкладку, в редакторе
	// туннеля их больше нет.

	// Вкладка «Настройки», раздел прокси.
	// ------------------------------------------------------------------
	// Пак 79: вкладка «Прокси». Всё, что раньше стояло в настройках
	// программы, теперь настраивается у каждого туннеля отдельно.
	// ------------------------------------------------------------------

	chainProxyTabTitle      = "Прокси"
	chainProxyTabTitleFor   = "%s прокси"
	chainProxyPickTunnel    = "Выберите туннель в списке на вкладке «Туннели»: настройки прокси у каждого свои."
	chainProxyEnableLabel   = "Включить прокси для этого туннеля"
	chainProxyEnableHint    = "Пока галочка снята, всё ниже выключено и в настройки не пишется. Когда она стоит, программа держит локальный порт, пока туннель поднят, и отправляет всё, что туда приходит, строго в этот туннель."

	chainProxyProtoLabel = "Протокол:"
	chainProxyProtoHint  = "Оба протокола живут на одном порту: первый байт соединения говорит, SOCKS5 это или HTTP."
	chainProxyProtoSocks = "SOCKS5 (TCP и UDP)"
	chainProxyProtoHTTP  = "HTTP CONNECT"
	chainProxyProtoBoth  = "Оба сразу"

	chainProxyPortLabel = "Порт:"
	chainProxyPortHint  = "Номер порта этого туннеля, по умолчанию 1080. У каждого туннеля он свой; если два поднятых туннеля получат один номер, второй напишет в журнал, что порт занят."

	chainProxyBindLabel = "Доступ:"
	chainProxyBindHint  = "Раздача в локальную сеть открывает порт для других машин, поэтому логин и пароль там обязательны."
	chainProxyBindLocal = "Только этот компьютер (127.0.0.1)"
	chainProxyBindLAN   = "Ещё и локальная сеть"

	chainProxyUserLabel = "Логин:"
	chainProxyPassLabel = "Пароль:"
	chainProxyPassHint  = "Пароль не хранится: в настройках лежит только его хэш с солью. Звёздочки означают, что пароль уже задан; не трогайте их или оставьте поле пустым, чтобы пароль не менялся. Смена логина пароль не сбрасывает."
	chainProxyLoginNeed = "Для раздачи в локальную сеть нужны логин и пароль, иначе прокси не запустится.\r\nПравило брандмауэра программа ставит сама."

	// Pack 97.
	chainProxyPassMask    = "********"
	chainProxyPassSet     = "Пароль: задан."
	chainProxyPassUnset   = "Пароль: не задан."
	chainProxyPassAgain   = "Пароль был сохранён старым способом, вместе с логином. После смены логина введите пароль заново: до этого прокси не запустится."
	chainProxyAddrTitle   = "Адрес для других машин"
	chainProxyAddrLocal   = "нет, прокси слушает только этот компьютер"
	chainProxyAddrMissing = "не найден адаптер Ethernet или Wi‑Fi со шлюзом"
	chainProxyLoginFails  = "Отказано во входе: %d раз с %s, проверьте логин на той машине."

	chainProxySplitLabel = "Только через прокси: адрес машины в интернете не меняется"
	chainProxySplitHint  = "Туннель не забирает маршрут по умолчанию и не меняет системный DNS. Обычные программы ходят напрямую, через туннель идёт только то, что обращается к прокси. Замок в этом режиме не ставится: защищает привязка соединений к туннелю и разрыв связи, если туннель пропал."

	chainProxyDownLabel = "Если туннель пропал:"
	chainProxyDownHint  = "Отвечать ошибкой: порт остаётся открытым, но каждое соединение получает честный отказ. Закрывать порт: программа увидит «соединение отклонено»."
	chainProxyDownError = "Отвечать ошибкой"
	chainProxyDownClose = "Закрывать порт"

	chainProxyGraceLabel = "Терпеть пропажу связи, секунд:"
	chainProxyGraceHint  = "Короткий перезапуск хопа не рвёт открытые соединения. Ноль означает рвать сразу."

	chainProxyStateTitle  = "Состояние"
	chainProxyStateOff    = "Прокси для этого туннеля выключен."
	chainProxyStateWait   = "Прокси включён, но не запущен: туннель не поднят."
	chainProxyStateAlive  = "Слушает %s (%s), соединений: %d"
	chainProxyStateDead   = "Слушает %s, но туннель не отвечает, соединения отклоняются"
	chainProxyStateSplit  = "Режим: только прокси, адрес машины не меняется."
	chainProxyStateWith   = "Режим: вместе с туннелем, машина ходит через него как обычно."
	chainProxySaveError   = "Настройки прокси не сохранились: "

	// Pack 84: the manager sends a short word about the proxy, and the
	// window says it in whole sentences. A closed DNS door used to look
	// like a dead site, so it is now named outright, together with what to
	// do about it.
	chainProxyNoteDown       = "Туннель не поднят, поэтому соединения отклоняются."
	chainProxyNoteNoDNS      = "У туннеля нет своего адреса DNS, поэтому прокси откроет адреса, но не имена. Добавьте строку DNS в конфигурацию туннеля."
	chainProxyNoteDNSBlocked = "Замок закрывает порт 53 на этом адаптере, поэтому имена не разбираются. Перезапустите туннель с замком, чтобы дверь DNS была прорезана заново."

	// ------------------------------------------------------------------
	// Пак 80: пометки у туннелей. Одна и та же пометка стоит в списке
	// туннелей и в меню трея, поэтому строк всего две.
	// ------------------------------------------------------------------

	// chainMarkProxyWith — туннель работает обычным туннелем и держит
	// прокси: и то и другое сразу.
	chainMarkProxyWith = " + прокси"
	// chainMarkProxyOnly — туннель везёт только свой прокси, адрес
	// машины в интернете не меняется.
	chainMarkProxyOnly = " прокси"
	// Пак 98: те же две, когда прокси раздаётся и в локальную сеть.
	chainMarkProxyWithLAN = " + прокси лан"
	chainMarkProxyOnlyLAN = " прокси лан"

	// Пак 80: порт прокси занят, туннель не поднимается.
	chainProxyPortBusy = "Туннель не поднят: "

	// Pack 70: the strings of the "lock engine" row are gone with the row.
)

// AwgChain pack 69 (J8): the lower part of the Settings tab is back.
//
// ПАМЯТКА (пак 69): низ вкладки «Настройки» снова виден.
// Показаны: галка «При выходе из программы опускать туннель и снимать замок»,
// строка «Режим замка» и строка «Замок сейчас» с кнопкой «Снять замок сейчас».
// Пак 81: в текстах, которые читает пользователь, тире не используется
// нигде. Ни длинное, ни короткое. Фраза либо перестраивается, либо режется
// на две; из знаков остаются запятая и двоеточие. Это правило действует и
// на все будущие строки, а не только на те, что переписаны в этом паке.
//
// Пак 70: строка «Движок замка» убрана совсем — замок всегда держит служба.
// Флаг chainSettingsHideLockUI оставлен на месте: поставьте true —
// и весь блок снова скроется, ничего не ломая.
const (
	// chainSettingsHideLockUI hides the exit box, the lock mode and the
	// lock state line. Pack 93 sets it to true again: the mode list is
	// disabled and offers no choice, so the strips only confuse. Nothing is
	// removed: the controls are still built and keep their saved values.
	// To bring the strips back set it to false and rebuild.
	chainSettingsHideLockUI = true
)
