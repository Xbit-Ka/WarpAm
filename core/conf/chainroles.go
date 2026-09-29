package conf

import "strings"

// Оценка того, насколько конфиг похож на внешнее звено (WARP).
// Считаем по тексту конфига, чтобы не зависеть от имён полей структуры.
// 3 - адрес Cloudflare и типичный адрес клиента WARP
// 2 - адрес Cloudflare
// 1 - только типичный адрес клиента WARP
// 0 - ничего похожего
func ChainWarpScore(c *Config) int {
	if c == nil {
		return 0
	}
	score := 0
	if ChainLooksLikeWarp(c) {
		score += 2
	}
	text := c.ToWgQuick()
	if strings.Contains(text, "172.16.0.") {
		score++
	}
	if score > 3 {
		score = 3
	}
	return score
}

// Роли считаются очевидными, если один конфиг заметно «варповее» другого.
func ChainRolesAreCertain(a *Config, b *Config) bool {
	sa := ChainWarpScore(a)
	sb := ChainWarpScore(b)
	if sa == sb {
		return false
	}
	if sa > sb {
		return sa >= 2
	}
	return sb >= 2
}

// Возвращает внешний и внутренний конфиг по оценке.
// Третье значение - уверенность в выборе.
func ChainSortRolesScored(a *Config, b *Config) (*Config, *Config, bool) {
	sure := ChainRolesAreCertain(a, b)
	if ChainWarpScore(b) > ChainWarpScore(a) {
		return b, a, sure
	}
	return a, b, sure
}

// Принудительный порядок: swap = true означает, что внешним считается b.
func ChainSortRolesForced(a *Config, b *Config, swap bool) (*Config, *Config) {
	if swap {
		return b, a
	}
	return a, b
}

// Короткая подсказка для окна выбора ролей.
func ChainRoleHint(c *Config) string {
	if c == nil {
		return ""
	}
	parts := []string{}
	switch ChainWarpScore(c) {
	case 3:
		parts = append(parts, "очень похож на WARP")
	case 2:
		parts = append(parts, "похож на WARP по адресу сервера")
	case 1:
		parts = append(parts, "похож на WARP по адресу клиента")
	default:
		parts = append(parts, "на WARP не похож")
	}
	if len(c.Peers) > 0 {
		parts = append(parts, "сервер "+c.Peers[0].Endpoint.String())
	}
	return strings.Join(parts, ", ")
}
