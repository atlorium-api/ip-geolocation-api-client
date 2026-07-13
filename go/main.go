// Клиент API «Профиль IP» Atlorium — геолокация IP-адреса и признаки анонимизации.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//
//	go run .
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// SandboxKey — публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ
// (не реальными данными), чтобы можно было встроить интеграцию до оплаты.
// Ответы детерминированы — на них можно писать стабильные тесты.
const SandboxKey = "ak_sandbox_demo_mockdata_v1"

var (
	apiKey  = envOr("ATLORIUM_API_KEY", SandboxKey)
	baseURL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com")
	client  = &http.Client{Timeout: 30 * time.Second}
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// GeoInfo — геолокация адреса.
type GeoInfo struct {
	City             string   `json:"city"`
	Region           string   `json:"region"`
	RegionCode       string   `json:"regionCode"`
	Country          string   `json:"country"`
	CountryCode      string   `json:"countryCode"`
	Continent        string   `json:"continent"`
	Latitude         *float64 `json:"latitude"`
	Longitude        *float64 `json:"longitude"`
	Postal           string   `json:"postal"`
	Timezone         string   `json:"timezone"`
	AccuracyRadiusKm *int     `json:"accuracyRadiusKm"` // радиус достоверности координат
}

// AsnInfo — владелец сети: автономная система, к которой принадлежит адрес.
type AsnInfo struct {
	ASN       string `json:"asn"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Route     string `json:"route"` // префикс сети в CIDR-нотации
	Type      string `json:"type"`  // isp | hosting | business | education | government
	RpkiValid *bool  `json:"rpkiValid"`
}

// CompanyInfo — организация, за которой закреплён адрес.
type CompanyInfo struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Route  string `json:"route"`
	Type   string `json:"type"`
}

// NetworkFlags — характеристики самой сети (только при extended=true).
type NetworkFlags struct {
	IsAnonymous bool `json:"isAnonymous"`
	IsAnycast   bool `json:"isAnycast"`
	IsHosting   bool `json:"isHosting"`
	IsMobile    bool `json:"isMobile"`
	IsSatellite bool `json:"isSatellite"`
}

// PrivacyInfo — признаки анонимизации (только при extended=true).
type PrivacyInfo struct {
	IsVpn              bool   `json:"isVpn"`
	IsProxy            bool   `json:"isProxy"`
	IsTor              bool   `json:"isTor"`
	IsRelay            bool   `json:"isRelay"`
	IsHosting          bool   `json:"isHosting"`
	IsResidentialProxy bool   `json:"isResidentialProxy"`
	ServiceName        string `json:"serviceName"`
	LastSeen           string `json:"lastSeen"`
	PercentDaysSeen    *int   `json:"percentDaysSeen"`
}

// AbuseInfo — куда писать жалобу на активность с этого адреса.
type AbuseInfo struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Address string `json:"address"`
	Country string `json:"country"`
	Network string `json:"network"`
}

// AbuseReportsInfo — репутация адреса в базах жалоб.
type AbuseReportsInfo struct {
	Flagged    bool   `json:"flagged"`
	DetailsURL string `json:"detailsUrl"`
}

// CarrierInfo — мобильный оператор (для адресов сотовых сетей).
type CarrierInfo struct {
	Name string `json:"name"`
	MCC  string `json:"mcc"`
	MNC  string `json:"mnc"`
}

// IpReport — профиль IP-адреса.
type IpReport struct {
	IP            string            `json:"ip"`
	Tier          string            `json:"tier"`    // Basic | Extended
	IsBogon       bool              `json:"isBogon"` // адрес не маршрутизируется в публичном интернете
	Hostname      string            `json:"hostname"`
	Geo           *GeoInfo          `json:"geo"`
	ASN           *AsnInfo          `json:"asn"`
	Company       *CompanyInfo      `json:"company"`
	Flags         *NetworkFlags     `json:"flags"`
	Carrier       *CarrierInfo      `json:"carrier"`
	Privacy       *PrivacyInfo      `json:"privacy"`
	Abuse         *AbuseInfo        `json:"abuse"`
	HostedDomains *HostedDomains    `json:"hostedDomains"`
	AbuseReports  *AbuseReportsInfo `json:"abuseReports"`
}

// HostedDomains — сколько доменов размещено на адресе.
type HostedDomains struct {
	Total *int `json:"total"`
}

// APIError раскладывает HTTP-код в человекочитаемую причину.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	reasons := map[int]string{
		400: "неверный IP-адрес (ожидается IPv4 или IPv6; приватные и зарезервированные диапазоны не принимаются)",
		401: "API-ключ отсутствует, просрочен или недействителен",
		402: "недостаточно кредитов на балансе — пополните на https://atlorium.com",
		404: "профиль для адреса не найден",
		429: "превышен лимит запросов — повторите позже",
		503: "источник геоданных временно недоступен (за сбой на своей стороне мы не списываем деньги)",
	}
	reason, ok := reasons[e.Status]
	if !ok {
		reason = "неизвестная ошибка"
	}
	return fmt.Sprintf("HTTP %d: %s. Ответ сервера: %s", e.Status, reason, e.Body)
}

func get(path string, query url.Values) ([]byte, error) {
	endpoint := baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, &APIError{Status: response.StatusCode, Body: string(body)}
	}
	return body, nil
}

// GetIpInfo возвращает профиль IP-адреса: город, регион, страну, координаты, часовой пояс.
//
// extended=true добавляет владельца сети (ASN/организация), hostname, признаки
// анонимизации (VPN, прокси, Tor, relay, резидентный прокси), контакт для жалоб
// и отметку о репутации адреса. Тарифицируется отдельно.
func GetIpInfo(ip string, extended bool) (*IpReport, error) {
	body, err := get("/api/ipinfo/"+url.PathEscape(ip),
		url.Values{"extended": {strconv.FormatBool(extended)}})
	if err != nil {
		return nil, err
	}
	var report IpReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// ── Применение данных: оценка риска посетителя ────────────────────────────────
// Профиль сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: пускать ли посетителя дальше, требовать ли 2FA, из какого региона его
// обслуживать. Ниже — типовой набор проверок для антифрода и гео-роутинга.

// Verdict — результат оценки посетителя.
type Verdict struct {
	Risks []string
	Notes []string
}

// IsRisky сообщает, найдены ли риск-флаги.
func (v Verdict) IsRisky() bool { return len(v.Risks) > 0 }

// AssessVisitorRisk выносит вердикт по профилю IP: скрывает ли посетитель себя,
// не бот ли это, и из какого региона его обслуживать.
func AssessVisitorRisk(r *IpReport) Verdict {
	var verdict Verdict

	// Bogon — адрес из диапазона, который не маршрутизируется в публичном
	// интернете. В заголовке X-Forwarded-For такой адрес означает подделку.
	if r.IsBogon {
		verdict.Risks = append(verdict.Risks,
			"Bogon-адрес: не маршрутизируется в публичном интернете (подделка или внутренняя сеть)")
		return verdict
	}

	if r.Privacy == nil {
		verdict.Notes = append(verdict.Notes,
			"Признаки VPN/прокси/Tor не запрашивались — нужен extended=true")
	} else {
		// Tor, VPN, открытый прокси — попытка скрыть настоящее местоположение.
		// Само по себе не преступление, но для платежей это повод усилить проверку.
		if r.Privacy.IsTor {
			verdict.Risks = append(verdict.Risks,
				"Tor: трафик идёт через анонимную сеть, настоящее местоположение скрыто")
		}
		if r.Privacy.IsVpn {
			verdict.Risks = append(verdict.Risks, "VPN: посетитель подменяет своё местоположение")
		}
		if r.Privacy.IsProxy {
			verdict.Risks = append(verdict.Risks, "Прокси: запрос идёт через промежуточный сервер")
		}
		if r.Privacy.IsRelay {
			verdict.Risks = append(verdict.Risks,
				"Приватный relay: геоданные искажены самим оператором relay")
		}

		// Самый весомый флаг. Резидентные прокси — это чужие домашние IP, которые
		// продают как «чистые». Их покупают ровно для того, чтобы обойти антифрод,
		// поэтому легитимному пользователю попасть под этот флаг почти невозможно.
		if r.Privacy.IsResidentialProxy {
			verdict.Risks = append(verdict.Risks,
				"Резидентный прокси: сильный признак фрода — такие сети покупают ради обхода антифрода")
		}

		// Хостинг вместо домашнего провайдера — за адресом почти наверняка скрипт,
		// а не живой человек с браузером.
		if r.Privacy.IsHosting || (r.Flags != nil && r.Flags.IsHosting) {
			verdict.Risks = append(verdict.Risks,
				"Датацентр, а не домашний провайдер: вероятнее бот или скрипт, чем живой посетитель")
		}

		if r.Privacy.ServiceName != "" {
			verdict.Notes = append(verdict.Notes, "Сервис анонимизации: "+r.Privacy.ServiceName)
		}
	}

	if r.Flags != nil && r.Flags.IsAnonymous {
		verdict.Risks = append(verdict.Risks, "Сеть помечена как анонимайзер")
	}

	if r.AbuseReports != nil && r.AbuseReports.Flagged {
		verdict.Risks = append(verdict.Risks,
			"Плохая репутация: адрес фигурирует в базах жалоб (спам, сканирование, брутфорс)")
	}

	// ── Прикладная польза, не связанная с риском ──────────────────────────────
	if r.Geo != nil {
		if r.Geo.Timezone != "" {
			verdict.Notes = append(verdict.Notes,
				"Часовой пояс: "+r.Geo.Timezone+" — локализуйте время и окно уведомлений")
		}
		if r.Geo.CountryCode != "" {
			verdict.Notes = append(verdict.Notes,
				"Страна: "+r.Geo.CountryCode+" — язык, валюта и ближайший регион обслуживания")
		}
		if r.Geo.AccuracyRadiusKm != nil && *r.Geo.AccuracyRadiusKm > 50 {
			verdict.Notes = append(verdict.Notes, fmt.Sprintf(
				"Координаты приблизительные: радиус ±%d км — не опирайтесь на город",
				*r.Geo.AccuracyRadiusKm))
		}
	}

	if r.Flags != nil {
		if r.Flags.IsMobile {
			verdict.Notes = append(verdict.Notes,
				"Мобильный оператор: IP меняется между запросами — не привязывайте сессию к адресу")
		}
		if r.Flags.IsSatellite {
			verdict.Notes = append(verdict.Notes,
				"Спутниковый доступ: большая задержка, гео может расходиться с реальным")
		}
		if r.Flags.IsAnycast {
			verdict.Notes = append(verdict.Notes, "Anycast-адрес: география условна")
		}
	}

	if r.Abuse != nil && r.Abuse.Email != "" {
		verdict.Notes = append(verdict.Notes, "Контакт для жалоб: "+r.Abuse.Email)
	}

	return verdict
}

func location(geo *GeoInfo) string {
	if geo == nil {
		return "неизвестно"
	}
	var parts []string
	for _, part := range []string{geo.City, geo.Region, geo.Country} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "неизвестно"
	}
	return strings.Join(parts, ", ")
}

func main() {
	if apiKey == SandboxKey {
		fmt.Println("Демо-ключ: ответы сгенерированы (моки), не реальные данные.")
		fmt.Println()
	}

	ip := "8.8.8.8"
	if len(os.Args) > 1 {
		ip = os.Args[1]
	}

	// extended=true — иначе не будет ни ASN, ни признаков анонимизации,
	// то есть оценивать риск будет попросту нечем.
	report, err := GetIpInfo(ip, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}

	fmt.Println(report.IP)
	fmt.Printf("  Местоположение: %s\n", location(report.Geo))

	if geo := report.Geo; geo != nil {
		if geo.Latitude != nil && geo.Longitude != nil {
			suffix := ""
			if geo.AccuracyRadiusKm != nil {
				suffix = fmt.Sprintf(" (±%d км)", *geo.AccuracyRadiusKm)
			}
			fmt.Printf("  Координаты: %g, %g%s\n", *geo.Latitude, *geo.Longitude, suffix)
		}
		if geo.Timezone != "" {
			fmt.Printf("  Часовой пояс: %s\n", geo.Timezone)
		}
	}
	if report.Hostname != "" {
		fmt.Printf("  Hostname: %s\n", report.Hostname)
	}
	if asn := report.ASN; asn != nil {
		fmt.Printf("  Сеть: %s %s · %s · тип %s\n", asn.ASN, asn.Name, asn.Route, asn.Type)
	}

	verdict := AssessVisitorRisk(report)
	fmt.Println()
	if verdict.IsRisky() {
		fmt.Println("РИСК-ФЛАГИ:")
		for _, risk := range verdict.Risks {
			fmt.Println("  [!]", risk)
		}
	} else {
		fmt.Println("Риск-флагов не обнаружено.")
	}
	for _, note := range verdict.Notes {
		fmt.Println("  [i]", note)
	}

	fmt.Printf("\nУровень профиля: %s.\n", report.Tier)
}
