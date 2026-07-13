// Клиент API «Профиль IP» Atlorium — геолокация IP-адреса и признаки анонимизации.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//     dotnet run
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.

using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

// Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
// данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
// Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
// поэтому на них можно писать стабильные тесты.
const string SandboxKey = "ak_sandbox_demo_mockdata_v1";

var apiKey = Environment.GetEnvironmentVariable("ATLORIUM_API_KEY") ?? SandboxKey;
var baseUrl = Environment.GetEnvironmentVariable("ATLORIUM_BASE_URL") ?? "https://atlorium.com";

using var http = new HttpClient
{
    BaseAddress = new Uri(baseUrl),
    Timeout = TimeSpan.FromSeconds(30),
};
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

var client = new IpInfoClient(http);

if (apiKey == SandboxKey)
{
    Console.WriteLine("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n");
}

var ip = args.Length > 0 ? args[0] : "8.8.8.8";

IpReport report;
try
{
    // extended: true — иначе не будет ни ASN, ни признаков анонимизации,
    // то есть оценивать риск будет попросту нечем.
    report = await client.GetIpInfoAsync(ip, extended: true);
}
catch (AtloriumException error)
{
    Console.Error.WriteLine($"Ошибка: {error.Message}");
    return 1;
}

var geo = report.Geo;
var asn = report.Asn;

Console.WriteLine(report.Ip);
Console.WriteLine($"  Местоположение: {Describe.Location(geo)}");

if (geo is { Latitude: { } latitude, Longitude: { } longitude })
{
    var suffix = geo.AccuracyRadiusKm is { } radius ? $" (±{radius} км)" : "";
    var invariant = CultureInfo.InvariantCulture;
    Console.WriteLine($"  Координаты: {latitude.ToString(invariant)}, {longitude.ToString(invariant)}{suffix}");
}

if (geo?.Timezone is { Length: > 0 } timezone)
{
    Console.WriteLine($"  Часовой пояс: {timezone}");
}
if (report.Hostname is { Length: > 0 } hostname)
{
    Console.WriteLine($"  Hostname: {hostname}");
}
if (asn is not null)
{
    Console.WriteLine($"  Сеть: {asn.Asn} {asn.Name} · {asn.Route} · тип {asn.Type}");
}

var verdict = VisitorRiskAssessment.Assess(report);
Console.WriteLine();

if (verdict.IsRisky)
{
    Console.WriteLine("РИСК-ФЛАГИ:");
    foreach (var risk in verdict.Risks)
    {
        Console.WriteLine($"  [!] {risk}");
    }
}
else
{
    Console.WriteLine("Риск-флагов не обнаружено.");
}

foreach (var note in verdict.Notes)
{
    Console.WriteLine($"  [i] {note}");
}

Console.WriteLine($"\nУровень профиля: {report.Tier}.");
return 0;

// ── Клиент ───────────────────────────────────────────────────────────────────

/// <summary>Ошибка API: HTTP-код разложен в человекочитаемую причину.</summary>
public sealed class AtloriumException(HttpStatusCode status, string body)
    : Exception($"HTTP {(int)status}: {Explain(status)}. Ответ сервера: {body[..Math.Min(200, body.Length)]}")
{
    public HttpStatusCode Status { get; } = status;

    private static string Explain(HttpStatusCode status) => (int)status switch
    {
        400 => "Неверный IP-адрес (ожидается IPv4 или IPv6; приватные и зарезервированные диапазоны не принимаются)",
        401 => "API-ключ отсутствует, просрочен или недействителен",
        402 => "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        404 => "Профиль для адреса не найден",
        429 => "Превышен лимит запросов — повторите позже",
        503 => "Источник геоданных временно недоступен (за сбой на своей стороне мы не списываем деньги)",
        _ => "Неизвестная ошибка",
    };
}

public sealed class IpInfoClient(HttpClient http)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Профиль IP-адреса: город, регион, страна, координаты, часовой пояс.
    /// </summary>
    /// <param name="extended">
    /// Добавляет владельца сети (ASN/организация), hostname, признаки анонимизации
    /// (VPN, прокси, Tor, relay, резидентный прокси), контакт для жалоб и отметку
    /// о репутации адреса. Тарифицируется отдельно.
    /// </param>
    public async Task<IpReport> GetIpInfoAsync(string ip, bool extended = false)
    {
        var path = $"/api/ipinfo/{Uri.EscapeDataString(ip)}?extended={extended.ToString().ToLowerInvariant()}";

        using var response = await http.GetAsync(path);
        if (!response.IsSuccessStatusCode)
        {
            throw new AtloriumException(response.StatusCode, await response.Content.ReadAsStringAsync());
        }

        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<IpReport>(json, JsonOptions)
               ?? throw new InvalidOperationException("Пустой ответ API.");
    }
}

// ── Модель ответа ────────────────────────────────────────────────────────────

/// <summary>Геолокация адреса.</summary>
public sealed record GeoInfo
{
    public string? City { get; init; }
    public string? Region { get; init; }
    public string? RegionCode { get; init; }
    public string? Country { get; init; }
    public string? CountryCode { get; init; }
    public string? Continent { get; init; }
    public double? Latitude { get; init; }
    public double? Longitude { get; init; }
    public string? Postal { get; init; }
    public string? Timezone { get; init; }

    /// <summary>Радиус, в пределах которого координаты можно считать верными.</summary>
    public int? AccuracyRadiusKm { get; init; }
}

/// <summary>Владелец сети: автономная система, к которой принадлежит адрес.</summary>
public sealed record AsnInfo
{
    public string? Asn { get; init; }
    public string? Name { get; init; }
    public string? Domain { get; init; }

    /// <summary>Префикс сети в CIDR-нотации, например 32.114.83.0/24.</summary>
    public string? Route { get; init; }

    /// <summary>isp — провайдер, hosting — датацентр, business, education, government.</summary>
    public string? Type { get; init; }

    public bool? RpkiValid { get; init; }
}

public sealed record CompanyInfo
{
    public string? Name { get; init; }
    public string? Domain { get; init; }
    public string? Route { get; init; }
    public string? Type { get; init; }
}

/// <summary>Характеристики самой сети (только при extended=true).</summary>
public sealed record NetworkFlags
{
    public bool? IsAnonymous { get; init; }
    public bool? IsAnycast { get; init; }
    public bool? IsHosting { get; init; }
    public bool? IsMobile { get; init; }
    public bool? IsSatellite { get; init; }
}

/// <summary>Признаки анонимизации (только при extended=true).</summary>
public sealed record PrivacyInfo
{
    public bool? IsVpn { get; init; }
    public bool? IsProxy { get; init; }
    public bool? IsTor { get; init; }
    public bool? IsRelay { get; init; }
    public bool? IsHosting { get; init; }
    public bool? IsResidentialProxy { get; init; }

    /// <summary>Имя сервиса-анонимайзера, если он опознан.</summary>
    public string? ServiceName { get; init; }

    public string? LastSeen { get; init; }
    public int? PercentDaysSeen { get; init; }
}

/// <summary>Куда писать жалобу на активность с этого адреса.</summary>
public sealed record AbuseInfo
{
    public string? Name { get; init; }
    public string? Email { get; init; }
    public string? Phone { get; init; }
    public string? Address { get; init; }
    public string? Country { get; init; }
    public string? Network { get; init; }
}

public sealed record AbuseReportsInfo
{
    /// <summary>Адрес фигурирует в базах жалоб.</summary>
    public bool Flagged { get; init; }

    public string? DetailsUrl { get; init; }
}

public sealed record CarrierInfo
{
    public string? Name { get; init; }
    public string? Mcc { get; init; }
    public string? Mnc { get; init; }
}

public sealed record HostedDomainsInfo
{
    public int? Total { get; init; }
}

/// <summary>Профиль IP-адреса.</summary>
public sealed record IpReport
{
    public string Ip { get; init; } = "";

    /// <summary>Basic — только геолокация; Extended — плюс ASN, privacy, abuse.</summary>
    public string Tier { get; init; } = "";

    /// <summary>Адрес из диапазона, который не маршрутизируется в публичном интернете.</summary>
    public bool IsBogon { get; init; }

    public string? Hostname { get; init; }
    public GeoInfo? Geo { get; init; }
    public AsnInfo? Asn { get; init; }
    public CompanyInfo? Company { get; init; }
    public NetworkFlags? Flags { get; init; }
    public CarrierInfo? Carrier { get; init; }
    public PrivacyInfo? Privacy { get; init; }
    public AbuseInfo? Abuse { get; init; }
    public HostedDomainsInfo? HostedDomains { get; init; }
    public AbuseReportsInfo? AbuseReports { get; init; }
}

// ── Применение данных: оценка риска посетителя ────────────────────────────────
// Профиль сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: пускать ли посетителя дальше, требовать ли 2FA, из какого региона его
// обслуживать. Ниже — типовой набор проверок для антифрода и гео-роутинга.

public sealed record Verdict(IReadOnlyList<string> Risks, IReadOnlyList<string> Notes)
{
    public bool IsRisky => Risks.Count > 0;
}

public static class Describe
{
    public static string Location(GeoInfo? geo)
    {
        var parts = new[] { geo?.City, geo?.Region, geo?.Country }
            .Where(part => !string.IsNullOrWhiteSpace(part))
            .ToArray();

        return parts.Length > 0 ? string.Join(", ", parts) : "неизвестно";
    }
}

public static class VisitorRiskAssessment
{
    public static Verdict Assess(IpReport report)
    {
        var risks = new List<string>();
        var notes = new List<string>();

        // Bogon — адрес из диапазона, который не маршрутизируется в публичном
        // интернете. В заголовке X-Forwarded-For такой адрес означает подделку.
        if (report.IsBogon)
        {
            risks.Add("Bogon-адрес: не маршрутизируется в публичном интернете (подделка или внутренняя сеть)");
            return new Verdict(risks, notes);
        }

        var privacy = report.Privacy;
        var flags = report.Flags;

        if (privacy is null)
        {
            notes.Add("Признаки VPN/прокси/Tor не запрашивались — нужен extended=true");
        }
        else
        {
            // Tor, VPN, открытый прокси — попытка скрыть настоящее местоположение.
            // Само по себе не преступление, но для платежей это повод усилить проверку.
            if (privacy.IsTor == true)
            {
                risks.Add("Tor: трафик идёт через анонимную сеть, настоящее местоположение скрыто");
            }
            if (privacy.IsVpn == true)
            {
                risks.Add("VPN: посетитель подменяет своё местоположение");
            }
            if (privacy.IsProxy == true)
            {
                risks.Add("Прокси: запрос идёт через промежуточный сервер");
            }
            if (privacy.IsRelay == true)
            {
                risks.Add("Приватный relay: геоданные искажены самим оператором relay");
            }

            // Самый весомый флаг. Резидентные прокси — это чужие домашние IP, которые
            // продают как «чистые». Их покупают ровно для того, чтобы обойти антифрод,
            // поэтому легитимному пользователю попасть под этот флаг почти невозможно.
            if (privacy.IsResidentialProxy == true)
            {
                risks.Add("Резидентный прокси: сильный признак фрода — такие сети покупают ради обхода антифрода");
            }

            // Хостинг вместо домашнего провайдера — за адресом почти наверняка скрипт,
            // а не живой человек с браузером.
            if (privacy.IsHosting == true || flags?.IsHosting == true)
            {
                risks.Add("Датацентр, а не домашний провайдер: вероятнее бот или скрипт, чем живой посетитель");
            }

            if (privacy.ServiceName is { Length: > 0 } service)
            {
                notes.Add($"Сервис анонимизации: {service}");
            }
        }

        if (flags?.IsAnonymous == true)
        {
            risks.Add("Сеть помечена как анонимайзер");
        }

        if (report.AbuseReports?.Flagged == true)
        {
            risks.Add("Плохая репутация: адрес фигурирует в базах жалоб (спам, сканирование, брутфорс)");
        }

        // ── Прикладная польза, не связанная с риском ──────────────────────────
        var geo = report.Geo;
        if (geo?.Timezone is { Length: > 0 } timezone)
        {
            notes.Add($"Часовой пояс: {timezone} — локализуйте время и окно уведомлений");
        }
        if (geo?.CountryCode is { Length: > 0 } countryCode)
        {
            notes.Add($"Страна: {countryCode} — язык, валюта и ближайший регион обслуживания");
        }
        if (geo?.AccuracyRadiusKm is > 50 and { } radius)
        {
            notes.Add($"Координаты приблизительные: радиус ±{radius} км — не опирайтесь на город");
        }

        if (flags?.IsMobile == true)
        {
            notes.Add("Мобильный оператор: IP меняется между запросами — не привязывайте сессию к адресу");
        }
        if (flags?.IsSatellite == true)
        {
            notes.Add("Спутниковый доступ: большая задержка, гео может расходиться с реальным");
        }
        if (flags?.IsAnycast == true)
        {
            notes.Add("Anycast-адрес: география условна");
        }

        if (report.Abuse?.Email is { Length: > 0 } abuseEmail)
        {
            notes.Add($"Контакт для жалоб: {abuseEmail}");
        }

        return new Verdict(risks, notes);
    }
}
