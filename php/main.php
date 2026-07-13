<?php

/**
 * Клиент API «Профиль IP» Atlorium — геолокация IP-адреса и признаки анонимизации.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   php main.php
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

declare(strict_types=1);

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
 * Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
 * поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const TIMEOUT = 30;

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
final class AtloriumError extends RuntimeException
{
    private const REASONS = [
        400 => 'Неверный IP-адрес (ожидается IPv4 или IPv6; приватные и зарезервированные диапазоны не принимаются)',
        401 => 'API-ключ отсутствует, просрочен или недействителен',
        402 => 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
        404 => 'Профиль для адреса не найден',
        429 => 'Превышен лимит запросов — повторите позже',
        503 => 'Источник геоданных временно недоступен (за сбой на своей стороне мы не списываем деньги)',
    ];

    public function __construct(public readonly int $status, string $body)
    {
        $reason = self::REASONS[$status] ?? 'Неизвестная ошибка';
        parent::__construct(sprintf(
            'HTTP %d: %s. Ответ сервера: %s',
            $status,
            $reason,
            mb_substr($body, 0, 200)
        ));
    }
}

final class IpInfoClient
{
    private string $apiKey;
    private string $baseUrl;

    public function __construct(?string $apiKey = null, ?string $baseUrl = null)
    {
        $this->apiKey = $apiKey ?? (getenv('ATLORIUM_API_KEY') ?: SANDBOX_KEY);
        $this->baseUrl = $baseUrl ?? (getenv('ATLORIUM_BASE_URL') ?: 'https://atlorium.com');
    }

    public function isSandbox(): bool
    {
        return $this->apiKey === SANDBOX_KEY;
    }

    /** @param array<string, string> $params */
    private function get(string $path, array $params = []): string
    {
        $url = $this->baseUrl . $path;
        if ($params !== []) {
            $url .= '?' . http_build_query($params);
        }

        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => TIMEOUT,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $this->apiKey,
                'Accept: application/json',
            ],
        ]);

        $body = curl_exec($curl);
        if ($body === false) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new RuntimeException("Сетевая ошибка: {$error}");
        }

        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);

        if ($status !== 200) {
            throw new AtloriumError($status, (string) $body);
        }

        return (string) $body;
    }

    /**
     * Профиль IP-адреса: город, регион, страна, координаты, часовой пояс.
     *
     * $extended добавляет владельца сети (ASN/организация), hostname, признаки
     * анонимизации (VPN, прокси, Tor, relay, резидентный прокси), контакт для жалоб
     * и отметку о репутации адреса. Тарифицируется отдельно.
     *
     * @return array<string, mixed>
     */
    public function getIpInfo(string $ip, bool $extended = false): array
    {
        $body = $this->get('/api/ipinfo/' . rawurlencode($ip), [
            'extended' => $extended ? 'true' : 'false',
        ]);

        return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    }
}

// ── Применение данных: оценка риска посетителя ────────────────────────────────
// Профиль сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: пускать ли посетителя дальше, требовать ли 2FA, из какого региона его
// обслуживать. Ниже — типовой набор проверок для антифрода и гео-роутинга.

/**
 * @param array<string, mixed> $report
 * @return array{risks: list<string>, notes: list<string>}
 */
function assessVisitorRisk(array $report): array
{
    $risks = [];
    $notes = [];

    // Bogon — адрес из диапазона, который не маршрутизируется в публичном
    // интернете. В заголовке X-Forwarded-For такой адрес означает подделку.
    if ($report['isBogon'] ?? false) {
        return [
            'risks' => ['Bogon-адрес: не маршрутизируется в публичном интернете (подделка или внутренняя сеть)'],
            'notes' => [],
        ];
    }

    $privacy = $report['privacy'] ?? null;
    $flags = $report['flags'] ?? [];

    if ($privacy === null) {
        $notes[] = 'Признаки VPN/прокси/Tor не запрашивались — нужен extended=true';
    } else {
        // Tor, VPN, открытый прокси — попытка скрыть настоящее местоположение.
        // Само по себе не преступление, но для платежей это повод усилить проверку.
        if ($privacy['isTor'] ?? false) {
            $risks[] = 'Tor: трафик идёт через анонимную сеть, настоящее местоположение скрыто';
        }
        if ($privacy['isVpn'] ?? false) {
            $risks[] = 'VPN: посетитель подменяет своё местоположение';
        }
        if ($privacy['isProxy'] ?? false) {
            $risks[] = 'Прокси: запрос идёт через промежуточный сервер';
        }
        if ($privacy['isRelay'] ?? false) {
            $risks[] = 'Приватный relay: геоданные искажены самим оператором relay';
        }

        // Самый весомый флаг. Резидентные прокси — это чужие домашние IP, которые
        // продают как «чистые». Их покупают ровно для того, чтобы обойти антифрод,
        // поэтому легитимному пользователю попасть под этот флаг почти невозможно.
        if ($privacy['isResidentialProxy'] ?? false) {
            $risks[] = 'Резидентный прокси: сильный признак фрода — такие сети покупают ради обхода антифрода';
        }

        // Хостинг вместо домашнего провайдера — за адресом почти наверняка скрипт,
        // а не живой человек с браузером.
        if (($privacy['isHosting'] ?? false) || ($flags['isHosting'] ?? false)) {
            $risks[] = 'Датацентр, а не домашний провайдер: вероятнее бот или скрипт, чем живой посетитель';
        }

        if (!empty($privacy['serviceName'])) {
            $notes[] = 'Сервис анонимизации: ' . $privacy['serviceName'];
        }
    }

    if ($flags['isAnonymous'] ?? false) {
        $risks[] = 'Сеть помечена как анонимайзер';
    }

    if ($report['abuseReports']['flagged'] ?? false) {
        $risks[] = 'Плохая репутация: адрес фигурирует в базах жалоб (спам, сканирование, брутфорс)';
    }

    // ── Прикладная польза, не связанная с риском ──────────────────────────────
    $geo = $report['geo'] ?? [];
    if (!empty($geo['timezone'])) {
        $notes[] = 'Часовой пояс: ' . $geo['timezone'] . ' — локализуйте время и окно уведомлений';
    }
    if (!empty($geo['countryCode'])) {
        $notes[] = 'Страна: ' . $geo['countryCode'] . ' — язык, валюта и ближайший регион обслуживания';
    }

    $radius = $geo['accuracyRadiusKm'] ?? null;
    if ($radius !== null && (int) $radius > 50) {
        $notes[] = 'Координаты приблизительные: радиус ±' . (int) $radius . ' км — не опирайтесь на город';
    }

    if ($flags['isMobile'] ?? false) {
        $notes[] = 'Мобильный оператор: IP меняется между запросами — не привязывайте сессию к адресу';
    }
    if ($flags['isSatellite'] ?? false) {
        $notes[] = 'Спутниковый доступ: большая задержка, гео может расходиться с реальным';
    }
    if ($flags['isAnycast'] ?? false) {
        $notes[] = 'Anycast-адрес: география условна';
    }

    if (!empty($report['abuse']['email'])) {
        $notes[] = 'Контакт для жалоб: ' . $report['abuse']['email'];
    }

    return ['risks' => $risks, 'notes' => $notes];
}

/** @param array<string, mixed> $geo */
function location(array $geo): string
{
    $parts = array_filter([$geo['city'] ?? null, $geo['region'] ?? null, $geo['country'] ?? null]);

    return $parts === [] ? 'неизвестно' : implode(', ', $parts);
}

// ── Демонстрация ─────────────────────────────────────────────────────────────

$client = new IpInfoClient();

if ($client->isSandbox()) {
    echo "Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n\n";
}

$ip = $argv[1] ?? '8.8.8.8';

try {
    // extended=true — иначе не будет ни ASN, ни признаков анонимизации,
    // то есть оценивать риск будет попросту нечем.
    $report = $client->getIpInfo($ip, true);
} catch (AtloriumError $error) {
    fwrite(STDERR, "Ошибка: {$error->getMessage()}\n");
    exit(1);
}

$geo = $report['geo'] ?? [];
$asn = $report['asn'] ?? null;

echo "{$report['ip']}\n";
echo '  Местоположение: ' . location($geo) . "\n";

if (isset($geo['latitude'], $geo['longitude'])) {
    $suffix = isset($geo['accuracyRadiusKm'])
        ? ' (±' . (int) $geo['accuracyRadiusKm'] . ' км)'
        : '';
    echo "  Координаты: {$geo['latitude']}, {$geo['longitude']}{$suffix}\n";
}
if (!empty($geo['timezone'])) {
    echo "  Часовой пояс: {$geo['timezone']}\n";
}
if (!empty($report['hostname'])) {
    echo "  Hostname: {$report['hostname']}\n";
}
if ($asn !== null) {
    echo "  Сеть: {$asn['asn']} {$asn['name']} · {$asn['route']} · тип {$asn['type']}\n";
}

$verdict = assessVisitorRisk($report);
echo "\n";

if ($verdict['risks'] !== []) {
    echo "РИСК-ФЛАГИ:\n";
    foreach ($verdict['risks'] as $risk) {
        echo "  [!] {$risk}\n";
    }
} else {
    echo "Риск-флагов не обнаружено.\n";
}

foreach ($verdict['notes'] as $note) {
    echo "  [i] {$note}\n";
}

echo "\nУровень профиля: {$report['tier']}.\n";
