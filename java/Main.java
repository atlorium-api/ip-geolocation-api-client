/*
 * Клиент API «Профиль IP» Atlorium — геолокация IP-адреса и признаки анонимизации.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе).
 * Начиная с Java 11 файл запускается напрямую, без компиляции и без зависимостей:
 *
 *     java Main.java
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    /**
     * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
     * данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
     * Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
     * поэтому на них можно писать стабильные тесты.
     */
    static final String SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1";

    static final String API_KEY = envOr("ATLORIUM_API_KEY", SANDBOX_KEY);
    static final String BASE_URL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com");

    static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    static String envOr(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    /** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
    static class AtloriumException extends RuntimeException {
        private static final Map<Integer, String> REASONS = Map.of(
                400, "Неверный IP-адрес (ожидается IPv4 или IPv6; приватные и зарезервированные диапазоны не принимаются)",
                401, "API-ключ отсутствует, просрочен или недействителен",
                402, "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
                404, "Профиль для адреса не найден",
                429, "Превышен лимит запросов — повторите позже",
                503, "Источник геоданных временно недоступен (за сбой на своей стороне мы не списываем деньги)");

        final int status;

        AtloriumException(int status, String body) {
            super("HTTP " + status + ": "
                    + REASONS.getOrDefault(status, "Неизвестная ошибка")
                    + ". Ответ сервера: " + body.substring(0, Math.min(200, body.length())));
            this.status = status;
        }
    }

    static HttpResponse<byte[]> get(String path, String query) throws IOException, InterruptedException {
        String url = BASE_URL + path + (query.isEmpty() ? "" : "?" + query);

        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + API_KEY)
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();

        HttpResponse<byte[]> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new AtloriumException(response.statusCode(),
                    new String(response.body(), StandardCharsets.UTF_8));
        }
        return response;
    }

    /**
     * Профиль IP-адреса: город, регион, страна, координаты, часовой пояс.
     *
     * extended добавляет владельца сети (ASN/организация), hostname, признаки
     * анонимизации (VPN, прокси, Tor, relay, резидентный прокси), контакт для жалоб
     * и отметку о репутации адреса. Тарифицируется отдельно.
     */
    static String getIpInfo(String ip, boolean extended) throws IOException, InterruptedException {
        String path = "/api/ipinfo/" + URLEncoder.encode(ip, StandardCharsets.UTF_8);
        return new String(get(path, "extended=" + extended).body(), StandardCharsets.UTF_8);
    }

    // ── Разбор JSON ──────────────────────────────────────────────────────────
    // Пример намеренно оставлен без внешних зависимостей, чтобы запускаться одной
    // командой `java Main.java`. В рабочем проекте берите Jackson или Gson и
    // маппьте ответ в полноценную запись — эти регулярки существуют только ради
    // отсутствия pom.xml.
    //
    // Ответ вложенный (geo, asn, privacy, flags…), а одинаковые имена полей
    // встречаются на разных уровнях — например, isHosting есть и в privacy, и в
    // flags. Поэтому сначала вырезаем нужный подобъект по балансу скобок и только
    // потом ищем поле внутри него.

    /** Вырезает вложенный объект по имени поля. null — если поля нет или там null. */
    static String obj(String json, String field) {
        if (json == null) {
            return null;
        }
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\\{").matcher(json);
        if (!matcher.find()) {
            return null;
        }
        int depth = 0;
        for (int i = matcher.end() - 1; i < json.length(); i++) {
            char symbol = json.charAt(i);
            if (symbol == '{') {
                depth++;
            } else if (symbol == '}') {
                depth--;
                if (depth == 0) {
                    return json.substring(matcher.end() - 1, i + 1);
                }
            }
        }
        return null;
    }

    static String str(String json, String field) {
        if (json == null) {
            return null;
        }
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return matcher.find() ? matcher.group(1).replace("\\\"", "\"") : null;
    }

    static boolean bool(String json, String field) {
        if (json == null) {
            return false;
        }
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*(true|false)").matcher(json);
        return matcher.find() && "true".equals(matcher.group(1));
    }

    static Double number(String json, String field) {
        if (json == null) {
            return null;
        }
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\"?(-?\\d+(?:\\.\\d+)?)\"?").matcher(json);
        return matcher.find() ? Double.valueOf(matcher.group(1)) : null;
    }

    // ── Применение данных: оценка риска посетителя ────────────────────────────
    // Профиль сам по себе — просто JSON. Ценность появляется, когда из него делают
    // вывод: пускать ли посетителя дальше, требовать ли 2FA, из какого региона его
    // обслуживать. Ниже — типовой набор проверок для антифрода и гео-роутинга.

    record Verdict(List<String> risks, List<String> notes) {
        boolean isRisky() {
            return !risks.isEmpty();
        }
    }

    static Verdict assessVisitorRisk(String report) {
        List<String> risks = new ArrayList<>();
        List<String> notes = new ArrayList<>();

        // Bogon — адрес из диапазона, который не маршрутизируется в публичном
        // интернете. В заголовке X-Forwarded-For такой адрес означает подделку.
        if (bool(report, "isBogon")) {
            risks.add("Bogon-адрес: не маршрутизируется в публичном интернете (подделка или внутренняя сеть)");
            return new Verdict(risks, notes);
        }

        String privacy = obj(report, "privacy");
        String flags = obj(report, "flags");

        if (privacy == null) {
            notes.add("Признаки VPN/прокси/Tor не запрашивались — нужен extended=true");
        } else {
            // Tor, VPN, открытый прокси — попытка скрыть настоящее местоположение.
            // Само по себе не преступление, но для платежей это повод усилить проверку.
            if (bool(privacy, "isTor")) {
                risks.add("Tor: трафик идёт через анонимную сеть, настоящее местоположение скрыто");
            }
            if (bool(privacy, "isVpn")) {
                risks.add("VPN: посетитель подменяет своё местоположение");
            }
            if (bool(privacy, "isProxy")) {
                risks.add("Прокси: запрос идёт через промежуточный сервер");
            }
            if (bool(privacy, "isRelay")) {
                risks.add("Приватный relay: геоданные искажены самим оператором relay");
            }

            // Самый весомый флаг. Резидентные прокси — это чужие домашние IP, которые
            // продают как «чистые». Их покупают ровно для того, чтобы обойти антифрод,
            // поэтому легитимному пользователю попасть под этот флаг почти невозможно.
            if (bool(privacy, "isResidentialProxy")) {
                risks.add("Резидентный прокси: сильный признак фрода — такие сети покупают ради обхода антифрода");
            }

            // Хостинг вместо домашнего провайдера — за адресом почти наверняка скрипт,
            // а не живой человек с браузером.
            if (bool(privacy, "isHosting") || bool(flags, "isHosting")) {
                risks.add("Датацентр, а не домашний провайдер: вероятнее бот или скрипт, чем живой посетитель");
            }

            String service = str(privacy, "serviceName");
            if (service != null) {
                notes.add("Сервис анонимизации: " + service);
            }
        }

        if (bool(flags, "isAnonymous")) {
            risks.add("Сеть помечена как анонимайзер");
        }

        if (bool(obj(report, "abuseReports"), "flagged")) {
            risks.add("Плохая репутация: адрес фигурирует в базах жалоб (спам, сканирование, брутфорс)");
        }

        // ── Прикладная польза, не связанная с риском ──────────────────────────
        String geo = obj(report, "geo");
        String timezone = str(geo, "timezone");
        if (timezone != null) {
            notes.add("Часовой пояс: " + timezone + " — локализуйте время и окно уведомлений");
        }
        String countryCode = str(geo, "countryCode");
        if (countryCode != null) {
            notes.add("Страна: " + countryCode + " — язык, валюта и ближайший регион обслуживания");
        }
        Double radius = number(geo, "accuracyRadiusKm");
        if (radius != null && radius > 50) {
            notes.add(String.format("Координаты приблизительные: радиус ±%.0f км — не опирайтесь на город", radius));
        }

        if (bool(flags, "isMobile")) {
            notes.add("Мобильный оператор: IP меняется между запросами — не привязывайте сессию к адресу");
        }
        if (bool(flags, "isSatellite")) {
            notes.add("Спутниковый доступ: большая задержка, гео может расходиться с реальным");
        }
        if (bool(flags, "isAnycast")) {
            notes.add("Anycast-адрес: география условна");
        }

        String abuseEmail = str(obj(report, "abuse"), "email");
        if (abuseEmail != null) {
            notes.add("Контакт для жалоб: " + abuseEmail);
        }

        return new Verdict(risks, notes);
    }

    static String location(String geo) {
        List<String> parts = new ArrayList<>();
        for (String field : List.of("city", "region", "country")) {
            String value = str(geo, field);
            if (value != null && !value.isBlank()) {
                parts.add(value);
            }
        }
        return parts.isEmpty() ? "неизвестно" : String.join(", ", parts);
    }

    public static void main(String[] args) throws Exception {
        if (API_KEY.equals(SANDBOX_KEY)) {
            System.out.println("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n");
        }

        String ip = args.length > 0 ? args[0] : "8.8.8.8";

        String report;
        try {
            // extended=true — иначе не будет ни ASN, ни признаков анонимизации,
            // то есть оценивать риск будет попросту нечем.
            report = getIpInfo(ip, true);
        } catch (AtloriumException error) {
            System.err.println("Ошибка: " + error.getMessage());
            System.exit(1);
            return;
        }

        String geo = obj(report, "geo");
        String asn = obj(report, "asn");

        System.out.println(str(report, "ip"));
        System.out.println("  Местоположение: " + location(geo));

        Double latitude = number(geo, "latitude");
        Double longitude = number(geo, "longitude");
        if (latitude != null && longitude != null) {
            Double radius = number(geo, "accuracyRadiusKm");
            String suffix = radius == null ? "" : String.format(" (±%.0f км)", radius);
            System.out.println("  Координаты: " + latitude + ", " + longitude + suffix);
        }

        String timezone = str(geo, "timezone");
        if (timezone != null) {
            System.out.println("  Часовой пояс: " + timezone);
        }
        String hostname = str(report, "hostname");
        if (hostname != null) {
            System.out.println("  Hostname: " + hostname);
        }
        if (asn != null) {
            System.out.println("  Сеть: " + str(asn, "asn") + " " + str(asn, "name")
                    + " · " + str(asn, "route") + " · тип " + str(asn, "type"));
        }

        Verdict verdict = assessVisitorRisk(report);
        System.out.println();

        if (verdict.isRisky()) {
            System.out.println("РИСК-ФЛАГИ:");
            verdict.risks().forEach(risk -> System.out.println("  [!] " + risk));
        } else {
            System.out.println("Риск-флагов не обнаружено.");
        }
        verdict.notes().forEach(note -> System.out.println("  [i] " + note));

        System.out.println("\nУровень профиля: " + str(report, "tier") + ".");
    }
}
