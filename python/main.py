"""
Клиент API «Профиль IP» Atlorium — геолокация IP-адреса и признаки анонимизации.

Запуск (работает сразу, без регистрации — на демо-ключе):
    pip install -r requirements.txt
    python main.py

Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
ATLORIUM_API_KEY. Код при этом не меняется.
"""

import os
import sys
from dataclasses import dataclass, field

import requests

# Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
# данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
# Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
# поэтому на них можно писать стабильные тесты.
SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1"

API_KEY = os.environ.get("ATLORIUM_API_KEY", SANDBOX_KEY)
BASE_URL = os.environ.get("ATLORIUM_BASE_URL", "https://atlorium.com")

TIMEOUT = 30


class AtloriumError(RuntimeError):
    """Ошибка API. Код HTTP разложен в человекочитаемую причину."""

    REASONS = {
        400: "Неверный IP-адрес (ожидается IPv4 или IPv6; приватные и зарезервированные диапазоны не принимаются)",
        401: "API-ключ отсутствует, просрочен или недействителен",
        402: "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        404: "Профиль для адреса не найден",
        429: "Превышен лимит запросов — повторите позже",
        503: "Источник геоданных временно недоступен (за сбой на своей стороне мы не списываем деньги)",
    }

    def __init__(self, status: int, body: str):
        reason = self.REASONS.get(status, "Неизвестная ошибка")
        super().__init__(f"HTTP {status}: {reason}. Ответ сервера: {body[:200]}")
        self.status = status


def _get(path: str, params: dict | None = None) -> requests.Response:
    response = requests.get(
        f"{BASE_URL}{path}",
        params=params,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Accept": "application/json",
        },
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise AtloriumError(response.status_code, response.text)
    return response


def get_ip_info(ip: str, extended: bool = False) -> dict:
    """Профиль IP-адреса: город, регион, страна, координаты, часовой пояс.

    extended=True добавляет владельца сети (ASN/организация), hostname, признаки
    анонимизации (VPN, прокси, Tor, relay, резидентный прокси), контакт для жалоб
    и отметку о репутации адреса. Тарифицируется отдельно.
    """
    return _get(f"/api/ipinfo/{ip}", {"extended": str(extended).lower()}).json()


# ── Применение данных: оценка риска посетителя ────────────────────────────────
# Профиль сам по себе — просто JSON. Ценность появляется, когда из него делают
# вывод: пускать ли посетителя дальше, требовать ли 2FA, из какого региона его
# обслуживать. Ниже — типовой набор проверок для антифрода и гео-роутинга.


@dataclass
class Verdict:
    risks: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_risky(self) -> bool:
        return bool(self.risks)


def assess_visitor_risk(report: dict) -> Verdict:
    verdict = Verdict()

    # Bogon — адрес из диапазона, который не маршрутизируется в публичном
    # интернете. В заголовке X-Forwarded-For такой адрес означает подделку.
    if report.get("isBogon"):
        verdict.risks.append("Bogon-адрес: не маршрутизируется в публичном интернете (подделка или внутренняя сеть)")
        return verdict

    privacy = report.get("privacy")
    flags = report.get("flags") or {}

    if privacy is None:
        verdict.notes.append(
            "Признаки VPN/прокси/Tor не запрашивались — нужен extended=true"
        )
    else:
        # Tor, VPN, открытый прокси — попытка скрыть настоящее местоположение.
        # Само по себе не преступление, но для платежей это повод усилить проверку.
        if privacy.get("isTor"):
            verdict.risks.append("Tor: трафик идёт через анонимную сеть, настоящее местоположение скрыто")
        if privacy.get("isVpn"):
            verdict.risks.append("VPN: посетитель подменяет своё местоположение")
        if privacy.get("isProxy"):
            verdict.risks.append("Прокси: запрос идёт через промежуточный сервер")
        if privacy.get("isRelay"):
            verdict.risks.append("Приватный relay: геоданные искажены самим оператором relay")

        # Самый весомый флаг. Резидентные прокси — это чужие домашние IP, которые
        # продают как «чистые». Их покупают ровно для того, чтобы обойти антифрод,
        # поэтому легитимному пользователю попасть под этот флаг почти невозможно.
        if privacy.get("isResidentialProxy"):
            verdict.risks.append("Резидентный прокси: сильный признак фрода — такие сети покупают ради обхода антифрода")

        # Хостинг вместо домашнего провайдера — за адресом почти наверняка скрипт,
        # а не живой человек с браузером.
        if privacy.get("isHosting") or flags.get("isHosting"):
            verdict.risks.append("Датацентр, а не домашний провайдер: вероятнее бот или скрипт, чем живой посетитель")

        if privacy.get("serviceName"):
            verdict.notes.append(f"Сервис анонимизации: {privacy['serviceName']}")

    if flags.get("isAnonymous"):
        verdict.risks.append("Сеть помечена как анонимайзер")

    abuse_reports = report.get("abuseReports") or {}
    if abuse_reports.get("flagged"):
        verdict.risks.append("Плохая репутация: адрес фигурирует в базах жалоб (спам, сканирование, брутфорс)")

    # ── Прикладная польза, не связанная с риском ──────────────────────────────
    geo = report.get("geo") or {}
    if geo.get("timezone"):
        verdict.notes.append(f"Часовой пояс: {geo['timezone']} — локализуйте время и окно уведомлений")
    if geo.get("countryCode"):
        verdict.notes.append(f"Страна: {geo['countryCode']} — язык, валюта и ближайший регион обслуживания")

    radius = geo.get("accuracyRadiusKm")
    if radius is not None and int(radius) > 50:
        verdict.notes.append(f"Координаты приблизительные: радиус ±{radius} км — не опирайтесь на город")

    if flags.get("isMobile"):
        verdict.notes.append("Мобильный оператор: IP меняется между запросами — не привязывайте сессию к адресу")
    if flags.get("isSatellite"):
        verdict.notes.append("Спутниковый доступ: большая задержка, гео может расходиться с реальным")
    if flags.get("isAnycast"):
        verdict.notes.append("Anycast-адрес: география условна")

    abuse = report.get("abuse") or {}
    if abuse.get("email"):
        verdict.notes.append(f"Контакт для жалоб: {abuse['email']}")

    return verdict


def _location(geo: dict) -> str:
    parts = [geo.get("city"), geo.get("region"), geo.get("country")]
    return ", ".join(part for part in parts if part) or "неизвестно"


def main() -> int:
    if API_KEY == SANDBOX_KEY:
        print("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n")

    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"

    try:
        # extended=true — иначе не будет ни ASN, ни признаков анонимизации,
        # то есть оценивать риск будет попросту нечем.
        report = get_ip_info(ip, extended=True)
    except AtloriumError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    geo = report.get("geo") or {}
    asn = report.get("asn") or {}

    print(report["ip"])
    print(f"  Местоположение: {_location(geo)}")

    if geo.get("latitude") is not None and geo.get("longitude") is not None:
        radius = geo.get("accuracyRadiusKm")
        suffix = f" (±{radius} км)" if radius is not None else ""
        print(f"  Координаты: {geo['latitude']}, {geo['longitude']}{suffix}")

    if geo.get("timezone"):
        print(f"  Часовой пояс: {geo['timezone']}")
    if report.get("hostname"):
        print(f"  Hostname: {report['hostname']}")
    if asn:
        print(f"  Сеть: {asn.get('asn')} {asn.get('name')} · {asn.get('route')} · тип {asn.get('type')}")

    verdict = assess_visitor_risk(report)
    print()
    if verdict.is_risky:
        print("РИСК-ФЛАГИ:")
        for risk in verdict.risks:
            print(f"  [!] {risk}")
    else:
        print("Риск-флагов не обнаружено.")

    for note in verdict.notes:
        print(f"  [i] {note}")

    print(f"\nУровень профиля: {report.get('tier')}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
