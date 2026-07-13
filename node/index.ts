/**
 * Клиент API «Профиль IP» Atlorium — геолокация IP-адреса и признаки анонимизации.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   npm install
 *   npm start
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
 * Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
 * поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const API_KEY = process.env.ATLORIUM_API_KEY ?? SANDBOX_KEY;
const BASE_URL = process.env.ATLORIUM_BASE_URL ?? 'https://atlorium.com';

const TIMEOUT_MS = 30_000;

/** Геолокация адреса. */
export interface GeoInfo {
  city: string | null;
  region: string | null;
  regionCode: string | null;
  country: string | null;
  countryCode: string | null;
  continent: string | null;
  continentCode: string | null;
  latitude: number | null;
  longitude: number | null;
  postal: string | null;
  timezone: string | null;
  /** Радиус, в пределах которого координаты можно считать верными. */
  accuracyRadiusKm: number | null;
}

/** Владелец сети: автономная система, к которой принадлежит адрес. */
export interface AsnInfo {
  asn: string | null;
  name: string | null;
  domain: string | null;
  /** Префикс сети в CIDR-нотации, например 32.114.83.0/24. */
  route: string | null;
  /** isp — провайдер, hosting — датацентр, business, education, government. */
  type: string | null;
  rpkiValid: boolean | null;
}

export interface CompanyInfo {
  name: string | null;
  domain: string | null;
  route: string | null;
  type: string | null;
}

/** Характеристики самой сети (только при extended=true). */
export interface NetworkFlags {
  isAnonymous: boolean | null;
  isAnycast: boolean | null;
  isHosting: boolean | null;
  isMobile: boolean | null;
  isSatellite: boolean | null;
}

/** Признаки анонимизации (только при extended=true). */
export interface PrivacyInfo {
  isVpn: boolean | null;
  isProxy: boolean | null;
  isTor: boolean | null;
  isRelay: boolean | null;
  isHosting: boolean | null;
  isResidentialProxy: boolean | null;
  /** Имя сервиса-анонимайзера, если он опознан. */
  serviceName: string | null;
  lastSeen: string | null;
  percentDaysSeen: number | null;
}

/** Куда писать жалобу на активность с этого адреса. */
export interface AbuseInfo {
  name: string | null;
  email: string | null;
  phone: string | null;
  address: string | null;
  country: string | null;
  network: string | null;
}

export interface AbuseReportsInfo {
  /** Адрес фигурирует в базах жалоб. */
  flagged: boolean;
  detailsUrl: string | null;
}

export interface CarrierInfo {
  name: string | null;
  mcc: string | null;
  mnc: string | null;
}

/** Профиль IP-адреса. */
export interface IpReport {
  ip: string;
  /** Basic — только геолокация; Extended — плюс ASN, privacy, abuse. */
  tier: 'Basic' | 'Extended';
  /** Адрес из диапазона, который не маршрутизируется в публичном интернете. */
  isBogon: boolean;
  hostname: string | null;
  geo: GeoInfo | null;
  asn: AsnInfo | null;
  company: CompanyInfo | null;
  flags: NetworkFlags | null;
  carrier: CarrierInfo | null;
  privacy: PrivacyInfo | null;
  abuse: AbuseInfo | null;
  hostedDomains: { total: number | null } | null;
  abuseReports: AbuseReportsInfo | null;
}

const ERROR_REASONS: Record<number, string> = {
  400: 'Неверный IP-адрес (ожидается IPv4 или IPv6; приватные и зарезервированные диапазоны не принимаются)',
  401: 'API-ключ отсутствует, просрочен или недействителен',
  402: 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
  404: 'Профиль для адреса не найден',
  429: 'Превышен лимит запросов — повторите позже',
  503: 'Источник геоданных временно недоступен (за сбой на своей стороне мы не списываем деньги)',
};

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
export class AtloriumError extends Error {
  constructor(readonly status: number, body: string) {
    const reason = ERROR_REASONS[status] ?? 'Неизвестная ошибка';
    super(`HTTP ${status}: ${reason}. Ответ сервера: ${body.slice(0, 200)}`);
    this.name = 'AtloriumError';
  }
}

async function request(path: string, params: Record<string, string> = {}): Promise<Response> {
  const url = new URL(path, BASE_URL);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new AtloriumError(response.status, await response.text());
  }
  return response;
}

/**
 * Профиль IP-адреса: город, регион, страна, координаты, часовой пояс.
 *
 * `extended` добавляет владельца сети (ASN/организация), hostname, признаки
 * анонимизации (VPN, прокси, Tor, relay, резидентный прокси), контакт для жалоб
 * и отметку о репутации адреса. Тарифицируется отдельно.
 */
export async function getIpInfo(ip: string, extended = false): Promise<IpReport> {
  const response = await request(`/api/ipinfo/${encodeURIComponent(ip)}`, {
    extended: String(extended),
  });
  return response.json() as Promise<IpReport>;
}

// ── Применение данных: оценка риска посетителя ────────────────────────────────
// Профиль сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: пускать ли посетителя дальше, требовать ли 2FA, из какого региона его
// обслуживать. Ниже — типовой набор проверок для антифрода и гео-роутинга.

export interface Verdict {
  risks: string[];
  notes: string[];
}

export function assessVisitorRisk(report: IpReport): Verdict {
  const risks: string[] = [];
  const notes: string[] = [];

  // Bogon — адрес из диапазона, который не маршрутизируется в публичном
  // интернете. В заголовке X-Forwarded-For такой адрес означает подделку.
  if (report.isBogon) {
    risks.push('Bogon-адрес: не маршрутизируется в публичном интернете (подделка или внутренняя сеть)');
    return { risks, notes };
  }

  const { privacy, flags } = report;

  if (privacy === null) {
    notes.push('Признаки VPN/прокси/Tor не запрашивались — нужен extended=true');
  } else {
    // Tor, VPN, открытый прокси — попытка скрыть настоящее местоположение.
    // Само по себе не преступление, но для платежей это повод усилить проверку.
    if (privacy.isTor) risks.push('Tor: трафик идёт через анонимную сеть, настоящее местоположение скрыто');
    if (privacy.isVpn) risks.push('VPN: посетитель подменяет своё местоположение');
    if (privacy.isProxy) risks.push('Прокси: запрос идёт через промежуточный сервер');
    if (privacy.isRelay) risks.push('Приватный relay: геоданные искажены самим оператором relay');

    // Самый весомый флаг. Резидентные прокси — это чужие домашние IP, которые
    // продают как «чистые». Их покупают ровно для того, чтобы обойти антифрод,
    // поэтому легитимному пользователю попасть под этот флаг почти невозможно.
    if (privacy.isResidentialProxy) {
      risks.push('Резидентный прокси: сильный признак фрода — такие сети покупают ради обхода антифрода');
    }

    // Хостинг вместо домашнего провайдера — за адресом почти наверняка скрипт,
    // а не живой человек с браузером.
    if (privacy.isHosting || flags?.isHosting) {
      risks.push('Датацентр, а не домашний провайдер: вероятнее бот или скрипт, чем живой посетитель');
    }

    if (privacy.serviceName) notes.push(`Сервис анонимизации: ${privacy.serviceName}`);
  }

  if (flags?.isAnonymous) risks.push('Сеть помечена как анонимайзер');

  if (report.abuseReports?.flagged) {
    risks.push('Плохая репутация: адрес фигурирует в базах жалоб (спам, сканирование, брутфорс)');
  }

  // ── Прикладная польза, не связанная с риском ──────────────────────────────
  const geo = report.geo;
  if (geo?.timezone) notes.push(`Часовой пояс: ${geo.timezone} — локализуйте время и окно уведомлений`);
  if (geo?.countryCode) notes.push(`Страна: ${geo.countryCode} — язык, валюта и ближайший регион обслуживания`);
  if (geo?.accuracyRadiusKm !== null && geo?.accuracyRadiusKm !== undefined && geo.accuracyRadiusKm > 50) {
    notes.push(`Координаты приблизительные: радиус ±${geo.accuracyRadiusKm} км — не опирайтесь на город`);
  }

  if (flags?.isMobile) {
    notes.push('Мобильный оператор: IP меняется между запросами — не привязывайте сессию к адресу');
  }
  if (flags?.isSatellite) {
    notes.push('Спутниковый доступ: большая задержка, гео может расходиться с реальным');
  }
  if (flags?.isAnycast) notes.push('Anycast-адрес: география условна');

  if (report.abuse?.email) notes.push(`Контакт для жалоб: ${report.abuse.email}`);

  return { risks, notes };
}

function location(geo: GeoInfo | null): string {
  const parts = [geo?.city, geo?.region, geo?.country].filter((part): part is string => Boolean(part));
  return parts.length > 0 ? parts.join(', ') : 'неизвестно';
}

async function main(): Promise<void> {
  if (API_KEY === SANDBOX_KEY) {
    console.log('Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n');
  }

  const ip = process.argv[2] ?? '8.8.8.8';

  // extended=true — иначе не будет ни ASN, ни признаков анонимизации,
  // то есть оценивать риск будет попросту нечем.
  const report = await getIpInfo(ip, true);

  const geo = report.geo;
  const asn = report.asn;

  console.log(report.ip);
  console.log(`  Местоположение: ${location(geo)}`);

  if (geo?.latitude !== null && geo?.latitude !== undefined && geo.longitude !== null) {
    const suffix = geo.accuracyRadiusKm !== null ? ` (±${geo.accuracyRadiusKm} км)` : '';
    console.log(`  Координаты: ${geo.latitude}, ${geo.longitude}${suffix}`);
  }
  if (geo?.timezone) console.log(`  Часовой пояс: ${geo.timezone}`);
  if (report.hostname) console.log(`  Hostname: ${report.hostname}`);
  if (asn) {
    console.log(`  Сеть: ${asn.asn} ${asn.name} · ${asn.route} · тип ${asn.type}`);
  }

  const verdict = assessVisitorRisk(report);
  console.log();
  if (verdict.risks.length > 0) {
    console.log('РИСК-ФЛАГИ:');
    verdict.risks.forEach((risk) => console.log(`  [!] ${risk}`));
  } else {
    console.log('Риск-флагов не обнаружено.');
  }
  verdict.notes.forEach((note) => console.log(`  [i] ${note}`));

  console.log(`\nУровень профиля: ${report.tier}.`);
}

// Запуск только когда файл выполняется напрямую, а не импортируется.
if (process.argv[1]?.includes('index')) {
  main().catch((error: unknown) => {
    console.error('Ошибка:', error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
