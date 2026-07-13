# IP geolocation API — IP to country, city, ASN, VPN and proxy detection

[Русский](README.md) · **English**

Ready-to-run examples for the **IP profile API** in six languages: **Python, TypeScript (Node.js), Go, Java, C#, PHP.**
Resolve **IP to country** and city, get coordinates and timezone, run an **ASN lookup** to find the network owner, and — in extended mode — get **VPN, proxy and Tor detection**, residential-proxy flags and **IP reputation**.

Every example **runs out of the box — no signup, no key, no card.** A public demo key is baked in.

```bash
git clone https://github.com/atlorium-api/ip-geolocation-api-client
cd ip-geolocation-api-client/python && pip install -r requirements.txt && python main.py
```

> The demo key returns **realistic mock data**, not real geolocation — which is why 8.8.8.8 comes back from a made-up ISP in the sample output. That is the point: you can write and test the integration before paying. Swap in a live key and the same code returns real data.

---

## What it is for

Payment anti-fraud and risk scoring, geo-routing (nearest service region, default language and currency), timezone-aware scheduling, bot and scraper blocking, content geo-restrictions, log enrichment.

The examples do not just print JSON — they **apply** it. Each ships an `assessVisitorRisk()` function that turns an IP profile into a verdict: is the visitor hiding their real location (VPN, proxy, Tor, relay), are they on a **residential proxy** (bought specifically to defeat anti-fraud, so the single strongest signal), is the address flagged in abuse databases, is it a datacentre rather than a home ISP (a bot, then, not a person). The same call also yields the timezone and country used for localisation and region selection.

## Quick start

Try the API without cloning anything:

```bash
curl -H "Authorization: Bearer ak_sandbox_demo_mockdata_v1" \
     "https://atlorium.com/api/ipinfo/8.8.8.8?extended=true"
```

| Language | Run | Requires |
|----------|-----|----------|
| [Python](python/) | `pip install -r requirements.txt && python main.py` | Python 3.10+ |
| [TypeScript / Node.js](node/) | `npm install && npm start` | Node.js 20+ |
| [Go](go/) | `go run .` | Go 1.22+ |
| [Java](java/) | `java Main.java` | JDK 17+ (no dependencies) |
| [C#](csharp/) | `dotnet run` | .NET 8+ |
| [PHP](php/) | `php main.php` | PHP 8.1+ |

Pass your own IP as an argument: `python main.py 1.1.1.1`

## Authentication

The key goes in the `Authorization` header:

```
Authorization: Bearer YOUR_KEY
```

| Key | Behaviour |
|-----|-----------|
| `ak_sandbox_demo_mockdata_v1` | **Demo key.** Public, shared by everyone. Returns mocks, charges nothing, needs no account. Responses are deterministic, so you can assert on them in tests. |
| Live key | Real geolocation data. Get one at [atlorium.com](https://atlorium.com) |

Switching to a live key requires **no code changes** — every example reads an environment variable:

```bash
export ATLORIUM_API_KEY="ak_your_live_key"
```

Every sandbox response carries the header `X-Atlorium-Sandbox: true`, so mock data can never be mistaken for real data.

## Endpoints

Base URL: `https://atlorium.com`

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/ipinfo/{ip}` | IP profile: geolocation, plus ASN, anonymity flags and reputation when `extended=true` |

### `GET /api/ipinfo/{ip}`

| Parameter | In | Type | Description |
|-----------|----|------|-------------|
| `ip` | path | string | **IPv4 or IPv6**, e.g. `8.8.8.8` or `2606:4700:4700::1111`. Private and reserved ranges are rejected with `400` |
| `extended` | query | bool | Extended profile: network owner (ASN / company), hostname, anonymity flags (VPN, proxy, Tor, relay, residential proxy), abuse contact, reputation flag. Defaults to `false`. **Billed separately** and slower to respond |

## Response fields

| Field | Type | Meaning |
|-------|------|---------|
| `ip` | string | The address the profile was built for |
| `tier` | string | `Basic` — geolocation only; `Extended` — full profile |
| `isBogon` | bool | **Risk flag.** Address is not routable on the public internet (spoofed or internal) |
| `hostname` | string | Reverse DNS record (with `extended=true`) |
| `geo` | object | `{ city, region, regionCode, country, countryCode, continent, continentCode, latitude, longitude, accuracyRadiusKm, postal, timezone, dmaCode, geonameId }` |
| `asn` | object | Network owner (with `extended=true`): `{ asn, name, domain, route, type, rpkiValid }`. `type` is `isp`, `hosting`, `business`, `education` or `government` |
| `company` | object | Organisation the range is registered to: `{ name, domain, route, type }` |
| `flags` | object | `{ isAnonymous, isAnycast, isHosting, isMobile, isSatellite }` |
| `carrier` | object | Mobile carrier for cellular ranges: `{ name, mcc, mnc }` |
| `privacy` | object | **Anonymity flags:** `{ isVpn, isProxy, isTor, isRelay, isHosting, isResidentialProxy, serviceName, lastSeen, percentDaysSeen }` |
| `abuse` | object | Abuse contact: `{ name, email, phone, address, country, network }` |
| `hostedDomains` | object | Domains hosted on the address: `{ total }` |
| `abuseReports` | object | **IP reputation:** `{ flagged, detailsUrl }` — whether the address appears in abuse databases |

`latitude` / `longitude` are the centre of an area, **not the device's position** — always read `accuracyRadiusKm` alongside them.

## Error handling

| Code | Cause | What to do |
|------|-------|------------|
| `400` | Malformed IP address | Check the format. Private (`192.168.0.0/16`, `10.0.0.0/8`) and reserved ranges are rejected |
| `401` | Key missing, expired or invalid | Check the `Authorization` header |
| `402` | Insufficient credit balance | Top up at [atlorium.com](https://atlorium.com) |
| `429` | Rate limit exceeded | Retry with backoff |
| `503` | Geo data source temporarily unavailable | Retry later. **You are not charged for our failures** |

All six examples map these codes to human-readable causes — see the `AtloriumError` class.

## Pricing

**Pay-as-you-go, no subscription** — you pay per successful request; the extended profile is billed separately from the basic one. Current prices: **[atlorium.com/pricing](https://atlorium.com/pricing)**

## FAQ

**How accurate is IP geolocation?** It is an estimate, not a device position. The response returns `accuracyRadiusKm` honestly — when it is over a hundred kilometres, the "city" field is not something to act on. Country resolution is reliable almost always, region usually, an exact city often not. IP geolocation is not suitable for emergency services or legally binding decisions.

**Is VPN / proxy detection 100 % reliable?** No, and nobody's is. Fresh VPN ranges and new proxies enter the databases with a lag, and `isVpn = true` does not mean fraud — plenty of people use a VPN for entirely legitimate reasons. The correct use is not a hard block on one flag but a weight in an overall score, as in `assessVisitorRisk()`.

**How is this different from a free "what is my IP" service?** Free services usually give country and city. Here a single response carries geolocation, the network owner (ASN and its type), reverse DNS, anonymity flags, an abuse contact and a reputation flag — exactly the inputs an anti-fraud rule is built from.

**Do I need to sign up to try it?** No. The demo key is public and works without an account — but it returns mocks, not real data.

**What does `extended=true` add?** Everything beyond basic geolocation: `asn`, `company`, `hostname`, `flags`, `privacy`, `abuse`, `abuseReports`. Without it there is nothing to score, which is why all six examples call `assessVisitorRisk()` with the extended profile. Billed separately.

**Is IPv6 supported?** Yes, the endpoint accepts both IPv4 and IPv6.

## Other Atlorium APIs

The same account and the same key also give you:

- [CIDR calculator](https://github.com/atlorium-api/cidr-subnet-calculator-api-client) — split networks into subnets, IP range membership
- [AML crypto screening](https://github.com/atlorium-api/aml-crypto-screening-api-client) — risk score, sanctions, PEP
- [DNS Lookup](https://github.com/atlorium-api/dns-lookup-api-client) — domain records, MX, SPF, DMARC
- [Card BIN lookup](https://github.com/atlorium-api/bin-lookup-api-client) — issuer, country and card type for checkout antifraud
- [SSL certificate check](https://github.com/atlorium-api/ssl-certificate-check-api-client) — expiry, SAN, chain of trust
- [SWIFT/BIC](https://github.com/atlorium-api/swift-bic-api-client) — ISO-9362 code parsing and pre-transfer checks

Full catalogue: [atlorium.com](https://atlorium.com)

## Links

- **API reference (Swagger):** [atlorium.com/ipinfoAPI](https://atlorium.com/ipinfoAPI)
- **OpenAPI spec:** [ipinfo_en-US.json](https://atlorium.com/openapi/ipinfo_en-US.json)
- **Support:** support@atlorium.com

## License

[MIT](LICENSE)
