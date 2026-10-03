# Web Security Headers Auditor

Scan any public URL for missing security headers, TLS/certificate problems, weak
cookie flags and malware reputation. Returns a weighted 0–100 score, a letter
grade, and copy-paste fixes for Nginx and Cloudflare.

Node.js + Express. No build step, no database, no API keys.

---

## Quick start

```bash
npm install
npm start
```

Open **http://localhost:3000**

Type a domain, press Enter. The scheme is optional — we default to `https://`.

```bash
npm run dev     # auto-restart on file changes
node test.js    # 188 assertions, runs fully offline
```

**Requires Node.js 18+** (uses built-in `fetch`, `AbortSignal.timeout` and
`node:tls`). Check with `node -v`.

---

## What's new in v2

**Real TLS inspection.** v1 only checked that a handshake succeeded. v2 opens a
separate `node:tls` socket and reports the actual protocol version, negotiated
cipher, certificate issuer and subject, validity window with days remaining,
SANs and SHA-256 fingerprint — plus whether the chain is actually trusted and
whether the cert is expired or expiring within 30 days.

**Redirect chain tracing.** Every hop is followed manually and rendered as a
timeline with status codes. Downgrades from HTTPS to HTTP anywhere in the chain
are detected and penalised. The redirect target is re-validated against the SSRF
blocklist on each hop, closing the "public URL redirects to `127.0.0.1`" hole.

**Cookie analysis.** Parses every `Set-Cookie` and checks `Secure`, `HttpOnly`
and `SameSite`. Flags missing flags, and flags `SameSite=None` without `Secure`
(which browsers reject outright). Sites that set no cookies are not penalised.

**Two more header checks:** `Cross-Origin-Opener-Policy` (tabnabbing) and
`Cross-Origin-Resource-Policy` (hotlinking / bulk exfiltration).

**More signals:** `security.txt` discovery (RFC 9116), IPv6 support detection,
`Server` / `X-Powered-By` / wildcard-CORS disclosure checks, and
`Content-Type` correctness.

**Six tabs** — Headers, TLS, Cookies, Redirects, Reputation, Raw headers.

**Export** — download the full JSON report, or copy a Markdown report to paste
into a client deliverable.

**Scan history** — last 25 scans in `localStorage`, click to re-run.

**Three themes** — light, dark, and hacker mode. See below.

**Batch API** — `POST /api/batch` scans up to 10 URLs at once.

---

## Themes

Three palettes, switchable from the nav bar or with <kbd>Shift</kbd>+<kbd>T</kbd>.
The choice persists in `localStorage`; first visit follows your OS preference.

| | |
|---|---|
| **Light** | Off-white `slate-50`, charcoal text. Default. |
| **Dark** | Deep navy, softer contrast than pure black. |
| **Hacker** | Pure black + `#00ff41` matrix green, JetBrains Mono everywhere, CRT scanline overlay. |

## Accessibility

- Tabs follow the WAI-ARIA tabs pattern: `role="tablist"`/`tab`/`tabpanel`,
  `aria-selected` kept in sync, and a roving `tabindex` so only the active tab
  is in the tab order.
- <kbd>←</kbd>/<kbd>→</kbd> move between tabs, <kbd>Home</kbd>/<kbd>End</kbd> jump
  to the first/last. <kbd>Tab</kbd> itself is never hijacked.
- Focus rings are preserved rather than suppressed.
- `prefers-reduced-motion` disables the scan spinner, transitions and smooth
  scrolling.
- Remote data (certificate fields, cookie names, redirect URLs, header values,
  threat-feed labels) is rendered with `textContent` and DOM APIs, never HTML
  interpolation.

All three are driven by CSS custom properties, so every component — badges,
tables, code blocks, the score bar — recolours together. Hacker mode also swaps
the font stack and disables the scanline animation under
`prefers-reduced-motion`.

---

## What gets checked

### Headers (60 points)

| Header | Weight | Passes when |
|---|---|---|
| Content-Security-Policy | 18 | Present, and `script-src` / `script-src-elem` / `default-src` restricts sources without `'unsafe-inline'`, `'unsafe-eval'` or `data:` |
| Strict-Transport-Security | 12 | On HTTPS: `max-age ≥ 31536000` **and** `includeSubDomains` **and** `preload` |
| X-Frame-Options | 6 | `DENY` / `SAMEORIGIN`, or CSP `frame-ancestors` present |
| X-Content-Type-Options | 5 | Exactly `nosniff` |
| Referrer-Policy | 5 | Present, not `unsafe-url` or `no-referrer-when-downgrade` |
| Permissions-Policy | 5 | Present, no wildcard on sensitive features |
| Cross-Origin-Opener-Policy | 5 | Exactly `same-origin` |
| Cross-Origin-Resource-Policy | 4 | `same-origin` or `same-site` |

### Transport & cookies (40 points)

| Check | Weight |
|---|---|
| Content-Type correctness | 6 |
| TLS certificate valid & trusted, modern protocol | 10 |
| HTTPS enforced (no plain-HTTP endpoint) | 6 |
| No HTTPS→HTTP downgrade in redirect chain | 6 |
| Cookie flags (`Secure`, `HttpOnly`, `SameSite`) | 12 |

### Grading

`95–100` **A+** · `90–94` **A** · `80–89` **B** · `70–79` **C** · `55–69` **D** · below 55 **F**

A site with no cookies and a clean TLS chain still reaches 100.

---

## API

```bash
# Single scan
curl "http://localhost:3000/api/scan?url=https://example.com"

# Batch (max 10)
curl -X POST http://localhost:3000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com","https://stripe.com"]}'

# Threat feed status
curl http://localhost:3000/api/feeds

# Health
curl http://localhost:3000/api/health
```

### Response shape

```jsonc
{
  "score": 74,
  "grade": "C",
  "scannedUrl": "https://github.com",
  "finalUrl": "https://github.com/",
  "scannedAt": "2026-10-02T22:51:00.000Z",
  "durationMs": 1269,

  "headers": [
    {
      "name": "Content-Security-Policy",
      "key": "content-security-policy",
      "weight": 18,
      "severity": "critical",
      "why": "Limits which scripts, styles and frames a page may load…",
      "present": true,
      "value": "default-src 'none'; …",
      "passed": true,
      "reason": "Script sources are explicitly restricted",
      "detail": "script-src github.githubassets.com 'sha256-…'",
      "notApplicable": false,
      "nginxFix": "add_header Content-Security-Policy \"…\" always;",
      "cloudflareFix": "Transform Rule → Modify Response Header\n…"
    }
  ],

  "redirectChain": [
    { "url": "http://github.com/", "status": 301, "location": "https://github.com/" },
    { "url": "https://github.com/", "status": 206, "location": null }
  ],
  "redirects": 1,
  "tooManyHops": false,

  "tls": {
    "passed": true,
    "reason": "TLSv1.3, certificate valid for 58 more days",
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "authorized": true,
    "weakProtocol": false,
    "expiry": { "status": "valid", "daysRemaining": 58 },
    "certificate": { "issuer": "C=GB, O=Sectigo Limited, …", "validTo": "…", "fingerprint256": "…" }
  },

  "cookies": [ { "name": "logged_in", "secure": true, "httpOnly": true, "sameSite": "lax", "passed": true, "issues": [] } ],
  "cookieSummary": { "total": 3, "insecure": 1 },

  "info": [ { "header": "Server", "value": "GitHub.com", "risk": "low", "note": "…" } ],
  "securityTxt": { "present": true, "status": 200, "contact": "https://hackerone.com/github" },
  "ipv6": { "supported": false, "count": 0 },
  "threatIntel": [ { "source": "URLhaus (abuse.ch)", "status": "clean", "data": { "listed": false, "entryCount": 15040 } } ],
  "rawHeaders": { "content-type": "text/html; charset=utf-8", "…": "…" }
}
```

Errors return `400` with `{ "error": "…" }`.

---

## Threat reputation (free, no API keys)

Both sources are **public bulk feeds**, downloaded once and cached in memory:

| Source | Feed | Cache TTL | Entries |
|---|---|---|---|
| URLhaus (abuse.ch) | `urlhaus.abuse.ch/downloads/text_recent/` | 30 min | ~15,000 |
| OpenPhish | `openphish.com/feed.txt` | 1 hour | ~300 |

URLhaus and PhishTank's *single-URL lookup* APIs now require an Auth-Key or sit
behind bot protection, so this uses their bulk feeds instead — same data, no
key. The first scan spends a few seconds downloading them; after that they're
cached. If a feed is unreachable, stale data is served, and if there's no cache
the UI says so rather than silently reporting "clean".

### Avoiding false positives

Feeds list *paths*, not sites. A naive host match flags all of GitHub, because
URLhaus contains `github.com/<user>/repo` malware links. So:

1. **Exact URL match** (`host + path + query`) → `listed` (red)
2. **Host-only match** → `host listed` (amber, advisory — other paths are bad)
3. **Shared platforms suppress host-level verdicts entirely** — GitHub, GitLab,
   WordPress, Blogspot, Vercel, Netlify, S3, CloudFront, Google Apps Script,
   Pastebin, Imgur and ~30 others

Both the submitted URL *and* the post-redirect URL are checked, since malware
links commonly bounce (`github.com/user/repo` → `raw.githubusercontent.com`).

---

## SSRF protection

This server fetches arbitrary URLs on your behalf, which is the classic SSRF
shape. Blocked before any request:

- Non-HTTP(S) schemes (`file:`, `ftp:`, `gopher:`, …)
- IPv4: `10/8`, `127/8`, `169.254/16` (cloud metadata), `172.16/12`,
  `192.168/16`, `0/8`
- IPv6: `::1`, `fe80::/10`, `fc00::/7` (covers `fc00`–`fdff`), brackets stripped
  first since `new URL('http://[::1]').hostname` returns `[::1]`
- Hostnames: `localhost`, `localtest.me`, `metadata.google.internal`, …
- Empty/unresolvable hostname — refused, since we can't prove it's public
- **Every redirect hop is re-checked**, so a public URL bouncing to `127.0.0.1`
  is blocked mid-chain
- **10s request timeout**, **rate limit** (default 20 req/min/IP)

**Known gap:** hostnames are checked as written, not after DNS resolution, so a
hostname resolving to a private IP would pass. For production, resolve first and
pin the IP.

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `RATE_LIMIT` | `20` | Requests per minute per IP on `/api/*` |
| `TRUST_PROXY` | unset | Set to `1` **only** when running behind a reverse proxy. Left unset, a client can spoof `X-Forwarded-For` and evade the rate limit |

---

## Deploy

Any platform that runs a Node process.

```bash
git init && git add . && git commit -m "Header Auditor"
```

Build command: leave empty · Start command: `npm start`

**Docker**

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV PORT=3000
EXPOSE 3000
CMD ["npm", "start"]
```

```bash
docker build -t header-auditor . && docker run -p 3000:3000 header-auditor
```

**Serverless (Vercel, Netlify):** works, but cold starts pay the full feed
download and the 10s timeout gets tight. A long-running container is better.

---

## Project structure

```
.
├── package.json
├── server.js          # Express app, all analysis, SSRF guard
├── test.js            # 188 offline assertions
└── public/
    └── index.html     # Whole frontend: 3 themes, Tailwind CDN, vanilla JS
```

No bundler, no framework runtime. The frontend is one file that runs as-is.

---

## Known limitations

- **CSP analysis is heuristic.** Directives are parsed properly and `script-src`
  is resolved through `script-src-elem` → `script-src` → `default-src`, but
  nonce entropy, `strict-dynamic` semantics and effective policy across multiple
  policies aren't evaluated. A hash-based or nonce-based CSP passes.
- **No cipher-suite weakness grading.** The negotiated cipher is reported, but
  TLS 1.2 ciphers aren't scored against a weak-cipher blocklist — only TLS 1.0/1.1
  and SSL are flagged as deprecated protocols.
- **Permissions-Policy is a presence + wildcard check**, not a full
  structured-header parse.
- **No DNS-rebinding protection** — see the SSRF section.
- **Rate limiting is in-memory**, so it resets on restart and isn't shared across
  instances. Use Redis for multi-instance deployments.
- **Feed coverage is partial.** URLhaus's `text_recent` feed is recent activity,
  not the full historical database. A clean result is weaker than a VirusTotal
  verdict.
- **Reputation ≠ safety.** "Not listed" means "not on these two lists". "Listed"
  means "reported by a third party" — not confirmed by us.
- **`security.txt` and `IPv6` probes are best-effort** and may fail silently on
  hosts that block the scanner.
- **Checks marked n/a are excluded from scoring entirely** — they count neither
  for nor against the total. Only HSTS is currently n/a-able (HTTP-only sites),
  so HTTPS scans are always graded against the full 100 points and the grade
  thresholds below stay stable.
- **The scanner's own frontend has no CSP.** A security tool serving its own UI
  without `Content-Security-Policy` is an awkward look, but a strict CSP would
  have to inline-hash every script and allow the Tailwind CDN. Response data is
  rendered via `textContent`/DOM APIs rather than HTML interpolation to keep the
  practical risk low.
- **Not a replacement for** [securityheaders.com](https://securityheaders.com) or
  Mozilla Observatory.

---

## License

MIT
