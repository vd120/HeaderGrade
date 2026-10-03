import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import tls from 'node:tls';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const PORT = process.env.PORT || 3000;

// Resolve assets relative to THIS file, not process.cwd(). Without this the
// server 404s when started from another directory (PM2, systemd, Docker).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

// trust proxy must only be enabled when actually behind a proxy. Trusting one
// hop unconditionally lets a client spoof X-Forwarded-For and evade rate limits.
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '10kb' }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT) || 20,
  message: { error: 'Rate limit reached. Please wait a minute and try again.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

app.use(express.static(PUBLIC_DIR));

// ============================================
// SSRF PROTECTION
// ============================================
const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'localhost.localdomain', 'local', 'localtest.me',
  'metadata', 'metadata.google.internal', 'instance-data',
  '169.254.169.254',
]);

const PRIVATE_IPV4_RANGES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^0\./,
];

// fc00::/7 covers the whole unique-local range fc00::–fdff:ffff:...
const PRIVATE_IPV6_PREFIXES = ['::1', 'fe80:', 'fc', 'fd'];

export function isPrivateIP(hostname) {
  // No hostname means we cannot prove the target is public — refuse.
  if (!hostname) return true;
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) return true;

  const isIPv6 = hostname.startsWith('[') && hostname.endsWith(']');
  const bare = (isIPv6 ? hostname.slice(1, -1) : hostname).toLowerCase();

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(bare)) {
    return PRIVATE_IPV4_RANGES.some(r => r.test(bare));
  }
  if (isIPv6 || (bare.includes(':') && /^[0-9a-f:.]+$/.test(bare))) {
    return PRIVATE_IPV6_PREFIXES.some(p => bare.startsWith(p));
  }
  return false;
}

function assertScannable(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ScanError('Invalid URL format');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new ScanError('Only HTTP and HTTPS protocols are allowed');
  }
  if (isPrivateIP(url.hostname)) {
    throw new ScanError('Scanning local or private network addresses is not allowed');
  }
  return url;
}

class ScanError extends Error {}

// ============================================
// TLS INSPECTION (real cert + protocol data)
// ============================================
const WEAK_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']);

export function inspectTLS(hostname, port = 443) {
  return new Promise((resolve) => {
    let socket;
    try {
      socket = tls.connect({
        host: hostname,
        port,
        servername: /^[\d.]+$/.test(hostname) ? undefined : hostname,
        rejectUnauthorized: false, // inspect even invalid certs
        timeout: 8000
      });
    } catch (e) {
      return resolve({ ok: false, error: e.code || e.message });
    }

    const done = (result) => { try { socket.destroy(); } catch {} resolve(result); };

    socket.on('secureConnect', () => {
      let cert = {};
      try { cert = socket.getPeerCertificate(true) || {}; } catch {}
      const cipher = socket.getCipher() || {};
      const authorized = socket.authorized;
      let authError = null;
      try { authError = socket.authorizationError || null; } catch {}

      done({
        ok: true,
        authorized,
        authorizationError: authError,
        protocol: socket.getProtocol() || null,
        cipher: cipher.name || null,
        cipherBits: cipher.standardName || null,
        cert: {
          subject: flattenName(cert.subject),
          issuer: flattenName(cert.issuer),
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          serialNumber: cert.serialNumber || null,
          fingerprint256: cert.fingerprint256 || null,
          altNames: cert.subjectaltname || null
        }
      });
    });

    socket.on('error', (e) => done({ ok: false, error: e.code || e.message }));
    socket.on('timeout', () => done({ ok: false, error: 'TLS_TIMEOUT' }));
  });
}

function flattenName(name) {
  if (!name) return null;
  const parts = Object.entries(name).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(', ') : v}`);
  return parts.length ? parts.join(', ') : null;
}

function certExpiryInfo(cert) {
  if (!cert?.validTo) return { status: 'unknown', daysRemaining: null };
  const expires = new Date(cert.validTo);
  // An unparseable date yields NaN, and every comparison against NaN is false —
  // which would silently fall through to "valid". Reject it explicitly.
  if (!Number.isFinite(expires.getTime())) return { status: 'unknown', daysRemaining: null };
  // Round rather than floor: a cert expiring in 10 days 23h should read as 11
  // days remaining, not 10.
  const days = Math.round((expires.getTime() - Date.now()) / 86400000);
  if (days < 0) return { status: 'expired', daysRemaining: days };
  if (days <= 7) return { status: 'expiring', daysRemaining: days };
  if (days <= 30) return { status: 'expiring-soon', daysRemaining: days };
  return { status: 'valid', daysRemaining: days };
}

// ============================================
// REDIRECT CHAIN TRACE + HEADER FETCH
// ============================================
const MAX_HOPS = 10;

async function fetchWithChain(startUrl, timeoutMs = 10000) {
  const chain = [];
  let current = startUrl;
  let sawDowngrade = false;
  let prevProtocol = null;
  let sawHttps = false;

  for (let hop = 0; hop < MAX_HOPS; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res;
    try {
      // GET + Range keeps Set-Cookie reliable (HEAD often omits it) while
      // pulling only the first bytes.
      res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'SecurityHeaderAuditor/2.0',
          'Range': 'bytes=0-2047',
          'Accept': '*/*'
        }
      });
    } catch (e) {
      clearTimeout(timer);
      const code = e.code || e.cause?.code || '';
      const msg = `${e.message} ${e.cause?.message || ''} ${e.cause?.code || ''}`;
      throw new ScanError(describeFetchError(e, controller, code, msg));
    } finally {
      clearTimeout(timer);
    }

    // We only need headers. Cancel the body so we don't download the page.
    try { await res.body?.cancel(); } catch {}

    const headers = {};
    for (const [k, v] of res.headers.entries()) headers[k.toLowerCase()] = v;

    const setCookies = typeof res.headers.getSetCookie === 'function'
      ? res.headers.getSetCookie()
      : (headers['set-cookie'] ? [headers['set-cookie']] : []);

    const protocol = new URL(current).protocol;
    if (protocol === 'https:') sawHttps = true;
    if (prevProtocol === 'https:' && protocol === 'http:') sawDowngrade = true;
    prevProtocol = protocol;

    const location = res.headers.get('location');
    chain.push({ hop, url: current, status: res.status, headers, setCookies });

    if (res.status >= 300 && res.status < 400 && location) {
      let next;
      try {
        next = new URL(location, current).toString();
      } catch {
        break;
      }
      // Re-validate every hop: a public URL can redirect to a private one.
      if (isPrivateIP(new URL(next).hostname)) {
        throw new ScanError('Redirect chain leads to a private network address — blocked (possible SSRF).');
      }
      current = next;
      continue;
    }
    break;
  }

  return {
    chain,
    final: chain[chain.length - 1],
    sawDowngrade,
    sawHttps,
    tooManyHops: chain.length >= MAX_HOPS && !!chain[chain.length - 1]?.headers?.location
  };
}

function describeFetchError(e, controller, code, msg) {
  if (e.name === 'AbortError' || controller.signal.aborted) {
    return 'Request timed out — the site did not respond within 10s.';
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return 'DNS lookup failed — domain does not exist or has no DNS records.';
  }
  if (
    code.startsWith('ERR_TLS') || code.startsWith('CERT_') || code.startsWith('DEPTH_') ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    /certificate|cert_|self.signed|selfsigned|SSL|TLS|wrong version number/i.test(msg)
  ) {
    return 'TLS/SSL certificate error — the site uses an invalid or expired certificate.';
  }
  if (code === 'UND_ERR_CONNECT_TIMEOUT' || code === 'ETIMEDOUT') {
    return 'Connection timed out — the server accepted the IP but never responded.';
  }
  if (code === 'ECONNREFUSED') return 'Connection refused — nothing is listening on that port.';
  if (code === 'ECONNRESET' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return 'Connection reset or host unreachable from the scanner.';
  }
  if (/HTTP\/2|ERR_HTTP2|PROTOCOL_ERROR/i.test(msg)) {
    return 'The server rejected the request protocol — it may not support HTTP/2 negotiation.';
  }
  return `Could not reach the site (${code || e.name}).`;
}

// ============================================
// CSP PARSER
// ============================================
export function parseCSP(value) {
  const directives = {};
  for (const part of String(value).split(/[;,]/)) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens.shift().toLowerCase();
    if (!directives[name]) directives[name] = tokens.map(t => t.toLowerCase());
  }
  return directives;
}

// ============================================
// HEADER CHECKS
// ============================================
const NGINX = (line) => `add_header ${line} always;`;

export const HEADER_CHECKS = [
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    severity: 'critical',
    weight: 18,
    why: 'Limits which scripts, styles and frames a page may load. The single most effective XSS mitigation.',
    check: (value) => {
      if (!value) return { pass: false, reason: 'Header is missing' };
      const d = parseCSP(value);
      if (!Object.keys(d).length) return { pass: false, reason: 'Present but contains no directives' };

      const scriptSources = d['script-src-elem'] || d['script-src'] || d['default-src'];
      if (!scriptSources) {
        return { pass: false, reason: 'No script-src or default-src — script sources are unrestricted' };
      }
      const issues = [];
      if (scriptSources.includes("'unsafe-inline'")) issues.push("'unsafe-inline'");
      if (scriptSources.includes("'unsafe-eval'")) issues.push("'unsafe-eval'");
      if (scriptSources.includes('data:')) issues.push('data:');
      if (issues.length) {
        return {
          pass: false,
          reason: `Script sources are permissive: ${issues.join(', ')}`,
          detail: `${d['script-src-elem'] || d['script-src'] ? 'script-src' : 'default-src'} ${scriptSources.join(' ')}`
        };
      }
      return {
        pass: true,
        reason: 'Script sources are explicitly restricted',
        detail: `script-src ${scriptSources.slice(0, 4).join(' ')}${scriptSources.length > 4 ? ' …' : ''}`
      };
    },
    nginxFix: NGINX(`Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"`),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: Content-Security-Policy\nValue: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'; connect-src \'self\'; frame-ancestors \'none\'; base-uri \'self\'; form-action \'self\'; object-src \'none\''
  },
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security',
    severity: 'high',
    weight: 12,
    why: 'Forces the browser to use HTTPS for every future visit, blocking SSL-stripping proxies.',
    check: (value, ctx) => {
      // An HTTP-only site cannot meaningfully set HSTS, so it is marked n/a and
      // excluded from scoring entirely (see headerTotals below) rather than
      // being handed free points for a header that does not apply.
      if (!ctx.isHttps) return { pass: true, reason: 'Not applicable — site is HTTP only', na: true };
      if (!value) return { pass: false, reason: 'Missing on an HTTPS site' };
      const lower = value.toLowerCase();
      // Tolerate whitespace around "=" and a quoted max-age, both of which real
      // servers emit and the HSTS ABNF permits.
      const m = lower.match(/max-age\s*=\s*"?(\d+)"?/);
      const maxAge = m ? parseInt(m[1], 10) : 0;
      const missing = [];
      if (maxAge < 31536000) missing.push('max-age must be ≥ 31536000');
      if (!lower.includes('includesubdomains')) missing.push('includeSubDomains missing');
      if (!lower.includes('preload')) missing.push('preload missing');
      if (missing.length) return { pass: false, reason: missing.join(' · '), detail: value };
      return { pass: true, reason: 'Preload-ready: max-age ≥ 1 year, includeSubDomains, preload', detail: value };
    },
    nginxFix: NGINX('Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: Strict-Transport-Security\nValue: max-age=31536000; includeSubDomains; preload'
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'high',
    weight: 6,
    why: 'Stops other sites framing yours, which is the basis of clickjacking.',
    check: (value, ctx) => {
      const csp = ctx.headers['content-security-policy'] || ctx.headers['content-security-policy-report-only'] || '';
      const hasFrameAncestors = parseCSP(csp)['frame-ancestors'];
      if (!value) {
        if (hasFrameAncestors) return { pass: true, reason: 'Covered by CSP frame-ancestors', detail: hasFrameAncestors.join(' ') };
        return { pass: false, reason: 'Header is missing' };
      }
      const upper = value.toUpperCase();
      if (upper === 'DENY' || upper === 'SAMEORIGIN') return { pass: true, reason: `Set to ${upper}` };
      return { pass: false, reason: `Invalid value: ${value}` };
    },
    nginxFix: NGINX('X-Frame-Options "DENY"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: X-Frame-Options\nValue: DENY'
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: 'medium',
    weight: 5,
    why: 'Prevents browsers from MIME-sniffing an uploaded file into executable JavaScript.',
    check: (value) => {
      if (!value) return { pass: false, reason: 'Header is missing' };
      if (value.toLowerCase() === 'nosniff') return { pass: true, reason: 'Set to nosniff' };
      return { pass: false, reason: `Invalid value: ${value}` };
    },
    nginxFix: NGINX('X-Content-Type-Options "nosniff"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: X-Content-Type-Options\nValue: nosniff'
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'medium',
    weight: 5,
    why: 'Controls how much URL data leaks to third parties when users click an outbound link.',
    check: (value) => {
      if (!value) return { pass: false, reason: 'Header is missing' };
      const lower = value.toLowerCase();
      if (lower.includes('unsafe-url')) return { pass: false, reason: 'unsafe-url leaks the full URL — the weakest policy' };
      if (lower.includes('no-referrer-when-downgrade')) {
        return { pass: false, reason: 'Leaks the full path on HTTPS→HTTP navigations' };
      }
      return { pass: true, reason: `Set to ${value}` };
    },
    nginxFix: NGINX('Referrer-Policy "strict-origin-when-cross-origin"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: Referrer-Policy\nValue: strict-origin-when-cross-origin'
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    severity: 'medium',
    weight: 5,
    why: 'Turns off camera, microphone, geolocation and friends unless a page explicitly re-enables them.',
    check: (value) => {
      if (!value) return { pass: false, reason: 'Header is missing' };
      const lower = value.toLowerCase();
      const permissive = ['geolocation', 'camera', 'microphone', 'payment', 'usb', 'accelerometer', 'gyroscope', 'magnetometer']
        .filter(f => new RegExp(`${f}\\s*=\\s*\\*`).test(lower));
      if (permissive.length) {
        return { pass: false, reason: `Wildcard allows these features everywhere: ${permissive.join(', ')}` };
      }
      return { pass: true, reason: 'Present and restrictive' };
    },
    nginxFix: NGINX('Permissions-Policy "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: Permissions-Policy\nValue: accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
  },
  {
    key: 'cross-origin-opener-policy',
    name: 'Cross-Origin-Opener-Policy',
    severity: 'low',
    weight: 5,
    why: 'Isolates the browsing context so cross-origin pages cannot reach your window object (tabnabbing).',
    check: (value) => {
      if (!value) return { pass: false, reason: 'Header is missing' };
      const v = value.toLowerCase().trim();
      // Must match exactly: a substring test would wrongly accept
      // "same-origin-allow-popups" as "same-origin".
      if (v === 'same-origin') return { pass: true, reason: 'Set to same-origin' };
      if (v === 'same-origin-allow-popups') {
        return { pass: false, reason: 'same-origin-allow-popups still lets cross-origin pages open windows into yours' };
      }
      if (v === 'noopener-allow-popups') {
        return { pass: false, reason: 'noopener-allow-popups provides no opener isolation' };
      }
      if (v === 'unsafe-none') {
        return { pass: false, reason: 'unsafe-none disables isolation entirely' };
      }
      return { pass: false, reason: `Unrecognised value: ${value}` };
    },
    nginxFix: NGINX('Cross-Origin-Opener-Policy "same-origin"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: Cross-Origin-Opener-Policy\nValue: same-origin'
  },
  {
    key: 'cross-origin-resource-policy',
    name: 'Cross-Origin-Resource-Policy',
    severity: 'low',
    weight: 4,
    why: 'Stops other origins from loading your images, fonts and scripts in bulk (hotlinking and data exfiltration).',
    check: (value) => {
      if (!value) return { pass: false, reason: 'Header is missing' };
      const v = value.toLowerCase();
      if (v.includes('same-origin') || v.includes('same-site')) return { pass: true, reason: `Set to ${value}` };
      if (v.includes('cross-origin')) return { pass: false, reason: 'cross-origin permits any site to read these resources' };
      return { pass: true, reason: `Set to ${value}` };
    },
    nginxFix: NGINX('Cross-Origin-Resource-Policy "same-origin"'),
    cloudflareFix: 'Transform Rule → Modify Response Header\nName: Cross-Origin-Resource-Policy\nValue: same-origin'
  }
];

// ============================================
// COOKIE ANALYSIS
// ============================================
export function analyzeCookies(setCookieHeaders) {
  return (setCookieHeaders || []).map(raw => {
    const parts = raw.split(';').map(s => s.trim());
    const [nameValue, ...attrs] = parts;
    const eq = nameValue.indexOf('=');
    const name = eq === -1 ? nameValue : nameValue.slice(0, eq);
    const lower = attrs.map(a => a.toLowerCase());

    const secure = lower.some(a => a === 'secure');
    const httpOnly = lower.some(a => a === 'httponly');
    const sameSiteAttr = attrs.find(a => a.toLowerCase().startsWith('samesite='));
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1].toLowerCase() : null;
    const isSession = !attrs.some(a => /expires=|max-age=/i.test(a));

    const issues = [];
    // SameSite=None is a deliberate opt-out of CSRF protection, so it is
    // reported as informational rather than a missing-flag failure.
    if (!sameSite) issues.push({ severity: 'medium', text: 'Missing SameSite — CSRF exposure' });
    if (!secure) issues.push({ severity: 'high', text: 'Missing Secure — sent over plain HTTP' });
    if (!httpOnly) issues.push({ severity: 'high', text: 'Missing HttpOnly — readable by JavaScript (XSS risk)' });
    if (sameSite === 'none' && !secure) issues.push({ severity: 'high', text: 'SameSite=None requires Secure' });

    return {
      name,
      secure,
      httpOnly,
      sameSite: sameSite || null,
      session: isSession,
      issues,
      passed: issues.length === 0
    };
  });
}

// ============================================
// THREAT INTEL — keyless bulk feeds
// ============================================
export const FEEDS = {
  urlhaus: {
    name: 'URLhaus (abuse.ch)',
    url: 'https://urlhaus.abuse.ch/downloads/text_recent/',
    ttl: 30 * 60 * 1000,
    timeout: 20000,
    exact: null, hosts: null, fetchedAt: 0
  },
  openphish: {
    name: 'OpenPhish',
    url: 'https://openphish.com/feed.txt',
    ttl: 60 * 60 * 1000,
    timeout: 20000,
    exact: null, hosts: null, fetchedAt: 0
  }
};

async function loadFeed(key) {
  const feed = FEEDS[key];
  const now = Date.now();
  if (feed.exact && now - feed.fetchedAt < feed.ttl) return feed;

  try {
    const res = await fetch(feed.url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(feed.timeout),
      headers: { 'User-Agent': 'SecurityHeaderAuditor/2.0' }
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);

    const text = await res.text();
    const exact = new Set();
    const hosts = new Set();

    for (const line of text.split('\n')) {
      const entry = line.trim();
      if (!entry || entry.startsWith('#') || entry.startsWith('<!--')) continue;
      try {
        const u = new URL(entry);
        exact.add(normKey(u.hostname + u.pathname + u.search));
        exact.add(normKey(u.hostname + u.pathname));
        hosts.add(normKey(u.hostname));
      } catch {}
    }

    feed.exact = exact;
    feed.hosts = hosts;
    feed.fetchedAt = now;
    console.log(`  [feed] ${feed.name}: ${exact.size} URLs / ${hosts.size} hosts`);
    return feed;
  } catch (e) {
    console.error(`  [feed] ${feed.name} failed: ${e.message}`);
    return feed.exact ? feed : null;
  }
}

const normKey = (v) => String(v).toLowerCase().replace(/\/+$/, '');

const SHARED_HOSTS = new Set([
  'github.com', 'www.github.com', 'raw.githubusercontent.com', 'gist.github.com',
  'gitlab.com', 'bitbucket.org', 'wordpress.com', 'blogspot.com', 'www.blogspot.com',
  'tumblr.com', 'netlify.app', 'vercel.app', 'herokuapp.com', 'pages.dev', 'workers.dev',
  'firebaseapp.com', 'web.app', 'appspot.com', 'glitch.me', 'replit.dev',
  's3.amazonaws.com', 'amazonaws.com', 'cloudfront.net', 'blob.core.windows.net',
  'cdn.discordapp.com', 'pastebin.com', 'hastebin.com', 'transfer.sh', 'anonfiles.com',
  'mediafire.com', 'mega.nz', 'drive.google.com', 'dropbox.com', 'imgur.com',
  'youtube.com', 'www.youtube.com', 'facebook.com', 'twitter.com', 'x.com',
  'telegram.org', 't.me', 'discord.com', 'reddit.com', 'medium.com',
  'codepen.io', 'jsfiddle.net', 'codesandbox.io', 'stackblitz.io'
]);

export async function checkFeed(key, targetUrl) {
  const feed = FEEDS[key];
  const loaded = await loadFeed(key);
  if (!loaded?.exact) return { source: feed.name, status: 'unavailable', data: null };

  let u;
  try { u = new URL(targetUrl); } catch { return { source: feed.name, status: 'invalid', data: null }; }

  const hostKey = normKey(u.hostname);
  const match = [normKey(u.hostname + u.pathname + u.search), normKey(u.hostname + u.pathname)]
    .find(c => loaded.exact.has(c));

  if (match) {
    return {
      source: feed.name, status: 'listed',
      data: { listed: true, severity: 'confirmed', scope: 'exact URL', match, entryCount: loaded.exact.size }
    };
  }

  const isShared = SHARED_HOSTS.has(hostKey);
  if (loaded.hosts.has(hostKey) && !isShared) {
    return {
      source: feed.name, status: 'listed',
      data: {
        listed: true, severity: 'advisory', scope: 'host', match: hostKey,
        entryCount: loaded.exact.size,
        note: 'Other paths on this host have been reported as malicious.'
      }
    };
  }
  return {
    source: feed.name, status: 'clean',
    data: { listed: false, entryCount: loaded.exact.size, sharedHost: isShared }
  };
}

export function mergeFeedResults(sourceName, perUrl) {
  const RANK = { confirmed: 3, advisory: 2, clean: 1, unavailable: 0 };
  const valid = perUrl.filter(r => r.status !== 'invalid');
  if (!valid.length) return { source: sourceName, status: 'unavailable', data: null };

  let best = valid[0];
  const rankOf = (r) => (r.data?.listed ? RANK[r.data.severity] ?? 1 : RANK[r.status] ?? 0);
  for (const r of valid) if (rankOf(r) > rankOf(best)) best = r;

  const out = { source: sourceName, status: best.status, data: best.data };
  if (!out.data?.listed && valid.some(r => r.data?.sharedHost)) {
    out.data = { ...(out.data || {}), sharedHost: true };
  }
  return out;
}

// ============================================
// EXTRA PROBES
// ============================================
async function probeSecurityTxt(origin) {
  try {
    const res = await fetch(`${origin}/.well-known/security.txt`, {
      method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'SecurityHeaderAuditor/2.0' }
    });
    if (res.ok) {
      const body = await res.text();
      try { await res.body?.cancel(); } catch {}
      const contact = body.match(/^Contact:\s*(.+)$/mi)?.[1]?.trim() || null;
      return { present: true, status: res.status, contact };
    }
    try { await res.body?.cancel(); } catch {}
    return { present: false, status: res.status };
  } catch {
    return { present: false, status: null };
  }
}

async function probeIPv6(hostname) {
  if (!hostname || /^[0-9.]+$/.test(hostname) || hostname.includes(':')) {
    return { supported: null, count: 0 };
  }
  try {
    const dns = await import('node:dns/promises');
    const res = await dns.resolve6(hostname).catch(() => null);
    return { supported: !!(res && res.length), count: res?.length || 0 };
  } catch {
    return { supported: null, count: 0 };
  }
}

function infoDisclosure(headers) {
  const out = [];
  if (headers['server']) {
    out.push({ header: 'Server', value: headers['server'], risk: 'low', note: 'Reveals the web server software and version.' });
  }
  if (headers['x-powered-by']) {
    out.push({ header: 'X-Powered-By', value: headers['x-powered-by'], risk: 'medium', note: 'Reveals the framework and version in use.' });
  }
  if (headers['x-aspnet-version']) {
    out.push({ header: 'X-AspNet-Version', value: headers['x-aspnet-version'], risk: 'medium', note: 'Reveals the exact ASP.NET version.' });
  }
  const acao = headers['access-control-allow-origin'];
  if (acao === '*') {
    const creds = (headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    out.push({
      header: 'Access-Control-Allow-Origin', value: acao,
      risk: creds ? 'high' : 'low',
      note: creds
        ? 'Wildcard origin combined with credentials is a serious misconfiguration.'
        : 'Any origin may read this response cross-origin.'
    });
  }
  if (headers['content-security-policy-report-only'] && !headers['content-security-policy']) {
    out.push({
      header: 'Content-Security-Policy-Report-Only', value: '(present)',
      risk: 'medium',
      note: 'Only reports violations — the policy is not actually enforced.'
    });
  }
  return out;
}

// ============================================
// GRADING
// ============================================
function gradeFor(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

// ============================================
// MAIN SCAN
// ============================================
async function performScan(rawUrl) {
  const url = assertScannable(rawUrl.trim());
  const started = Date.now();

  const { chain, final, sawDowngrade, sawHttps, tooManyHops } = await fetchWithChain(url.toString());
  if (!final) throw new ScanError('No response received.');

  const headers = final.headers;
  const isHttps = new URL(final.url).protocol === 'https:';
  const startedHttp = url.protocol === 'http:';

  // Run independent probes in parallel
  const [tlsInfo, securityTxt, ipv6, feedResults] = await Promise.all([
    // Pass the port explicitly: a site served on :8443 presents a different
    // certificate than the same hostname on :443, so inspecting the default
    // port would report entirely the wrong certificate.
    isHttps
      ? inspectTLS(url.hostname, Number(url.port) || 443)
      : Promise.resolve({ ok: false, skipped: 'HTTP only' }),
    probeSecurityTxt(url.origin),
    probeIPv6(url.hostname),
    Promise.all(
      Object.keys(FEEDS).map(async (key) => {
        const perUrl = await Promise.all(
          [...new Set([url.toString(), final.url])].map(u => checkFeed(key, u))
        );
        return mergeFeedResults(FEEDS[key].name, perUrl);
      })
    )
  ]);

  // ---- Header checks ----
  const ctx = { isHttps, headers };
  const headerResults = HEADER_CHECKS.map(c => {
    const value = headers[c.key];
    const result = c.check(value, ctx);
    return {
      name: c.name, key: c.key, weight: c.weight, severity: c.severity, why: c.why,
      present: !!value, value: value || null,
      passed: result.pass, reason: result.reason, detail: result.detail || null,
      notApplicable: !!result.na,
      nginxFix: c.nginxFix, cloudflareFix: c.cloudflareFix
    };
  });

  // ---- TLS scoring ----
  const tlsExpiry = tlsInfo.ok ? certExpiryInfo(tlsInfo.cert) : null;
  const weakProtocol = tlsInfo.ok && WEAK_PROTOCOLS.has(tlsInfo.protocol);

  let tlsPassed = false;
  let tlsReason = 'No TLS';
  if (isHttps && tlsInfo.ok) {
    if (tlsInfo.authorized && tlsExpiry.status !== 'expired' && !weakProtocol) {
      tlsPassed = true;
      tlsReason = `${tlsInfo.protocol}, certificate valid for ${tlsExpiry.daysRemaining} more days`;
    } else if (!tlsInfo.authorized) {
      tlsReason = `Certificate not trusted: ${tlsInfo.authorizationError || 'unknown error'}`;
    } else if (weakProtocol) {
      tlsReason = `Deprecated protocol: ${tlsInfo.protocol}`;
    } else {
      tlsReason = `Certificate expired ${Math.abs(tlsExpiry.daysRemaining)} days ago`;
    }
  } else if (!isHttps) {
    tlsReason = 'Site does not use HTTPS';
  } else {
    tlsReason = `TLS connection failed: ${tlsInfo.error || 'unknown'}`;
  }

  // ---- HTTPS enforcement ----
  let httpsPassed, httpsReason;
  if (isHttps && startedHttp) {
    httpsPassed = true;
    httpsReason = `HTTP requests are upgraded to HTTPS (${chain.length} redirect${chain.length > 1 ? 's' : ''})`;
  } else if (isHttps) {
    httpsPassed = true;
    httpsReason = 'Served over HTTPS';
  } else {
    httpsPassed = false;
    httpsReason = 'Served over plain HTTP with no upgrade to HTTPS';
  }

  const downgradePassed = !sawDowngrade;
  const downgradeReason = sawDowngrade
    ? 'A redirect in the chain downgrades from HTTPS to HTTP'
    : 'No HTTPS to HTTP downgrade in the redirect chain';

  // ---- Cookies ----
  const cookies = analyzeCookies(final.setCookies);
  const badCookies = cookies.filter(c => !c.passed);
  const cookiesPassed = cookies.length === 0 ? true : badCookies.length === 0;
  const cookiesReason = cookies.length === 0
    ? 'No cookies set — nothing to flag'
    : badCookies.length === 0
      ? `All ${cookies.length} cookies are correctly flagged`
      : `${badCookies.length} of ${cookies.length} cookies have missing or weak flags`;

  // ---- Content-Type ----
  const contentType = headers['content-type'] || '';
  const ctOk = !contentType || /^(text\/html|application\/xhtml\+xml)/i.test(contentType);
  const ctReason = ctOk
    ? (contentType ? `Served as ${contentType.split(';')[0]}` : 'No Content-Type header')
    : `Unexpected Content-Type: ${contentType.split(';')[0]}`;

  const contentTypeResult = {
    name: 'Content-Type correctness', key: 'content-type', weight: 6, severity: 'low',
    why: 'HTML must be typed as HTML — a wrong MIME type opens content-sniffing and JSON-hijacking paths.',
    present: !!contentType, value: contentType || null,
    passed: ctOk, reason: ctReason, detail: null, notApplicable: false,
    nginxFix: null, cloudflareFix: null
  };

  const headerTotals = [...headerResults, contentTypeResult];

  // ---- Score ----
  const dynamic = [
    { weight: 10, passed: tlsPassed },
    { weight: 6, passed: httpsPassed },
    { weight: 12, passed: cookiesPassed },
    { weight: 6, passed: downgradePassed }
  ];

  // n/a checks are dropped from BOTH sides of the ratio. Counting them in the
  // denominator while also awarding the points would hand an HTTP-only site a
  // free 12 for HSTS; counting them in neither means an HTTPS site is still
  // graded against the full 100, so grade thresholds stay stable.
  let totalWeight = 0, earned = 0;
  for (const h of headerTotals) {
    if (h.notApplicable) continue;
    totalWeight += h.weight;
    if (h.passed) earned += h.weight;
  }
  for (const d of dynamic) { totalWeight += d.weight; if (d.passed) earned += d.weight; }

  const score = Math.round((earned / totalWeight) * 100);

  const t0 = Date.now();
  const report = {
    score,
    grade: gradeFor(score),
    scannedUrl: rawUrl,
    finalUrl: final.url,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,

    headers: headerTotals,
    redirectChain: chain.map(h => ({ url: h.url, status: h.status, location: h.headers.location || null })),
    redirects: chain.length - 1,
    tooManyHops,

    tls: {
      passed: tlsPassed,
      reason: tlsReason,
      enabled: isHttps,
      protocol: tlsInfo.protocol || null,
      cipher: tlsInfo.cipher || null,
      cipherSuite: tlsInfo.cipherBits || null,
      authorized: tlsInfo.authorized ?? null,
      authorizationError: tlsInfo.authorizationError || null,
      weakProtocol,
      expiry: tlsExpiry,
      certificate: tlsInfo.cert || null
    },

    cookies,
    cookieSummary: { total: cookies.length, insecure: badCookies.length },

    info: infoDisclosure(headers),
    securityTxt,
    ipv6,
    threatIntel: feedResults,

    rawHeaders: Object.fromEntries(
      Object.entries(headers).filter(([k]) => k !== 'set-cookie')
    )
  };
  void t0;

  return report;
}

// ============================================
// ROUTES
// ============================================
app.get('/api/scan', async (req, res) => {
  const url = req.query.url;
  if (!url || typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: 'A url query parameter is required.' });
  }
  try {
    res.json(await performScan(url));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/batch', async (req, res) => {
  const urls = Array.isArray(req.body?.urls) ? req.body.urls : [];
  if (!urls.length) return res.status(400).json({ error: 'Provide a "urls" array.' });
  if (urls.length > 10) return res.status(400).json({ error: 'Maximum 10 URLs per batch.' });

  const results = await Promise.all(urls.map(async (u) => {
    try { return { url: u, report: await performScan(String(u)) }; }
    catch (e) { return { url: u, error: e.message }; }
  }));
  res.json({ results, scannedAt: new Date().toISOString() });
});

app.get('/api/feeds', async (_req, res) => {
  const out = {};
  await Promise.all(Object.keys(FEEDS).map(async (k) => {
    const loaded = await loadFeed(k);
    out[k] = loaded?.exact
      ? { name: FEEDS[k].name, entries: loaded.exact.size, hosts: loaded.hosts.size, fetchedAt: new Date(FEEDS[k].fetchedAt).toISOString() }
      : { name: FEEDS[k].name, entries: 0, error: 'unavailable' };
  }));
  res.json(out);
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '2.0.0', node: process.version, uptime: process.uptime() });
});

app.get('*', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    console.log(`\n  🚀 Security Header Auditor v2.0`);
    console.log(`     http://localhost:${PORT}\n`);
  });
}

export {
  app, performScan, gradeFor, fetchWithChain,
  certExpiryInfo, infoDisclosure, normKey
};
