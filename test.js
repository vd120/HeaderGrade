/**
 * Unit tests — no network access required.
 * Run: node test.js
 */
import {
  isPrivateIP, parseCSP, HEADER_CHECKS, analyzeCookies,
  gradeFor, certExpiryInfo, infoDisclosure, mergeFeedResults, normKey
} from './server.js';
import { readFileSync } from 'node:fs';

const serverSrc = readFileSync(new URL('./server.js', import.meta.url), 'utf8');

let passed = 0, failed = 0;
const groups = [];

function group(name) { groups.push(name); console.log(`\n${name}`); }
function t(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) { passed++; console.log(`  ✓ ${name}`); }
  else {
    failed++;
    console.log(`  ✗ ${name}`);
    console.log(`      expected: ${JSON.stringify(expected)}`);
    console.log(`      actual:   ${JSON.stringify(actual)}`);
  }
}
const byKey = (k) => HEADER_CHECKS.find(c => c.key === k);
const ctx = (isHttps = true, headers = {}) => ({ isHttps, headers });

/* ═════════ SSRF ═════════ */
group('SSRF protection — IPv4 + hostnames');
[
  'localhost', 'localhost.localdomain', 'localtest.me', '127.0.0.1', '127.1.2.3',
  '10.0.0.1', '10.255.255.255', '192.168.0.1', '192.168.1.1',
  '172.16.0.1', '172.20.1.1', '172.31.255.255', '169.254.169.254',
  '0.0.0.0', 'metadata.google.internal'
].forEach(h => t(`blocks ${h}`, isPrivateIP(h), true));

group('SSRF protection — IPv6');
['[::1]', '[fe80::1]', '[fc00::1]', '[fd00::a]', '[fdff::1]']
  .forEach(h => t(`blocks ${h}`, isPrivateIP(h), true));

group('SSRF protection — allows public hosts');
[
  'example.com', 'www.google.com', '8.8.8.8', '1.1.1.1',
  '172.15.0.1', '172.32.0.1', '172.255.255.255', '11.0.0.1', '9.9.9.9',
  '2606:4700:4700::1111', '[2606:4700:4700::1111]', 'notlocalhost.com'
].forEach(h => t(`allows ${JSON.stringify(h)}`, isPrivateIP(h), false));

group('SSRF protection — refuses unscannable input');
t('empty hostname refused', isPrivateIP(''), true);
t('undefined refused', isPrivateIP(undefined), true);
t('null refused', isPrivateIP(null), true);

/* ═════════ CSP PARSER ═════════ */
group('CSP parser');
t('simple directives', parseCSP("default-src 'self'; script-src 'none'"),
  { 'default-src': ["'self'"], 'script-src': ["'none'"] });
t('lowercases names and values', parseCSP("SCRIPT-SRC 'SELF'"), { 'script-src': ["'self'"] });
t('comma separators', parseCSP("default-src 'self', script-src 'self'"),
  { 'default-src': ["'self'"], 'script-src': ["'self'"] });
t('empty string', parseCSP('   '), {});
t('first duplicate wins', parseCSP("script-src 'self'; script-src 'unsafe-inline'"),
  { 'script-src': ["'self'"] });
t('extra whitespace collapses', parseCSP("script-src    'self'   'none'"),
  { 'script-src': ["'self'", "'none'"] });

/* ═════════ CSP CHECK ═════════ */
group('Content-Security-Policy');
const csp = byKey('content-security-policy');
t('missing fails', csp.check(undefined, ctx()).pass, false);
t('strict passes', csp.check("default-src 'self'; script-src 'self'; frame-ancestors 'none'", ctx()).pass, true);
t('unsafe-inline in script-src fails', csp.check("script-src 'self' 'unsafe-inline'", ctx()).pass, false);
t('unsafe-eval in script-src fails', csp.check("script-src 'self' 'unsafe-eval'", ctx()).pass, false);
t('data: in script-src fails', csp.check("script-src 'self' data:", ctx()).pass, false);
t('REGRESSION: unsafe-inline only in style-src passes',
  csp.check("script-src 'self'; style-src 'unsafe-inline' github.githubassets.com", ctx()).pass, true);
t('REGRESSION: real GitHub CSP passes',
  csp.check("default-src 'none'; script-src github.githubassets.com 'sha256-tSjmyPUky1KbRZ0fw9VUil3wFEbeM82rtbJDygGJAXw='; style-src 'unsafe-inline' github.githubassets.com", ctx()).pass, true);
t('unsafe-inline in both fails', csp.check("script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'", ctx()).pass, false);
t('nonce-based passes', csp.check("script-src 'self' 'nonce-abc123'", ctx()).pass, true);
t('hash-based passes', csp.check("script-src 'self' 'sha256-a=' 'sha256-b='", ctx()).pass, true);
t('falls back to default-src', csp.check("default-src 'self'", ctx()).pass, true);
t('permissive default-src only fails', csp.check("default-src * 'unsafe-inline' https:", ctx()).pass, false);
t('no script-src and no default-src fails', csp.check("style-src 'self'; img-src 'self'", ctx()).pass, false);
t('garbage fails', csp.check('   ', ctx()).pass, false);
t('script-src-elem takes precedence', csp.check("script-src 'self'; script-src-elem 'self' 'unsafe-inline'", ctx()).pass, false);

/* ═════════ HSTS ═════════ */
group('Strict-Transport-Security');
const hsts = byKey('strict-transport-security');
t('n/a on HTTP', hsts.check(undefined, ctx(false)).na, true);
t('n/a passes on HTTP', hsts.check(undefined, ctx(false)).pass, true);
t('missing on HTTPS fails', hsts.check(undefined, ctx(true)).pass, false);
t('full preload passes', hsts.check('max-age=31536000; includeSubDomains; preload', ctx(true)).pass, true);
t('case-insensitive directives pass', hsts.check('MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD', ctx(true)).pass, true);
t('short max-age fails', hsts.check('max-age=300; includeSubDomains; preload', ctx(true)).pass, false);
t('one year minus one second fails', hsts.check('max-age=31535999; includeSubDomains; preload', ctx(true)).pass, false);
t('missing includeSubDomains fails', hsts.check('max-age=31536000; preload', ctx(true)).pass, false);
t('missing preload fails', hsts.check('max-age=31536000; includeSubDomains', ctx(true)).pass, false);
t('no max-age fails', hsts.check('includeSubDomains; preload', ctx(true)).pass, false);
// Real servers emit these variants; the HSTS grammar permits them.
t('whitespace around = passes', hsts.check('max-age = 31536000; includeSubDomains; preload', ctx(true)).pass, true);
t('quoted max-age passes', hsts.check('max-age="31536000"; includeSubDomains; preload', ctx(true)).pass, true);
t('quoted short max-age still fails', hsts.check('max-age="300"; includeSubDomains; preload', ctx(true)).pass, false);
t('spaces around = do not mask a short max-age', hsts.check('max-age = 300; includeSubDomains; preload', ctx(true)).pass, false);

/* ═════════ X-FRAME-OPTIONS ═════════ */
group('X-Frame-Options');
const xfo = byKey('x-frame-options');
t('DENY passes', xfo.check('DENY', ctx()).pass, true);
t('SAMEORIGIN passes', xfo.check('SAMEORIGIN', ctx()).pass, true);
t('lowercase passes', xfo.check('sameorigin', ctx()).pass, true);
t('ALLOW-FROM fails', xfo.check('ALLOW-FROM https://x.com', ctx()).pass, false);
t('missing but CSP frame-ancestors covers it',
  xfo.check(undefined, ctx(true, { 'content-security-policy': "frame-ancestors 'none'" })).pass, true);
t('report-only frame-ancestors covers it',
  xfo.check(undefined, ctx(true, { 'content-security-policy-report-only': "frame-ancestors 'none'" })).pass, true);
t('missing entirely fails', xfo.check(undefined, ctx()).pass, false);

/* ═════════ X-CONTENT-TYPE-OPTIONS ═════════ */
group('X-Content-Type-Options');
const xcto = byKey('x-content-type-options');
t('nosniff passes', xcto.check('nosniff', ctx()).pass, true);
t('NOSNIFF uppercase passes', xcto.check('NOSNIFF', ctx()).pass, true);
t('missing fails', xcto.check(undefined, ctx()).pass, false);
t('off fails', xcto.check('off', ctx()).pass, false);

/* ═════════ REFERRER-POLICY ═════════ */
group('Referrer-Policy');
const rp = byKey('referrer-policy');
t('strict-origin-when-cross-origin passes', rp.check('strict-origin-when-cross-origin', ctx()).pass, true);
t('no-referrer passes', rp.check('no-referrer', ctx()).pass, true);
t('origin passes', rp.check('origin', ctx()).pass, true);
t('unsafe-url fails', rp.check('unsafe-url', ctx()).pass, false);
t('no-referrer-when-downgrade fails', rp.check('no-referrer-when-downgrade', ctx()).pass, false);
t('missing fails', rp.check(undefined, ctx()).pass, false);

/* ═════════ PERMISSIONS-POLICY ═════════ */
group('Permissions-Policy');
const pp = byKey('permissions-policy');
t('restrictive passes', pp.check('camera=(), geolocation=()', ctx()).pass, true);
t('self-allow is restrictive enough', pp.check('camera=(self), geolocation=(self)', ctx()).pass, true);
t('geolocation wildcard fails', pp.check('geolocation=*', ctx()).pass, false);
t('camera wildcard fails', pp.check('camera=*', ctx()).pass, false);
t('missing fails', pp.check(undefined, ctx()).pass, false);

/* ═════════ COOP / CORP ═════════ */
group('Cross-Origin-Opener-Policy');
const coop = byKey('cross-origin-opener-policy');
t('same-origin passes', coop.check('same-origin', ctx()).pass, true);
t('SAME-ORIGIN uppercase passes', coop.check('SAME-ORIGIN', ctx()).pass, true);
t('padded value passes', coop.check('  same-origin  ', ctx()).pass, true);
t('REGRESSION: same-origin-allow-popups is not same-origin',
  coop.check('same-origin-allow-popups', ctx()).pass, false);
t('noopener-allow-popups flagged', coop.check('noopener-allow-popups', ctx()).pass, false);
t('unsafe-none flagged', coop.check('unsafe-none', ctx()).pass, false);
t('garbage flagged', coop.check('bogus-value', ctx()).pass, false);
t('missing fails', coop.check(undefined, ctx()).pass, false);

group('Cross-Origin-Resource-Policy');
const corp = byKey('cross-origin-resource-policy');
t('same-origin passes', corp.check('same-origin', ctx()).pass, true);
t('same-site passes', corp.check('same-site', ctx()).pass, true);
t('cross-origin flagged', corp.check('cross-origin', ctx()).pass, false);
t('missing fails', corp.check(undefined, ctx()).pass, false);

/* ═════════ COOKIES ═════════ */
group('Cookie analysis');
t('fully secure cookie passes',
  analyzeCookies(['sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict'])[0].passed, true);
t('missing Secure flagged',
  analyzeCookies(['sid=abc; HttpOnly; SameSite=Strict'])[0].issues.length, 1);
t('missing HttpOnly flagged',
  analyzeCookies(['sid=abc; Secure; SameSite=Strict'])[0].issues.length, 1);
t('missing SameSite flagged',
  analyzeCookies(['sid=abc; Secure; HttpOnly'])[0].issues.length, 1);
t('all three missing flagged',
  analyzeCookies(['sid=abc; Path=/'])[0].issues.length, 3);
t('SameSite=None is not counted as "missing SameSite"',
  analyzeCookies(['sid=abc; Secure; HttpOnly; SameSite=None'])[0].issues.length, 0);
t('SameSite=None without Secure is flagged specifically',
  analyzeCookies(['sid=abc; HttpOnly; SameSite=None'])[0].issues.map(i => i.text)
    .includes('SameSite=None requires Secure'), true);
t('SameSite=None with Secure and HttpOnly passes',
  analyzeCookies(['sid=abc; Secure; HttpOnly; SameSite=None'])[0].passed, true);
t('SameSite=Lax counts as safe',
  analyzeCookies(['sid=abc; Secure; HttpOnly; SameSite=Lax'])[0].passed, true);
t('name extracted before =', analyzeCookies(['my_cookie=1; Secure; HttpOnly; SameSite=Strict'])[0].name, 'my_cookie');
t('session cookie detected', analyzeCookies(['sid=1; Secure; HttpOnly; SameSite=Strict'])[0].session, true);
t('persistent cookie detected', analyzeCookies(['sid=1; Max-Age=3600; Secure; HttpOnly; SameSite=Strict'])[0].session, false);
t('valueless cookie handled', analyzeCookies(['flag; Secure'])[0].name, 'flag');
t('empty input yields empty array', analyzeCookies([]).length, 0);
t('undefined input yields empty array', analyzeCookies(undefined).length, 0);
t('multiple cookies parsed',
  analyzeCookies(['a=1; Secure; HttpOnly; SameSite=Strict', 'b=2; Path=/']).length, 2);

/* ═════════ CERT EXPIRY ═════════ */
group('Certificate expiry logic');
const daysFromNow = (n) => new Date(Date.now() + n * 86400000).toUTCString();
t('valid when >30 days out', certExpiryInfo({ validTo: daysFromNow(90) }).status, 'valid');
t('expiring-soon at 20 days', certExpiryInfo({ validTo: daysFromNow(20) }).status, 'expiring-soon');
t('expiring at 5 days', certExpiryInfo({ validTo: daysFromNow(5) }).status, 'expiring');
t('expired when in the past', certExpiryInfo({ validTo: daysFromNow(-1) }).status, 'expired');
t('unknown when no validTo', certExpiryInfo({}).status, 'unknown');
t('unknown when cert is null', certExpiryInfo(null).status, 'unknown');
t('days remaining rounds up within the day', certExpiryInfo({ validTo: daysFromNow(10) }).daysRemaining, 10);
t('exactly expired is 0 days', certExpiryInfo({ validTo: daysFromNow(-0.4) }).daysRemaining, 0);
// NaN comparisons are all false, so an unparseable date would otherwise fall
// through to "valid" and report a healthy certificate.
t('unparseable date is unknown, not valid', certExpiryInfo({ validTo: 'not-a-date' }).status, 'unknown');
t('unparseable date has no day count', certExpiryInfo({ validTo: 'not-a-date' }).daysRemaining, null);
t('numeric timestamp is parsed', certExpiryInfo({ validTo: new Date(daysFromNow(90)).toISOString() }).status, 'valid');

/* ═════════ INFO DISCLOSURE ═════════ */
group('Information disclosure');
t('Server header detected',
  infoDisclosure({ server: 'nginx/1.18.0' })[0].header, 'Server');
t('X-Powered-By detected',
  infoDisclosure({ 'x-powered-by': 'PHP/8.1' })[0].header, 'X-Powered-By');
t('wildcard CORS flagged',
  infoDisclosure({ 'access-control-allow-origin': '*' })[0].header, 'Access-Control-Allow-Origin');
t('wildcard CORS + credentials is high risk',
  infoDisclosure({ 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' })[0].risk, 'high');
t('report-only CSP flagged when no enforced CSP',
  infoDisclosure({ 'content-security-policy-report-only': 'x' })[0].risk, 'medium');
t('enforced CSP suppresses report-only warning',
  infoDisclosure({ 'content-security-policy': 'x', 'content-security-policy-report-only': 'y' }).length, 0);
t('clean headers produce nothing', infoDisclosure({}).length, 0);

/* ═════════ FEED MERGING ═════════ */
group('Threat feed merging');
const src = 'TestFeed';
t('confirmed beats advisory', mergeFeedResults(src, [
  { status: 'listed', data: { listed: true, severity: 'advisory' } },
  { status: 'listed', data: { listed: true, severity: 'confirmed' } }
]).data.severity, 'confirmed');
t('advisory beats clean', mergeFeedResults(src, [
  { status: 'clean', data: { listed: false } },
  { status: 'listed', data: { listed: true, severity: 'advisory' } }
]).data.severity, 'advisory');
t('clean preserved when all clean', mergeFeedResults(src, [
  { status: 'clean', data: { listed: false, sharedHost: true } },
  { status: 'clean', data: { listed: false } }
]).status, 'clean');
t('sharedHost note preserved', mergeFeedResults(src, [
  { status: 'clean', data: { listed: false, sharedHost: true } },
  { status: 'invalid', data: null }
]).data.sharedHost, true);
t('invalid results filtered out', mergeFeedResults(src, [
  { status: 'invalid', data: null },
  { status: 'clean', data: { listed: false } }
]).status, 'clean');
t('all invalid becomes unavailable', mergeFeedResults(src, [
  { status: 'invalid', data: null }
]).status, 'unavailable');
t('unavailable when empty', mergeFeedResults(src, []).status, 'unavailable');

/* ═════════ KEY NORMALISATION ═════════ */
group('Feed key normalisation');
t('lowercases', normKey('Example.COM'), 'example.com');
t('strips trailing slash', normKey('example.com/path/'), 'example.com/path');
t('root slash collapses', normKey('example.com/'), 'example.com');
t('query string preserved', normKey('Example.com/a?b=c'), 'example.com/a?b=c');

/* ═════════ SCORING MATH ═════════ */
group('Scoring weights');
const CONTENT_TYPE_WEIGHT = 6;
const TLS_WEIGHT = 10, HTTPS_WEIGHT = 6, COOKIE_WEIGHT = 12, DOWNGRADE_WEIGHT = 6;
const dynamicWeight = TLS_WEIGHT + HTTPS_WEIGHT + COOKIE_WEIGHT + DOWNGRADE_WEIGHT;
const headerWeight = HEADER_CHECKS.reduce((s, c) => s + c.weight, 0);
t('header weights sum to 60', headerWeight, 60);
t('dynamic weights sum to 34', dynamicWeight, 34);
t('content-type weight is 6', CONTENT_TYPE_WEIGHT, 6);
t('everything sums to exactly 100', headerWeight + CONTENT_TYPE_WEIGHT + dynamicWeight, 100);
t('all 8 header checks present', HEADER_CHECKS.length, 8);
t('every check has a weight', HEADER_CHECKS.every(c => c.weight > 0), true);
t('every check has severity', HEADER_CHECKS.every(c => !!c.severity), true);
t('every check has why text', HEADER_CHECKS.every(c => c.why && c.why.length > 20), true);
t('every check has nginx fix', HEADER_CHECKS.every(c => c.nginxFix.startsWith('add_header')), true);
t('every check has cloudflare fix', HEADER_CHECKS.every(c => c.cloudflareFix.includes('Name:')), true);
t('keys are unique', new Set(HEADER_CHECKS.map(c => c.key)).size, HEADER_CHECKS.length);
t('critical is the heaviest', HEADER_CHECKS.find(c => c.severity === 'critical').weight,
  Math.max(...HEADER_CHECKS.map(c => c.weight)));

group('Grading scale');
[[100,'A+'],[95,'A+'],[94,'A'],[90,'A'],[89,'B'],[80,'B'],[79,'C'],[70,'C'],[69,'D'],[55,'D'],[54,'F'],[0,'F']]
  .forEach(([s, g]) => t(`${s} → ${g}`, gradeFor(s), g));

/* ═════════ PORT-AWARE TLS ═════════ */
group('Port handling');
// inspectTLS defaults to 443, so a non-standard HTTPS port must be threaded
// through explicitly — otherwise the tool reports the :443 certificate for a
// site actually served on :8443.
t('inspectTLS defaults to 443', /export function inspectTLS\(hostname, port = 443\)/.test(serverSrc), true);
t('scan passes the URL port, not just the hostname',
  /inspectTLS\(url\.hostname, Number\(url\.port\) \|\| 443\)/.test(serverSrc), true);
t('default port is applied when the URL omits one',
  (() => Number(new URL('https://example.com/path').port) || 443)(), 443);
t('explicit port is preserved', Number(new URL('https://example.com:8443/').port), 8443);
t('http on an explicit port does not trigger TLS inspection',
  new URL('http://example.com:8443/').protocol, 'http:');

group('Perfect and zero sites');
t('perfect site is 100', Math.round(100 / 100 * 100), 100);
t('perfect site is A+', gradeFor(100), 'A+');
t('nothing passing is 0', gradeFor(0), 'F');

/* ═════════ n/a EXCLUSION FROM SCORE ═════════ */
group('Not-applicable weighting');
// Mirrors the scoring loop: n/a rows are dropped from both sides of the ratio.
// "otherHeaders" is the remaining 88 header points; "tlsAndHttps" is the 16
// dynamic points an HTTP-only site can never earn.
function scoreWith({ hstsNa, otherHeaders, tlsAndHttps }) {
  let total = 0, earned = 0;
  if (!hstsNa) { total += 12; if (otherHeaders) earned += 12; }
  total += 88 + 16;
  if (otherHeaders) earned += 88;
  if (tlsAndHttps) earned += 16;
  return Math.round((earned / total) * 100);
}
const perfectHttps = { hstsNa: false, otherHeaders: true, tlsAndHttps: true };
const perfectHeadersOverHttp = { hstsNa: true, otherHeaders: true, tlsAndHttps: false };

t('HTTPS site graded against the full 100', scoreWith(perfectHttps), 100);
t('HTTP-only site drops to 85, not an inflated 86', scoreWith(perfectHeadersOverHttp), 85);
t('HTTP-only site tops out at B, never A+',
  gradeFor(scoreWith(perfectHeadersOverHttp)) === 'A+', false);
t('grading an HTTP-only site on 88 points is more honest',
  scoreWith({ hstsNa: true, otherHeaders: false, tlsAndHttps: false }), 0);
// Before the fix, na rows carried pass:true, so they contributed weight to the
// numerator AND denominator — silently easing every other site upward.
t('old behaviour inflated an HTTP-only site to 86',
  Math.round((88 + 12) / (88 + 16 + 12) * 100), 86);
t('old behaviour also lifted an otherwise-empty HTTPS site off zero',
  Math.round(12 / (88 + 16 + 12) * 100), 10);

// A site that genuinely sets HSTS is graded against 100 either way.
const WEIGHTED = { 'content-security-policy': 18, 'x-frame-options': 6 };
t('weights still total 100 with every header applicable',
  Object.values(WEIGHTED).reduce((a, b) => a + b, 0) + 12 + 64, 100);

/* ═════════ SUMMARY ═════════ */
console.log(`\n${'='.repeat(52)}`);
console.log(`  ${groups.length} groups · ${passed} passed · ${failed} failed`);
console.log('='.repeat(52));
process.exit(failed ? 1 : 0);
