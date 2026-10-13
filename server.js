/**
 * Lumio — Discord Linked Roles + operational monitoring
 * Render-ready Node.js / Express server.
 *
 * Features:
 * - Request/action and error logging (with secrets and query strings redacted)
 * - Basic traffic monitoring and high-traffic warnings
 * - Security headers, request-size limits, rate limiting, safe error responses
 * - Discord OAuth2 Linked Roles starter flow
 * - Bot guild/server count and names via Discord API (never publicly exposed)
 * - Health and protected admin-status endpoints
 *
 * Render environment variables:
 *   DISCORD_CLIENT_ID
 *   DISCORD_CLIENT_SECRET
 *   DISCORD_REDIRECT_URI   https://YOUR-SERVICE.onrender.com/discord/callback
 *   DISCORD_BOT_TOKEN
 *   SESSION_SECRET         use a long random value
 *   ADMIN_STATUS_KEY       long random key for /admin/status
 *   OWNER_PANEL_PASSCODE   passcode required to enter /owner (set in Render, never commit)
 * Optional:
 *   BASE_URL               https://YOUR-SERVICE.onrender.com
 *   PORT                   supplied by Render
 *
 * package.json dependencies:
 *   express, express-session, helmet, express-rate-limit
 *
 * Security notes:
 * - Never commit tokens/secrets to GitHub.
 * - Don't log request bodies, authorization headers, cookies, OAuth codes, or tokens.
 * - This starter's linked-role metadata values are examples; implement real eligibility checks.
 */

'use strict';

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// HTTPS redirect: Render terminates TLS at its proxy and forwards x-forwarded-proto.
// Keep local development usable over HTTP.
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.get('x-forwarded-proto') !== 'https') {
    return res.redirect(308, `https://${req.get('host')}${req.originalUrl}`);
  }
  next();
});

const PORT = Number(process.env.PORT) || 3000;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_STATUS_KEY = process.env.ADMIN_STATUS_KEY;
const OWNER_PANEL_PASSCODE = process.env.OWNER_PANEL_PASSCODE;
const BASE_URL = process.env.BASE_URL || '';
const DATA_DIR = process.env.LUMIO_DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'lumio-store.json');

const REQUIRED_ENV = {
  DISCORD_CLIENT_ID: CLIENT_ID,
  DISCORD_CLIENT_SECRET: CLIENT_SECRET,
  DISCORD_REDIRECT_URI: REDIRECT_URI,
  DISCORD_BOT_TOKEN: BOT_TOKEN,
  SESSION_SECRET,
  ADMIN_STATUS_KEY,
};
const missingEnv = Object.entries(REQUIRED_ENV)
  .filter(([, value]) => !value)
  .map(([name]) => name);

const startedAt = Date.now();
const traffic = {
  totalRequests: 0,
  requestsLastMinute: 0,
  minuteStartedAt: Date.now(),
  highTrafficEvents: 0,
  lastHighTrafficAt: null,
  lastHighTrafficRate: 0,
  errors: 0,
  lastErrorAt: null,
};
const recentActions = [];
const recentErrors = [];
const recentGuilds = { fetchedAt: null, items: [], error: null };
const store = loadStore();
const MAX_RECENT = 100;
const HIGH_TRAFFIC_PER_MINUTE = Number(process.env.HIGH_TRAFFIC_PER_MINUTE) || 180;

function loadStore() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      audit: Array.isArray(parsed.audit) ? parsed.audit : [],
    };
  } catch {
    return { users: [], audit: [] };
  }
}
function saveStore() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = `${DATA_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, DATA_FILE);
    return true;
  } catch (err) {
    logEvent('error', { event: 'store_save_failed', message: err.message });
    return false;
  }
}
function audit(action, details = {}) {
  store.audit.unshift({ at: new Date().toISOString(), action, ...details });
  if (store.audit.length > 500) store.audit.length = 500;
  saveStore();
  logEvent('action', { event: `owner_${action}`, ...details });
}
function requireOwner(req, res, next) {
  if (req.session?.ownerAuthenticated !== true) {
    return res.status(401).json({ error: 'Owner login required.' });
  }
  if (Date.now() - Number(req.session.ownerAuthenticatedAt || 0) > 60 * 60 * 1000) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Owner session expired. Log in again.' });
  }
  next();
}
function publicUser(user) {
  return {
    discordId: user.discordId,
    username: user.username,
    globalName: user.globalName || null,
    avatar: user.avatar || null,
    linkedAt: user.linkedAt,
    suspended: Boolean(user.suspended),
    suspensionReason: user.suspensionReason || null,
    guilds: Array.isArray(user.guilds) ? user.guilds.map(g => ({ id: g.id, name: g.name })) : [],
  };
}

function addRecent(list, item) {
  list.unshift(item);
  if (list.length > MAX_RECENT) list.length = MAX_RECENT;
}
function logEvent(type, details = {}) {
  const entry = { at: new Date().toISOString(), type, ...details };
  console.log(JSON.stringify(entry));
  if (type === 'error' || type === 'security') addRecent(recentErrors, entry);
  else addRecent(recentActions, entry);
}
function safePath(originalUrl) {
  // Avoid logging query strings because OAuth codes/state may be present there.
  const path = String(originalUrl || '/').split('?')[0].slice(0, 180);
  return path || '/';
}

app.use(helmet({
  // OAuth callback uses redirects; no inline scripts are required on the status pages.
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'", 'https://discord.com'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
}));
app.use(express.json({ limit: '20kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

app.use(session({
  name: 'lumio.sid',
  secret: SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000,
  },
}));

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again shortly.' },
  handler: (req, res, _next, options) => {
    logEvent('security', {
      event: 'rate_limit_exceeded',
      method: req.method,
      path: safePath(req.originalUrl),
      ip: req.ip,
    });
    res.status(options.statusCode).json(options.message);
  },
});
const ownerLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many owner-panel login attempts. Try again in 15 minutes.' },
});
const oauthLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Try again later.' },
});
app.use(globalLimiter);

// Request/traffic monitoring. Do not log body, cookies, auth headers, or query string.
app.use((req, res, next) => {
  const now = Date.now();
  traffic.totalRequests += 1;
  if (now - traffic.minuteStartedAt >= 60_000) {
    traffic.requestsLastMinute = 0;
    traffic.minuteStartedAt = now;
  }
  traffic.requestsLastMinute += 1;

  if (traffic.requestsLastMinute === HIGH_TRAFFIC_PER_MINUTE) {
    traffic.highTrafficEvents += 1;
    traffic.lastHighTrafficAt = new Date().toISOString();
    traffic.lastHighTrafficRate = traffic.requestsLastMinute;
    logEvent('security', {
      event: 'high_traffic_warning',
      requestsPerMinute: traffic.requestsLastMinute,
      threshold: HIGH_TRAFFIC_PER_MINUTE,
    });
  }

  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    logEvent('request', {
      method: req.method,
      path: safePath(req.originalUrl),
      status: res.statusCode,
      durationMs: Math.round(durationMs),
      ip: req.ip,
      userAgent: String(req.get('user-agent') || '').slice(0, 120),
    });
    if (res.statusCode >= 500) {
      traffic.errors += 1;
      traffic.lastErrorAt = new Date().toISOString();
      logEvent('error', {
        event: 'http_5xx',
        method: req.method,
        path: safePath(req.originalUrl),
        status: res.statusCode,
      });
    }
  });
  next();
});

function configReady(res) {
  if (missingEnv.length) {
    res.status(503).json({
      error: 'Server configuration is incomplete.',
      missing: missingEnv,
    });
    return false;
  }
  return true;
}
function makeState() {
  return crypto.randomBytes(24).toString('hex');
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function requireAdmin(req, res, next) {
  const provided = req.get('x-admin-key') || '';
  if (!ADMIN_STATUS_KEY || !safeEqual(provided, ADMIN_STATUS_KEY)) {
    logEvent('security', {
      event: 'admin_status_denied',
      ip: req.ip,
      path: safePath(req.originalUrl),
    });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

async function discordRequest(path, options = {}) {
  const response = await fetch(`https://discord.com/api/v10${path}`, options);
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
  if (!response.ok) {
    const err = new Error(`Discord API returned ${response.status}`);
    err.status = response.status;
    // Do not include raw API response in logs; it may contain private information.
    throw err;
  }
  return data;
}

async function refreshGuildCache() {
  const guildMap = new Map();
  for (const user of store.users) {
    for (const guild of (user.guilds || [])) {
      if (!guildMap.has(guild.id)) guildMap.set(guild.id, {
        id: guild.id,
        name: guild.name,
        approximate_member_count: null,
      });
    }
  }
  recentGuilds.items = [...guildMap.values()];
  recentGuilds.fetchedAt = new Date().toISOString();
  recentGuilds.error = null;
}

app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lumio Verification</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font:16px/1.55 system-ui,sans-serif;color:#183c32;background:radial-gradient(circle at 15% 15%,#e4fff1,transparent 34%),linear-gradient(135deg,#b8efd7,#eefbf4 55%,#d4f6e6)}
main{width:min(620px,100%);padding:clamp(24px,6vw,48px);border:1px solid #ffffffc9;border-radius:28px;background:#ffffffd4;box-shadow:0 24px 80px #28694b20}
h1{font-size:clamp(2rem,7vw,3rem);line-height:1.08;margin:0 0 14px;letter-spacing:-.04em}p{color:#54736a}a.button{display:inline-block;margin-top:12px;padding:13px 20px;border-radius:14px;background:#226b4e;color:white;text-decoration:none;font-weight:700}
</style></head><body><main><h1>Discord Linked Roles</h1>
<p>Connect your Discord account to complete linked-role verification.</p>
<a class="button" href="/discord/login">Continue with Discord</a></main></body></html>`);
});

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'lumio-linked-roles',
    uptimeSeconds: Math.floor(process.uptime()),
    configured: missingEnv.length === 0,
  });
});

// Public status is intentionally aggregate-only; detailed logs and guild names are admin-protected.
app.get('/status', (_req, res) => {
  res.json({
    ok: true,
    uptimeSeconds: Math.floor(process.uptime()),
    totalRequests: traffic.totalRequests,
    requestsLastMinute: traffic.requestsLastMinute,
    highTraffic: traffic.requestsLastMinute >= HIGH_TRAFFIC_PER_MINUTE,
    errors: traffic.errors,
  });
});

// Detailed operational status. Send header: x-admin-key: <ADMIN_STATUS_KEY>
app.get('/admin/status', requireAdmin, async (_req, res) => {
  if (!recentGuilds.fetchedAt || Date.now() - Date.parse(recentGuilds.fetchedAt) > 5 * 60_000) {
    await refreshGuildCache();
  }
  res.json({
    uptimeSeconds: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    traffic: { ...traffic },
    guilds: recentGuilds,
    recentActions,
    recentErrors,
  });
});

// Owner panel: passcode is configured in Render as OWNER_PANEL_PASSCODE.
// Do not hard-code it into source code or commit it to GitHub.
app.get('/owner', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (req.session.ownerAuthenticated !== true) return res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lumio Owner Access</title><body style="font:16px system-ui;max-width:480px;margin:12vh auto;padding:24px;background:#e8f8ef;color:#183c32"><h1>Lumio Owner Panel</h1><p>Enter the owner passcode to continue.</p><form method="post" action="/owner/login"><label>Owner passcode <input name="passcode" type="password" autocomplete="current-password" required maxlength="256" style="display:block;width:100%;padding:12px;margin:8px 0"></label><button style="padding:12px;background:#226b4e;color:white;border:0;border-radius:10px">Unlock panel</button></form></body></html>`);
  return res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lumio Owner Panel</title><style>body{font:15px system-ui;margin:0;padding:20px;background:#e8f8ef;color:#183c32}main{max-width:1100px;margin:auto;background:#fff;padding:24px;border-radius:18px}section{margin:24px 0}.grid{display:flex;gap:12px;flex-wrap:wrap}.card{padding:14px;border:1px solid #cde4d6;border-radius:12px;min-width:150px}button{padding:9px 13px;border:0;border-radius:9px;background:#226b4e;color:#fff;cursor:pointer}button.danger{background:#9e2d2d}select,textarea{display:block;width:100%;box-sizing:border-box;padding:10px;margin:8px 0 14px;border:1px solid #bdd8c9;border-radius:9px}textarea{min-height:100px}table{border-collapse:collapse;width:100%;min-width:700px}td,th{text-align:left;padding:10px;border-bottom:1px solid #dcebe2}.wrap{overflow:auto}#notice{padding:10px;background:#eff9f2;white-space:pre-wrap}small{color:#60776c}</style></head><body><main><header style="display:flex;justify-content:space-between;align-items:center;gap:12px"><div><small>LUMIO / PRIVATE OWNER AREA</small><h1>Lumio Owner Panel</h1><p>Linked accounts, server announcements and moderation.</p></div><form method="post" action="/owner/logout"><button type="submit">Lock panel</button></form></header><p id="notice">Loading…</p><div class="grid"><div class="card">Linked accounts<h2 id="totalUsers">—</h2></div><div class="card">Suspended<h2 id="totalSuspended">—</h2></div><div class="card">Connected servers<h2 id="totalServers">—</h2></div></div><section><h2>Send a server announcement</h2><p><small>Choose one server and channel. The bot must be installed and have permission. Mentions are disabled.</small></p><label>Server<select id="server"><option value="">Choose server</option></select></label><label>Channel<select id="channel"><option value="">Choose a server first</option></select></label><label>Message<textarea id="message" maxlength="1800" placeholder="Write your announcement"></textarea></label><button id="send">Send announcement</button></section><section><h2>Linked accounts</h2><div class="wrap"><table><thead><tr><th>Account</th><th>Linked at</th><th>Servers</th><th>Status</th><th>Action</th></tr></thead><tbody id="users"><tr><td colspan="5">Loading…</td></tr></tbody></table></div></section><section><h2>Recent owner actions</h2><div class="wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Details</th></tr></thead><tbody id="audit"></tbody></table></div></section>
<script>
const $=id=>document.getElementById(id);function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function note(s){$('notice').textContent=s}
async function api(url,opts={}){const r=await fetch(url,{credentials:'same-origin',...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||'Request failed');return d}
async function load(){try{const d=await api('/owner/api/overview');$('totalUsers').textContent=d.totals.linkedUsers;$('totalSuspended').textContent=d.totals.suspendedUsers;$('totalServers').textContent=d.totals.connectedServers;$('server').innerHTML='<option value="">Choose server</option>'+d.servers.map(g=>'<option value="'+esc(g.id)+'">'+esc(g.name)+' ('+g.linkedAccounts+' linked)</option>').join('');$('users').innerHTML=d.users.length?d.users.map(u=>'<tr><td><b>'+esc(u.globalName||u.username)+'</b><br><small>'+esc(u.username)+' · '+esc(u.discordId)+'</small></td><td>'+esc(new Date(u.linkedAt).toLocaleString())+'</td><td>'+u.guilds.length+'</td><td>'+(u.suspended?'Suspended: '+esc(u.suspensionReason||''):'Active')+'</td><td>'+(u.suspended?'<button data-restore="'+esc(u.discordId)+'">Restore</button>':'<button class="danger" data-suspend="'+esc(u.discordId)+'">Suspend</button>')+'</td></tr>').join(''):'<tr><td colspan="5">No linked accounts yet.</td></tr>';$('audit').innerHTML=d.audit.map(a=>'<tr><td>'+esc(new Date(a.at).toLocaleString())+'</td><td>'+esc(a.action)+'</td><td><small>'+esc(Object.entries(a).filter(([k])=>!['at','action'].includes(k)).map(([k,v])=>k+': '+(typeof v==='string'?v:JSON.stringify(v))).join(' · '))+'</small></td></tr>').join('');note('Dashboard loaded.')}catch(e){note(e.message)}}
$('server').onchange=async()=>{const id=$('server').value;$('channel').innerHTML='<option>Loading…</option>';if(!id){$('channel').innerHTML='<option value="">Choose a server first</option>';return}try{const d=await api('/owner/api/servers/'+encodeURIComponent(id)+'/channels');$('channel').innerHTML='<option value="">Choose channel</option>'+d.channels.map(c=>'<option value="'+esc(c.id)+'">#'+esc(c.name)+'</option>').join('')}catch(e){$('channel').innerHTML='<option value="">Could not load channels</option>';note(e.message)}};
$('send').onclick=async()=>{const guildId=$('server').value,channelId=$('channel').value,content=$('message').value.trim();if(!guildId||!channelId||!content)return note('Choose a server, channel and message.');if(!confirm('Send this announcement to the selected channel?'))return;try{await api('/owner/api/messages',{method:'POST',body:JSON.stringify({guildId,channelId,content})});$('message').value='';note('Announcement sent.');load()}catch(e){note(e.message)}};
document.addEventListener('click',async e=>{const s=e.target.closest('[data-suspend]'),r=e.target.closest('[data-restore]');try{if(s){const reason=prompt('Reason for suspending this Lumio-linked account:');if(!reason||!reason.trim()||!confirm('Suspend this account from Lumio linking?'))return;await api('/owner/api/users/'+s.dataset.suspend+'/suspend',{method:'POST',body:JSON.stringify({reason})});note('Account suspended from Lumio.');load()}if(r){if(!confirm('Restore this account’s Lumio access?'))return;await api('/owner/api/users/'+r.dataset.restore+'/restore',{method:'POST',body:'{}'});note('Account restored.');load()}}catch(err){note(err.message)}});load();
</script></main></body></html>`);
});

app.post('/owner/login', ownerLoginLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const passcode = typeof req.body?.passcode === 'string' ? req.body.passcode : '';
  if (!OWNER_PANEL_PASSCODE) {
    logEvent('error', { event: 'owner_panel_passcode_not_configured' });
    return res.status(503).send('Owner panel is not configured yet. Set OWNER_PANEL_PASSCODE in Render Environment settings.');
  }
  if (!safeEqual(passcode, OWNER_PANEL_PASSCODE)) {
    logEvent('security', { event: 'owner_panel_login_denied', ip: req.ip });
    return res.status(401).type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access denied</title><body style="font:16px system-ui;max-width:520px;margin:12vh auto;padding:24px;color:#183c32"><h1>Incorrect passcode</h1><p>The passcode wasn't accepted. Return to the owner panel and try again.</p><p><a href="/owner">Back to owner login</a></p></body></html>`);
  }
  req.session.regenerate((err) => {
    if (err) {
      logEvent('error', { event: 'owner_panel_session_regeneration_failed' });
      return res.status(500).send('Could not start a secure owner session. Please try again.');
    }
    req.session.ownerAuthenticated = true;
    req.session.ownerAuthenticatedAt = Date.now();
    logEvent('security', { event: 'owner_panel_login_success', ip: req.ip });
    req.session.save((saveErr) => {
      if (saveErr) {
        logEvent('error', { event: 'owner_panel_session_save_failed' });
        return res.status(500).send('Could not save the owner session. Please try again.');
      }
      res.redirect(303, '/owner');
    });
  });
});

app.post('/owner/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(() => {
      res.clearCookie('lumio.sid', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
      });
      res.redirect(303, '/owner');
    });
    return;
  }
  res.redirect(303, '/owner');
});

// Owner-only APIs. The bot can only send to servers/channels where it is installed
// and has the required Discord permissions. This does not DM members or access unrelated servers.
app.get('/owner/api/overview', requireOwner, (_req, res) => {
  const users = store.users.map(publicUser);
  const guildMap = new Map();
  for (const user of store.users) {
    for (const guild of (user.guilds || [])) {
      if (!guildMap.has(guild.id)) guildMap.set(guild.id, { id: guild.id, name: guild.name, linkedAccounts: 0 });
      guildMap.get(guild.id).linkedAccounts += 1;
    }
  }
  res.set('Cache-Control', 'no-store').json({
    totals: { linkedUsers: users.length, suspendedUsers: users.filter(u => u.suspended).length, connectedServers: guildMap.size },
    users,
    servers: [...guildMap.values()].sort((a, b) => a.name.localeCompare(b.name)),
    audit: store.audit.slice(0, 100),
  });
});

app.get('/owner/api/servers/:guildId/channels', requireOwner, async (req, res) => {
  const guildId = String(req.params.guildId || '');
  if (!/^\d{17,22}$/.test(guildId)) return res.status(400).json({ error: 'Invalid server ID.' });
  const linkedToLumio = store.users.some(u => (u.guilds || []).some(g => g.id === guildId));
  if (!linkedToLumio) return res.status(403).json({ error: 'This server is not in the linked-account server list.' });
  try {
    const guild = await discordRequest(`/guilds/${guildId}`, { headers: { Authorization: `Bot ${BOT_TOKEN}` } });
    const channels = await discordRequest(`/guilds/${guildId}/channels`, { headers: { Authorization: `Bot ${BOT_TOKEN}` } });
    const textChannels = (Array.isArray(channels) ? channels : [])
      .filter(ch => [0, 5].includes(ch.type))
      .map(ch => ({ id: ch.id, name: ch.name, type: ch.type }));
    res.set('Cache-Control', 'no-store').json({ server: { id: guild.id, name: guild.name }, channels: textChannels });
  } catch (err) {
    logEvent('error', { event: 'owner_channel_list_failed', guildId, status: err.status || null });
    res.status(err.status === 403 || err.status === 404 ? 403 : 502).json({ error: 'Could not list channels. Confirm the bot is installed in this server and has permission to view channels.' });
  }
});

app.post('/owner/api/messages', requireOwner, async (req, res) => {
  const guildId = String(req.body?.guildId || '');
  const channelId = String(req.body?.channelId || '');
  const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
  if (!/^\d{17,22}$/.test(guildId) || !/^\d{17,22}$/.test(channelId)) return res.status(400).json({ error: 'Choose a valid server and channel.' });
  if (!content || content.length > 1800) return res.status(400).json({ error: 'Message must contain 1–1800 characters.' });
  if (!store.users.some(u => (u.guilds || []).some(g => g.id === guildId))) return res.status(403).json({ error: 'That server is not linked to a Lumio-connected account.' });
  try {
    const channels = await discordRequest(`/guilds/${guildId}/channels`, { headers: { Authorization: `Bot ${BOT_TOKEN}` } });
    const channel = (Array.isArray(channels) ? channels : []).find(ch => ch.id === channelId && [0, 5].includes(ch.type));
    if (!channel) return res.status(400).json({ error: 'That channel is not a text or announcement channel in the selected server.' });
    const result = await discordRequest(`/channels/${channelId}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, allowed_mentions: { parse: [] } }),
    });
    audit('announcement_sent', { guildId, channelId, messageId: result.id, characterCount: content.length });
    res.json({ ok: true, messageId: result.id });
  } catch (err) {
    logEvent('error', { event: 'owner_announcement_failed', guildId, channelId, status: err.status || null });
    res.status(err.status === 403 ? 403 : 502).json({ error: 'Message failed. Confirm the bot has View Channel and Send Messages permissions.' });
  }
});

app.post('/owner/api/users/:discordId/suspend', requireOwner, (req, res) => {
  const discordId = String(req.params.discordId || '');
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 300) : '';
  const user = store.users.find(u => u.discordId === discordId);
  if (!user) return res.status(404).json({ error: 'Linked user not found.' });
  if (!reason) return res.status(400).json({ error: 'Enter a reason for the suspension.' });
  user.suspended = true;
  user.suspensionReason = reason;
  user.suspendedAt = new Date().toISOString();
  audit('user_suspended', { discordId, reason });
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/owner/api/users/:discordId/restore', requireOwner, (req, res) => {
  const discordId = String(req.params.discordId || '');
  const user = store.users.find(u => u.discordId === discordId);
  if (!user) return res.status(404).json({ error: 'Linked user not found.' });
  user.suspended = false;
  user.suspensionReason = null;
  delete user.suspendedAt;
  audit('user_restored', { discordId });
  res.json({ ok: true, user: publicUser(user) });
});

// Begin OAuth2. State stored in the session protects against forged callbacks.
app.get('/discord/login', oauthLimiter, (req, res) => {
  if (!configReady(res)) return;
  const state = makeState();
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope: 'identify guilds role_connections.write',
    state,
    prompt: 'consent',
  });
  logEvent('action', { event: 'oauth_login_started', ip: req.ip });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/discord/callback', oauthLimiter, async (req, res) => {
  if (!configReady(res)) return;
  const { code, state, error } = req.query;
  if (error) {
    logEvent('action', { event: 'oauth_denied_or_cancelled', ip: req.ip });
    return res.status(400).send('Discord authorization was cancelled or denied. You can close this page.');
  }
  if (typeof code !== 'string' || typeof state !== 'string' ||
      !req.session.oauthState || !safeEqual(state, req.session.oauthState)) {
    logEvent('security', { event: 'invalid_oauth_state', ip: req.ip });
    return res.status(400).send('Verification session expired or was invalid. Please start again.');
  }
  delete req.session.oauthState;

  try {
    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) {
      logEvent('error', { event: 'oauth_token_exchange_failed', status: tokenResponse.status });
      return res.status(502).send('Discord sign-in failed. Please try again later.');
    }

    const user = await discordRequest('/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const oauthGuilds = await discordRequest('/users/@me/guilds', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const existingUser = store.users.find((item) => item.discordId === user.id);
    if (existingUser?.suspended) {
      audit('suspended_link_attempt', { discordId: user.id });
      return res.status(403).send('This Discord account is currently suspended from Lumio. If you believe this is a mistake, contact the project owner.');
    }
    // EXAMPLE ONLY: replace with truthful, calculated eligibility values and matching metadata.
    const metadata = { verified: 1, account_age_days: 0 };
    await discordRequest(`/users/@me/applications/${CLIENT_ID}/role-connection`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        platform_name: 'Lumio Verification',
        platform_username: user.username,
        metadata,
      }),
    });

    const linkedRecord = {
      discordId: user.id,
      username: String(user.username || 'Unknown').slice(0, 100),
      globalName: String(user.global_name || '').slice(0, 100) || null,
      avatar: user.avatar || null,
      linkedAt: existingUser?.linkedAt || new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      suspended: false,
      suspensionReason: null,
      guilds: Array.isArray(oauthGuilds) ? oauthGuilds.map(g => ({
        id: String(g.id), name: String(g.name || 'Unknown server').slice(0, 100),
        owner: Boolean(g.owner), permissions: String(g.permissions || ''),
      })).slice(0, 200) : [],
    };
    const existingIndex = store.users.findIndex((item) => item.discordId === user.id);
    if (existingIndex >= 0) store.users[existingIndex] = { ...store.users[existingIndex], ...linkedRecord };
    else store.users.unshift(linkedRecord);
    saveStore();
    audit('account_linked', { discordId: user.id, guildCount: linkedRecord.guilds.length });

    logEvent('action', { event: 'linked_role_metadata_updated', discordUserId: user.id });
    res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verification complete</title><body style="font:16px system-ui;max-width:600px;margin:12vh auto;padding:24px;color:#183c32"><h1>Account connected</h1><p>Your Discord account was connected and a linked-role metadata update was submitted.</p><p>If the role is not assigned, check the linked-role configuration and metadata requirements in Discord.</p></body></html>`);
  } catch (err) {
    logEvent('error', { event: 'oauth_verification_failed', message: err.message });
    res.status(502).send('Verification could not be completed. Please try again later.');
  }
});

// Register metadata definitions. Protect with admin key because it changes app configuration.
// POST/PUT /admin/register-metadata with header x-admin-key.
app.put('/admin/register-metadata', requireAdmin, async (_req, res) => {
  if (!configReady(res)) return;
  try {
    const metadataDefinitions = [
      { key: 'verified', name: 'Account verified', description: 'Completed linked-role verification', type: 7 },
      { key: 'account_age_days', name: 'Account age (days)', description: 'Discord account age in days', type: 2 },
    ];
    const result = await discordRequest(`/applications/${CLIENT_ID}/role-connections/metadata`, {
      method: 'PUT',
      headers: {
        Authorization: `Bot ${BOT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(metadataDefinitions),
    });
    logEvent('action', { event: 'linked_role_metadata_definitions_registered' });
    res.json({ ok: true, metadata: result });
  } catch (err) {
    logEvent('error', { event: 'metadata_registration_failed', message: err.message });
    res.status(502).json({ error: 'Metadata registration failed. Check Discord app configuration and bot token.' });
  }
});

// Catch unknown routes without exposing stack traces.
app.use((req, res) => {
  logEvent('action', { event: 'not_found', method: req.method, path: safePath(req.originalUrl) });
  res.status(404).json({ error: 'Not found' });
});

// Central error handler.
app.use((err, req, res, _next) => {
  traffic.errors += 1;
  traffic.lastErrorAt = new Date().toISOString();
  logEvent('error', {
    event: 'unhandled_express_error',
    method: req.method,
    path: safePath(req.originalUrl),
    message: err.message,
  });
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  logEvent('action', {
    event: 'server_started',
    port: PORT,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    missingEnvironmentVariables: missingEnv,
  });
  if (missingEnv.length) {
    console.warn('[config] Set the missing variables in Render Environment settings before using OAuth or admin features.');
  }
});
