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
const BASE_URL = process.env.BASE_URL || '';

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
const MAX_RECENT = 100;
const HIGH_TRAFFIC_PER_MINUTE = Number(process.env.HIGH_TRAFFIC_PER_MINUTE) || 180;

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
  if (!BOT_TOKEN) return;
  try {
    const guilds = await discordRequest('/users/@me/guilds?with_counts=true', {
      headers: { Authorization: `Bot ${BOT_TOKEN}` },
    });
    recentGuilds.items = Array.isArray(guilds)
      ? guilds.map(g => ({
          id: g.id,
          name: g.name,
          approximate_member_count: Number.isFinite(g.approximate_member_count)
            ? g.approximate_member_count : null,
        }))
      : [];
    recentGuilds.fetchedAt = new Date().toISOString();
    recentGuilds.error = null;
    logEvent('action', { event: 'guild_cache_refreshed', guildCount: recentGuilds.items.length });
  } catch (err) {
    recentGuilds.error = 'Discord API request failed';
    logEvent('error', { event: 'guild_cache_refresh_failed', message: err.message });
  }
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

// Begin OAuth2. State stored in the session protects against forged callbacks.
app.get('/discord/login', oauthLimiter, (req, res) => {
  if (!configReady(res)) return;
  const state = makeState();
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope: 'identify role_connections.write',
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
