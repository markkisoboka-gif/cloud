// Cloudflare Worker — combines everything the six separate Vercel/Netlify
// files used to do into one script, since that's how Cloudflare Workers
// are structured. Each of the original files' logic lives in its own
// clearly-labeled section below, doing exactly the same job as before.

import { createToken, verifyToken } from './auth.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
  });
}

async function redisGet(env, key) {
  const res = await fetch(`${env.KV_REST_API_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${env.KV_REST_API_TOKEN}` }
  });
  const data = await res.json();
  return data.result;
}

async function redisSet(env, key, value) {
  const res = await fetch(`${env.KV_REST_API_URL}/set/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.KV_REST_API_TOKEN}`, 'Content-Type': 'text/plain' },
    body: value
  });
  if (!res.ok) throw new Error('Redis set failed: ' + res.status);
}

async function redisIncr(env, key) {
  const res = await fetch(`${env.KV_REST_API_URL}/incr/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.KV_REST_API_TOKEN}` }
  });
  if (!res.ok) throw new Error('Redis incr failed: ' + res.status);
}

// ===== was: /api/login.js =====
async function timingSafeStringEqual(a, b) {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a), bBytes = enc.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}

async function handleLogin(request, env) {
  if (!env.OWNER_PASSWORD) return json({ error: 'Owner password not configured on the server yet.' }, 500);
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const submitted = ((body && body.password) || '').trim();
  const expected = env.OWNER_PASSWORD.trim();

  if (!(await timingSafeStringEqual(submitted, expected))) {
    return json({ error: 'Incorrect password' }, 401);
  }
  return json({ token: await createToken(env.SESSION_SECRET) });
}

// ===== was: /api/quote.js =====
async function handleQuote(request, env) {
  const url = new URL(request.url);
  const symbol = url.searchParams.get('symbol');
  if (!symbol) return json({ error: 'Missing symbol parameter' }, 400);

  try {
    const yahooUrl = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1m&range=1d`;
    const yahooRes = await fetch(yahooUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ProportionalPlatform/1.0)' }
    });
    if (!yahooRes.ok) return json({ error: `Yahoo responded with ${yahooRes.status}` }, 502);
    const data = await yahooRes.json();
    const price = data?.chart?.result?.[0]?.meta?.regularMarketPrice;
    if (typeof price !== 'number') return json({ error: 'No price in Yahoo response' }, 502);
    return json({ symbol, price });
  } catch (err) {
    return json({ error: 'Fetch failed', detail: String(err) }, 500);
  }
}

// ===== was: /api/state.js =====
async function handleState(request, env) {
  if (!env.KV_REST_API_URL || !env.KV_REST_API_TOKEN) {
    return json({
      error: 'Storage not configured on the server yet.',
      diagnostic: {
        urlPresent: !!env.KV_REST_API_URL,
        urlLength: env.KV_REST_API_URL ? env.KV_REST_API_URL.length : 0,
        tokenPresent: !!env.KV_REST_API_TOKEN,
        tokenLength: env.KV_REST_API_TOKEN ? env.KV_REST_API_TOKEN.length : 0
      }
    }, 500);
  }

  if (request.method === 'GET') {
    try {
      const raw = await redisGet(env, 'platform:state');
      if (raw === null) return json({ state: null });
      return json({ state: JSON.parse(raw) });
    } catch (err) {
      return json({ error: 'Failed to read state', detail: String(err) }, 500);
    }
  }

  if (request.method === 'POST') {
    const authHeader = request.headers.get('authorization') || '';
    const token = authHeader.replace(/^Bearer\s+/i, '');
    if (!(await verifyToken(token, env.SESSION_SECRET))) {
      return json({ error: 'Not authorized. Please sign in again.' }, 401);
    }
    try {
      const body = await request.json();
      if (!body || typeof body !== 'object') return json({ error: 'Invalid state payload' }, 400);
      await redisSet(env, 'platform:state', JSON.stringify(body));
      return json({ ok: true });
    } catch (err) {
      return json({ error: 'Failed to save state', detail: String(err) }, 500);
    }
  }

  return json({ error: 'Method not allowed' }, 405);
}

// ===== was: /api/visit.js =====
async function handleVisit(request, env) {
  if (!env.KV_REST_API_URL || !env.KV_REST_API_TOKEN) {
    return json({ error: 'Storage not configured on the server yet.' }, 500);
  }
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const site = body && body.site;
  if (!['platform', 'landing'].includes(site)) {
    return json({ error: 'site must be "platform" or "landing"' }, 400);
  }
  try {
    await redisIncr(env, `visits:${site}`);
    return json({ ok: true });
  } catch (err) {
    return json({ error: 'Failed to record visit', detail: String(err) }, 500);
  }
}

// ===== was: /api/visits-stats.js =====
async function handleVisitsStats(request, env) {
  const authHeader = request.headers.get('authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!(await verifyToken(token, env.SESSION_SECRET))) {
    return json({ error: 'Not authorized.' }, 401);
  }
  if (!env.KV_REST_API_URL || !env.KV_REST_API_TOKEN) {
    return json({ error: 'Storage not configured on the server yet.' }, 500);
  }
  try {
    const [platform, landing] = await Promise.all([
      redisGet(env, 'visits:platform'),
      redisGet(env, 'visits:landing')
    ]);
    return json({ platform: parseInt(platform, 10) || 0, landing: parseInt(landing, 10) || 0 });
  } catch (err) {
    return json({ error: 'Failed to read visit stats', detail: String(err) }, 500);
  }
}

// ===== Router: sends each /api/... request to the right handler above =====
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 200, headers: CORS_HEADERS });
    }

    const path = new URL(request.url).pathname;

    if (path === '/api/login') return handleLogin(request, env);
    if (path === '/api/quote') return handleQuote(request, env);
    if (path === '/api/state') return handleState(request, env);
    if (path === '/api/visit') return handleVisit(request, env);
    if (path === '/api/visits-stats') return handleVisitsStats(request, env);

    // Anything not matching an API route falls through to the static site
    return env.ASSETS.fetch(request);
  }
};
