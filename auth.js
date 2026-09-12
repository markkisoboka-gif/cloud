// Simple, stateless session tokens for a single owner — no session database needed.
// A token is: base64url(payload) + "." + HMAC-SHA256 signature of that payload,
// signed with a server-only secret. Anyone can read the payload, but nobody
// can forge a valid signature without the secret, so it can't be faked.
//
// Cloudflare Workers don't run Node.js — they use the browser-standard Web
// Crypto API instead, which is why this looks different from the Vercel/
// Netlify version, even though the actual security logic is identical.

const SESSION_HOURS = 24;

function toBase64Url(bytes) {
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function createToken(secret) {
  const payload = JSON.stringify({ exp: Date.now() + SESSION_HOURS * 60 * 60 * 1000 });
  const payloadB64 = toBase64Url(new TextEncoder().encode(payload));
  const key = await getKey(secret);
  const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sig = toBase64Url(new Uint8Array(sigBuffer));
  return `${payloadB64}.${sig}`;
}

export async function verifyToken(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payloadB64, sig] = parts;

  try {
    const key = await getKey(secret);
    const valid = await crypto.subtle.verify(
      'HMAC', key, fromBase64Url(sig), new TextEncoder().encode(payloadB64)
    );
    if (!valid) return false;

    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(payloadB64)));
    return typeof payload.exp === 'number' && Date.now() < payload.exp;
  } catch {
    return false;
  }
}
