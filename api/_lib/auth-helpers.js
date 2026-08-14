import crypto from 'crypto';

export const COOKIE_NAME = 'skzsess';
export const NICK_RE = /^[a-zA-Z0-9가-힣_.\-]{2,20}$/;

// The Redis/Upstash token doubles as our HMAC signing secret: it's already a
// unique per-deployment secret injected by Vercel, so this needs no extra
// env var for a non-technical user to set up.
export function getSecret() {
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return token || 'insecure-dev-secret-change-me';
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx < 0) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

export function sign(value) {
  const h = crypto.createHmac('sha256', getSecret()).update(value).digest('hex');
  return `${value}.${h}`;
}

export function unsign(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf('.');
  if (idx < 0) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expected = crypto.createHmac('sha256', getSecret()).update(value).digest('hex');
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;
  return value;
}

export function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

export function safeEqualHex(hexA, hexB) {
  const a = Buffer.from(hexA, 'hex');
  const b = Buffer.from(hexB, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isHttps(req) {
  return req.headers['x-forwarded-proto'] === 'https';
}

export function setSessionCookie(req, res, nickname) {
  const value = sign(nickname);
  const secure = isHttps(req) ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 365}${secure}`
  );
}

export function clearSessionCookie(req, res) {
  const secure = isHttps(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}

export function getNicknameFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  return unsign(cookies[COOKIE_NAME]);
}
