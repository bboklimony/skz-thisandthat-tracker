import { Redis } from '@upstash/redis';
import crypto from 'crypto';
import {
  NICK_RE,
  hashPassword,
  safeEqualHex,
  setSessionCookie,
  clearSessionCookie,
  getNicknameFromRequest,
} from './_lib/auth-helpers.js';

const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
let redis = null;
if (url && token) {
  // Auto-pipelining batches concurrent commands for latency, but this app's
  // write volume is tiny and simple request/response semantics are easier
  // to reason about, so it's turned off explicitly.
  redis = new Redis({ url, token, enableAutoPipelining: false });
}

function newShareToken() {
  return crypto.randomBytes(20).toString('hex');
}

// Lazily create + persist a share token for a user record that doesn't have
// one yet (e.g. accounts created before this feature existed), keeping the
// reverse lookup key (share:<token> -> nickname) in sync.
async function ensureShareToken(nickname, record) {
  if (record.shareToken) return record.shareToken;
  const shareToken = newShareToken();
  const updated = { ...record, shareToken };
  await redis.set(`user:${nickname}`, updated);
  await redis.set(`share:${shareToken}`, nickname);
  return shareToken;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!redis) {
    res.status(500).json({
      error: 'storage_not_connected',
      message: 'Storage(Redis)가 아직 연결되지 않았어요. Vercel 프로젝트의 Storage 탭에서 Upstash를 연결한 뒤 다시 시도해주세요.',
    });
    return;
  }

  // GET = "who am I" check, used on page load. Also returns the user's
  // share-link token so the frontend can show/copy it without a second
  // round trip.
  if (req.method === 'GET') {
    const nickname = getNicknameFromRequest(req);
    if (!nickname) {
      res.status(200).json({ nickname: null });
      return;
    }
    const record = await redis.get(`user:${nickname}`);
    if (!record) {
      res.status(200).json({ nickname: null });
      return;
    }
    const shareToken = await ensureShareToken(nickname, record);
    res.status(200).json({ nickname, shareToken });
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  body = body || {};
  const action = body.action;

  if (action === 'logout') {
    clearSessionCookie(req, res);
    res.status(200).json({ ok: true });
    return;
  }

  if (action === 'regenerate_share_token') {
    const nickname = getNicknameFromRequest(req);
    if (!nickname) {
      res.status(401).json({ error: 'unauthorized', message: '로그인이 필요해요.' });
      return;
    }
    const record = await redis.get(`user:${nickname}`);
    if (!record) {
      res.status(401).json({ error: 'unauthorized', message: '계정 정보를 찾을 수 없어요.' });
      return;
    }
    if (record.shareToken) {
      await redis.del(`share:${record.shareToken}`);
    }
    const shareToken = newShareToken();
    await redis.set(`user:${nickname}`, { ...record, shareToken });
    await redis.set(`share:${shareToken}`, nickname);
    res.status(200).json({ ok: true, shareToken });
    return;
  }

  const nickname = (body.nickname || '').trim();
  const password = body.password || '';

  if (action === 'signup') {
    if (!NICK_RE.test(nickname)) {
      res.status(400).json({ error: 'invalid_nickname', message: '닉네임은 2~20자의 한글/영문/숫자/-_ 만 가능해요.' });
      return;
    }
    if (password.length < 4) {
      res.status(400).json({ error: 'weak_password', message: '비밀번호는 4자 이상으로 해주세요.' });
      return;
    }
    const inviteCode = (body.inviteCode || '').trim().toUpperCase();
    if (!inviteCode) {
      res.status(400).json({ error: 'invite_code_required', message: '가입하려면 초대 코드가 필요해요.' });
      return;
    }
    const inviteKey = `invite:${inviteCode}`;
    const invite = await redis.get(inviteKey);
    if (!invite) {
      res.status(400).json({ error: 'invalid_invite_code', message: '초대 코드가 올바르지 않아요.' });
      return;
    }
    if (invite.usedBy) {
      res.status(400).json({ error: 'invite_code_used', message: '이미 사용된 초대 코드예요.' });
      return;
    }
    const userKey = `user:${nickname}`;
    const existing = await redis.get(userKey);
    if (existing) {
      res.status(409).json({ error: 'nickname_taken', message: '이미 사용 중인 닉네임이에요.' });
      return;
    }
    // Atomically claim the code with SET-if-not-exists on a dedicated lock
    // key. Two people submitting the same code at nearly the same instant
    // would otherwise both pass the `invite.usedBy` check above before
    // either write lands (a classic check-then-act race) and both get
    // accounts off one paid code. Only the request that wins this NX write
    // is allowed to proceed; everyone else is told the code is used, even
    // if they "checked" first.
    const claimed = await redis.set(`${inviteKey}:claim`, nickname, { nx: true });
    if (claimed !== 'OK') {
      res.status(400).json({ error: 'invite_code_used', message: '이미 사용된 초대 코드예요.' });
      return;
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    const shareToken = newShareToken();
    await redis.set(userKey, { salt, hash, createdAt: new Date().toISOString(), shareToken });
    await redis.set(`share:${shareToken}`, nickname);
    // This second write is just to keep the admin invite-list display
    // (usedBy/usedAt/note) accurate; the claim key above is what actually
    // enforces single-use.
    await redis.set(inviteKey, { ...invite, usedBy: nickname, usedAt: new Date().toISOString() });
    setSessionCookie(req, res, nickname);
    res.status(200).json({ ok: true, nickname });
    return;
  }

  if (action === 'login') {
    const userKey = `user:${nickname}`;
    const record = await redis.get(userKey);
    if (!record || !record.salt || !record.hash) {
      res.status(401).json({ error: 'invalid_credentials', message: '닉네임 또는 비밀번호가 올바르지 않아요.' });
      return;
    }
    const hash = hashPassword(password, record.salt);
    if (!safeEqualHex(hash, record.hash)) {
      res.status(401).json({ error: 'invalid_credentials', message: '닉네임 또는 비밀번호가 올바르지 않아요.' });
      return;
    }
    setSessionCookie(req, res, nickname);
    res.status(200).json({ ok: true, nickname });
    return;
  }

  res.status(400).json({ error: 'unknown_action' });
}
