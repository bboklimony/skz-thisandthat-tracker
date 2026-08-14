import { Redis } from '@upstash/redis';
import { getNicknameFromRequest, isAdmin, generateInviteCode } from './_lib/auth-helpers.js';

const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
let redis = null;
if (url && token) {
  redis = new Redis({ url, token, enableAutoPipelining: false });
}

const INDEX_KEY = 'invite_codes_index';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!redis) {
    res.status(500).json({
      error: 'storage_not_connected',
      message: 'Storage(Redis)가 아직 연결되지 않았어요.',
    });
    return;
  }

  const nickname = getNicknameFromRequest(req);
  if (!isAdmin(nickname)) {
    res.status(403).json({ error: 'forbidden', message: '관리자만 사용할 수 있어요.' });
    return;
  }

  if (req.method === 'GET') {
    const codes = (await redis.smembers(INDEX_KEY)) || [];
    const records = await Promise.all(
      codes.map(async (code) => {
        const rec = await redis.get(`invite:${code}`);
        return { code, ...(rec || {}) };
      })
    );
    records.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    res.status(200).json({ codes: records });
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

  if (body.action === 'create') {
    const note = String(body.note || '').slice(0, 100);
    let code = null;
    for (let i = 0; i < 5; i++) {
      const candidate = generateInviteCode();
      const exists = await redis.get(`invite:${candidate}`);
      if (!exists) { code = candidate; break; }
    }
    if (!code) {
      res.status(500).json({ error: 'code_generation_failed', message: '코드 생성에 실패했어요. 다시 시도해주세요.' });
      return;
    }
    await redis.set(`invite:${code}`, {
      createdAt: new Date().toISOString(),
      usedBy: null,
      usedAt: null,
      note,
    });
    await redis.sadd(INDEX_KEY, code);
    res.status(200).json({ ok: true, code });
    return;
  }

  if (body.action === 'revoke') {
    const code = String(body.code || '').trim().toUpperCase();
    if (!code) {
      res.status(400).json({ error: 'code_required', message: '코드를 지정해주세요.' });
      return;
    }
    const invite = await redis.get(`invite:${code}`);
    if (invite && invite.usedBy) {
      // Refuse to delete a code that's already been redeemed -- it's the
      // only record of which account used it, and deleting it wouldn't
      // undo the signup anyway (only free the code for the wrong reason).
      res.status(400).json({ error: 'already_used', message: '이미 사용된 코드는 삭제할 수 없어요 (사용 기록 보존).' });
      return;
    }
    await redis.del(`invite:${code}`);
    await redis.del(`invite:${code}:claim`);
    await redis.srem(INDEX_KEY, code);
    res.status(200).json({ ok: true });
    return;
  }

  res.status(400).json({ error: 'unknown_action' });
}
