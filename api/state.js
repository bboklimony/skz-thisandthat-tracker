import { Redis } from '@upstash/redis';
import { getNicknameFromRequest } from './_lib/auth-helpers.js';

// Vercel injects env vars automatically once you connect an Upstash Redis
// storage integration to this project (Project -> Storage -> Upstash).
// The names can be KV_REST_API_* (legacy Vercel KV naming, kept for
// backward compatibility) or UPSTASH_REDIS_REST_* depending on how the
// integration was connected, so we check both.
const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

let redis = null;
if (url && token) {
  // Auto-pipelining batches concurrent commands for latency, but this app's
  // write volume is tiny and simple request/response semantics are easier
  // to reason about, so it's turned off explicitly.
  redis = new Redis({ url, token, enableAutoPipelining: false });
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!redis) {
    res.status(500).json({
      error: 'storage_not_connected',
      message: 'Redis storage is not connected to this project yet. Go to the Vercel project -> Storage tab and connect an Upstash Redis database, then redeploy.',
    });
    return;
  }

  const nickname = getNicknameFromRequest(req);
  if (!nickname) {
    res.status(401).json({ error: 'unauthorized', message: '로그인이 필요해요.' });
    return;
  }
  // Each user's data lives under its own key, keyed by their nickname, so
  // separate accounts never see or overwrite each other's collection.
  const STATE_KEY = `state:${nickname}`;

  try {
    if (req.method === 'GET') {
      const data = await redis.get(STATE_KEY);
      res.status(200).json(data || null);
      return;
    }

    if (req.method === 'PUT' || req.method === 'POST') {
      let body = req.body;
      if (typeof body === 'string') {
        try { body = JSON.parse(body); } catch (e) { body = null; }
      }
      if (!body || typeof body !== 'object') {
        res.status(400).json({ error: 'invalid_body' });
        return;
      }
      await redis.set(STATE_KEY, body);
      res.status(200).json({ ok: true });
      return;
    }

    res.status(405).json({ error: 'method_not_allowed' });
  } catch (err) {
    res.status(500).json({ error: 'server_error', message: String((err && err.message) || err) });
  }
}
