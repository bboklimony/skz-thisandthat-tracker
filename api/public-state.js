import { Redis } from '@upstash/redis';

const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
let redis = null;
if (url && token) {
  redis = new Redis({ url, token, enableAutoPipelining: false });
}

// Public, unauthenticated endpoint backing share.html. Only ever returns
// itemState (owned/trading/need status per card) — never tradeLog,
// recipients, or fullship, since those contain other people's contact info
// and shouldn't be exposed on an unauthenticated link.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!redis) {
    res.status(500).json({ error: 'storage_not_connected', message: 'Storage(Redis)가 아직 연결되지 않았어요.' });
    return;
  }
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }

  let shareToken = null;
  try {
    const parsed = new URL(req.url, 'http://localhost');
    shareToken = parsed.searchParams.get('token');
  } catch (e) {
    shareToken = null;
  }

  if (!shareToken) {
    res.status(400).json({ error: 'missing_token', message: '공유 링크가 올바르지 않아요.' });
    return;
  }

  const nickname = await redis.get(`share:${shareToken}`);
  if (!nickname) {
    res.status(404).json({ error: 'invalid_link', message: '유효하지 않거나 재발급되어 만료된 링크예요.' });
    return;
  }

  const data = await redis.get(`state:${nickname}`);
  res.status(200).json({ nickname, itemState: data ? data.itemState || null : null });
}
