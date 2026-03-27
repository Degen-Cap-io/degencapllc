const crypto = require('crypto');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: 'Bad Request' };
  }

  const { username, password } = body;

  const validUser = process.env.INVESTOR_USERNAME;
  const validPass = process.env.INVESTOR_PASSWORD;
  const secret    = process.env.DC_SECRET;

  if (!validUser || !validPass || !secret) {
    console.error('Missing required environment variables');
    return { statusCode: 500, body: 'Server configuration error' };
  }

  // Constant-time comparison (pad to same length to avoid throws on mismatch)
  const u1 = Buffer.from((username || '').padEnd(64));
  const u2 = Buffer.from(validUser.padEnd(64));
  const p1 = Buffer.from((password || '').padEnd(64));
  const p2 = Buffer.from(validPass.padEnd(64));

  const userMatch = crypto.timingSafeEqual(u1, u2) && (username || '').length === validUser.length;
  const passMatch = crypto.timingSafeEqual(p1, p2) && (password || '').length === validPass.length;

  if (!userMatch || !passMatch) {
    return {
      statusCode: 401,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid credentials' })
    };
  }

  // Issue a signed token: expiry|hmac
  const expiry = Date.now() + 8 * 60 * 60 * 1000; // 8 hours
  const payload = `${expiry}:${username}`;
  const hmac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const token = `${payload}:${hmac}`;

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  };
};
