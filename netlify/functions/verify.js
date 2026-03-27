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

  const { token } = body;
  const secret = process.env.DC_SECRET;

  if (!secret) {
    return { statusCode: 500, body: 'Server configuration error' };
  }

  if (!token || typeof token !== 'string') {
    return { statusCode: 401, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ valid: false }) };
  }

  const parts = token.split(':');
  if (parts.length !== 3) {
    return { statusCode: 401, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ valid: false }) };
  }

  const [expiry, username, hmac] = parts;

  // Check expiry
  if (Date.now() > parseInt(expiry, 10)) {
    return { statusCode: 401, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ valid: false, reason: 'expired' }) };
  }

  // Re-compute HMAC and compare
  const payload = `${expiry}:${username}`;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const valid = crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expected));

  return {
    statusCode: valid ? 200 : 401,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ valid })
  };
};
