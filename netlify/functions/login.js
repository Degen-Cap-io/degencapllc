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

  // Constant-time comparison to prevent timing attacks
  const userMatch = crypto.timingSafeEqual(
    Buffer.from(username || ''),
    Buffer.from(validUser)
  );
  const passMatch = crypto.timingSafeEqual(
    Buffer.from(password || ''),
    Buffer.from(validPass)
  );

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
