// auth — all token + password logic lives here.
// Fixes vs the original:
//  1. Syntax: the old file never closed authenticate() (missing `}`) — the
//     whole app crashed on require. Fixed.
//  2. Passwords were plaintext and compared with `stored.toUpperCase() ===
//     input`, which REJECTED the real password ('Admin123') and ACCEPTED
//     only its all-caps form ('ADMIN123'). Now: scrypt hashes, exact verify
//     with timingSafeEqual, no case mangling.
//  3. authenticate() crashed (TypeError) on unknown users. Now returns false.
//  4. requireAdmin() trusted the payload without verifying the HMAC — any
//     forged `x.base64({"role":"admin"})` token was accepted — and it even
//     JSON.parsed the SIGNATURE segment, so legitimate tokens crashed with
//     500. Now: full HMAC verification (timing-safe), structure checks,
//     expiry check, 401/403 instead of 500.
//  5. Tokens never expired (iat only). Now: exp = iat + 1h, enforced.
const crypto = require('crypto');
const { getSecret } = require('./config');

const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

// Stored password format: "scrypt:<saltHex>:<hashHex>" (scrypt, 64-byte key).
function verifyPassword(stored, password) {
  if (typeof stored !== 'string' || typeof password !== 'string') return false;
  const parts = stored.split(':');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, saltHex, hashHex] = parts;
  let derived;
  try {
    derived = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64);
  } catch {
    return false;
  }
  const expected = Buffer.from(hashHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function authenticate(user, password) {
  if (!user || typeof password !== 'string') return false;
  return verifyPassword(user.password, password);
}

// Token format: base64(payload).base64url(hmac-sha256(payload, secret))
function signToken(user) {
  const payload = Buffer.from(JSON.stringify({
    sub: user.id,
    role: user.role,
    iat: Date.now(),
    exp: Date.now() + TOKEN_TTL_MS,
  })).toString('base64');
  const sig = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
  return payload + '.' + sig;
}

// Returns the payload object on success, null on ANY failure
// (missing/malformed/forged/expired/wrong-secret). Never throws.
function verifyToken(token) {
  try {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payloadB64, sig] = parts;
    if (!payloadB64 || !sig) return null;
    const expected = crypto.createHmac('sha256', getSecret()).update(payloadB64).digest('base64url');
    const given = Buffer.from(sig, 'base64url');
    const want = Buffer.from(expected, 'base64url');
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    if (!payload || typeof payload.sub !== 'string' || typeof payload.role !== 'string') return null;
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const payload = verifyToken(req.headers['x-token']);
  if (!payload) {
    return res.status(401).json({ error: 'invalid or expired token' });
  }
  if (payload.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  req.user = payload;
  next();
}

module.exports = { authenticate, verifyPassword, requireAdmin, signToken, verifyToken, TOKEN_TTL_MS };
