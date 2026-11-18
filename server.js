// bench-api — Task Order API (fixed)
// Fixes vs the original (details + regression tests in FIXES.md / test/run.js):
//  1. /health leaked the HMAC secret. It now returns only {ok, uptime}.
//  2. requestLog grew without bound and kept full headers+bodies of every
//     request (memory leak + sensitive data retention). Now a ring buffer
//     of max 100 entries holding metadata only (method/url/status/ms).
//  3. /user/:id crashed with 500 on unknown users and on null profiles.
//     Now 404 for unknown users, null-safe name.
//  4. /login returned 200 {token:null} on failure. Now 401; missing fields 400.
//  5. /reports/export swallowed read errors (missing file -> 200 empty) and
//     allowed path traversal. Now 403/404/500 with a JSON error body.
//  6. /search matched when EVERY CHARACTER of the query appeared somewhere
//     in the name (q=prd matched all 30k items). Now true substring match.
//  7. /orders swallowed errors with an empty catch -> the request hung
//     forever on any store failure. Now errors return 500 JSON.
//  8. /orders accepted any body (negative amount, missing sku). Now 400.
//  9. DEBUG was hard-coded on. Now opt-in via DEBUG=true.
// 10. JSON body limit was 10mb. Now 100kb.
// 11. The app only ran via `node server.js` (no exports). Now exports the
//     app for tests and listens only when run directly.
const express = require('express');
const { authenticate, requireAdmin, signToken } = require('./auth');
const store = require('./store');
const app = express();
app.use(express.json({ limit: '100kb' }));

const DEBUG = process.env.DEBUG === 'true';
const MAX_LOG_ENTRIES = 100;
const requestLog = []; // ring buffer: metadata only, never headers/bodies
let requestCount = 0;
app.requestLog = requestLog;

app.use((req, res, next) => {
  const started = Date.now();
  requestCount++;
  res.on('finish', () => {
    requestLog.push({ method: req.method, url: req.url, status: res.statusCode, ms: Date.now() - started, ts: Date.now() });
    if (requestLog.length > MAX_LOG_ENTRIES) requestLog.splice(0, requestLog.length - MAX_LOG_ENTRIES);
  });
  next();
});

app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: Math.floor(process.uptime()) });
});

app.get('/user/:id', (req, res) => {
  const user = store.findUser(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'user not found' });
  }
  res.json({ name: user.profile ? user.profile.name : null, role: user.role });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password are required' });
  }
  const user = store.findUserByUsername(username);
  if (authenticate(user, password)) {
    res.json({ token: signToken(user) });
  } else {
    res.status(401).json({ error: 'invalid credentials' });
  }
});

app.get('/admin/users', requireAdmin, (req, res) => {
  res.json(store.allUsers());
});

app.get('/reports/export', (req, res) => {
  const file = req.query.file;
  if (typeof file !== 'string' || file.length === 0) {
    return res.status(400).json({ error: 'file query parameter is required' });
  }
  store.exportReport(file, (err, data) => {
    if (err) {
      if (err.code === 'INVALID_PATH') return res.status(403).json({ error: 'invalid file path' });
      if (err.code === 'NOT_FOUND') return res.status(404).json({ error: 'report not found' });
      if (DEBUG) console.error(err);
      return res.status(500).json({ error: 'failed to read report' });
    }
    res.type('text/plain').send(data);
  });
});

app.get('/search', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const items = store.loadItems();
  const results = [];
  for (const item of items) {
    // nameLower is an internal precomputed field — never leak it in the API.
    if (item.nameLower.includes(q)) results.push({ id: item.id, name: item.name, price: item.price });
  }
  res.json({ count: results.length, results: results.slice(0, 20) });
});

app.post('/orders', async (req, res) => {
  const { sku, amount } = req.body || {};
  if (typeof sku !== 'string' || sku.trim().length === 0) {
    return res.status(400).json({ error: 'sku is required' });
  }
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: 'amount must be a positive number' });
  }
  try {
    const order = await store.createOrder(sku, amount);
    res.status(201).json(order);
  } catch (e) {
    if (e.code === 'VALIDATION') {
      return res.status(400).json({ error: e.message });
    }
    if (DEBUG) console.error(e);
    res.status(500).json({ error: 'failed to create order' });
  }
});

// Central error handler: a handler bug returns JSON 500 instead of the
// default Express HTML stack-trace page (and never hangs the request).
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'request body too large' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid JSON body' });
  }
  if (DEBUG) console.error(err);
  res.status(500).json({ error: 'internal server error' });
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    if (DEBUG) console.log('DEBUG MODE ON — stack traces enabled');
    console.log(`bench-api listening on port ${PORT}`);
  });
}

module.exports = app;
