// Regression suite for muse-bench-fixed.
// Plain Node, no extra dependencies. Run: npm test
// Each test names the finding it guards (see FIXES.md). Any failure exits 1.
process.env.API_SECRET = 'test-secret-min-16-chars';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORDERS_FILE = path.join(ROOT, 'data', 'orders.json');

const app = require(path.join(ROOT, 'server.js'));
const store = require(path.join(ROOT, 'store.js'));
const { getSecret } = require(path.join(ROOT, 'config.js'));

let server;
let BASE = '';
let passed = 0;
let failed = 0;
const failures = [];

function resetOrders() {
  fs.writeFileSync(ORDERS_FILE, JSON.stringify({ lastId: 0, orders: [] }));
}

function readOrders() {
  return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8'));
}

async function req(method, p, { body, headers = {} } = {}) {
  const res = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(5000), // a hang must FAIL the test, not stall it
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, text, json, contentType: res.headers.get('content-type') || '' };
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`PASS ${name}`);
  } catch (e) {
    failed++;
    failures.push(name);
    console.log(`FAIL ${name}\n     ${e.message}`);
  }
}

function signForged(payloadObj, secret) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return payload + '.' + sig;
}

async function main() {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  BASE = `http://127.0.0.1:${server.address().port}`;
  resetOrders();

  // --- 1. Syntax / boot (finding 1) ---
  await test('1. modules load without SyntaxError (auth.js brace fix)', async () => {
    assert.doesNotThrow(() => require(path.join(ROOT, 'auth.js')));
    assert.doesNotThrow(() => require(path.join(ROOT, 'store.js')));
    assert.doesNotThrow(() => require(path.join(ROOT, 'config.js')));
  });

  // --- 2/3. Login behaviour (findings 2, 3, 4) ---
  await test('2. login with the REAL password works (admin/Admin123)', async () => {
    const r = await req('POST', '/login', { body: { username: 'admin', password: 'Admin123' } });
    assert.strictEqual(r.status, 200);
    assert.ok(r.json && typeof r.json.token === 'string' && r.json.token.length > 20);
  });
  await test('3. login with the ALL-CAPS password is rejected (no case mangling)', async () => {
    const r = await req('POST', '/login', { body: { username: 'admin', password: 'ADMIN123' } });
    assert.strictEqual(r.status, 401);
  });
  await test('4. login with unknown user returns 401, not 500', async () => {
    const r = await req('POST', '/login', { body: { username: 'ghost', password: 'x' } });
    assert.strictEqual(r.status, 401);
  });
  await test('5. login with wrong password returns 401, not 200 {token:null}', async () => {
    const r = await req('POST', '/login', { body: { username: 'admin', password: 'salah' } });
    assert.strictEqual(r.status, 401);
    assert.ok(r.json && r.json.error);
  });
  await test('6. login with missing fields returns 400', async () => {
    const r = await req('POST', '/login', { body: { username: 'admin' } });
    assert.strictEqual(r.status, 400);
  });

  // --- 4. Password storage (finding 5) ---
  await test('7. passwords are stored as scrypt hashes, never plaintext', async () => {
    for (const u of ['admin', 'alice', 'bob']) {
      const user = store.findUserByUsername(u);
      assert.ok(user.password.startsWith('scrypt:'), `${u} password is not a scrypt hash`);
      assert.ok(!['Admin123', 'alicepw', 'bobpw'].includes(user.password));
    }
  });

  // --- 5/6. Admin tokens (findings 6, 7, 8, 9) ---
  const adminLogin = await req('POST', '/login', { body: { username: 'admin', password: 'Admin123' } });
  const adminToken = adminLogin.json.token;
  const aliceLogin = await req('POST', '/login', { body: { username: 'alice', password: 'alicepw' } });
  const aliceToken = aliceLogin.json.token;

  await test('8. legitimate admin token opens /admin/users (200)', async () => {
    const r = await req('GET', '/admin/users', { headers: { 'x-token': adminToken } });
    assert.strictEqual(r.status, 200);
    assert.ok(Array.isArray(r.json) && r.json.length === 3);
  });
  await test('9. forged token (payload in segment 2, no signature) is rejected 401', async () => {
    const forged = 'x.' + Buffer.from(JSON.stringify({ role: 'admin' })).toString('base64');
    const r = await req('GET', '/admin/users', { headers: { 'x-token': forged } });
    assert.strictEqual(r.status, 401);
  });
  await test('10. token signed with a WRONG secret is rejected 401', async () => {
    const bad = signForged({ sub: 'u1', role: 'admin', iat: Date.now(), exp: Date.now() + 3600000 }, 'wrong-secret-12345678');
    const r = await req('GET', '/admin/users', { headers: { 'x-token': bad } });
    assert.strictEqual(r.status, 401);
  });
  await test('11. expired token is rejected 401', async () => {
    const old = signForged({ sub: 'u1', role: 'admin', iat: Date.now() - 7200000, exp: Date.now() - 3600000 }, process.env.API_SECRET);
    const r = await req('GET', '/admin/users', { headers: { 'x-token': old } });
    assert.strictEqual(r.status, 401);
  });
  await test('12. missing token returns 401, not 500', async () => {
    const r = await req('GET', '/admin/users');
    assert.strictEqual(r.status, 401);
  });
  await test('13. malformed token returns 401, not 500', async () => {
    const r = await req('GET', '/admin/users', { headers: { 'x-token': 'garbage-no-dots' } });
    assert.strictEqual(r.status, 401);
  });
  await test('14. non-admin token returns 403 on /admin/users', async () => {
    const r = await req('GET', '/admin/users', { headers: { 'x-token': aliceToken } });
    assert.strictEqual(r.status, 403);
  });
  await test('15. getSecret() throws when API_SECRET is unset (no hard-coded fallback)', async () => {
    const saved = process.env.API_SECRET;
    delete process.env.API_SECRET;
    try {
      assert.throws(() => getSecret(), /API_SECRET/);
    } finally {
      process.env.API_SECRET = saved;
    }
  });

  // --- 7. /health (finding 10) ---
  await test('16. /health never leaks the secret', async () => {
    const r = await req('GET', '/health');
    assert.strictEqual(r.status, 200);
    assert.ok(!('secret' in (r.json || {})));
    assert.ok(!r.text.includes(process.env.API_SECRET));
    assert.ok(!r.text.includes('dev-secret-123'));
  });

  // --- 8. /user/:id (finding 11) ---
  await test('17. /user/u3 (null profile) returns 200 with name null, not 500', async () => {
    const r = await req('GET', '/user/u3');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.name, null);
  });
  await test('18. /user/nope returns 404, not 500', async () => {
    const r = await req('GET', '/user/nope');
    assert.strictEqual(r.status, 404);
  });

  // --- 9. Reports (findings 12, 13) ---
  await test('19. traversal ?file=../../server.js is rejected 403', async () => {
    const r = await req('GET', '/reports/export?file=../../server.js');
    assert.strictEqual(r.status, 403);
    assert.ok(!r.text.includes('express'));
  });
  await test('20. traversal ?file=../orders.json is rejected 403', async () => {
    const r = await req('GET', '/reports/export?file=../orders.json');
    assert.strictEqual(r.status, 403);
  });
  await test('21. missing report returns 404, not 200 empty', async () => {
    const r = await req('GET', '/reports/export?file=tidak-ada.txt');
    assert.strictEqual(r.status, 404);
    assert.ok(r.json && r.json.error);
  });
  await test('22. valid report monthly.txt returns 200 with content', async () => {
    const r = await req('GET', '/reports/export?file=monthly.txt');
    assert.strictEqual(r.status, 200);
    assert.ok(r.text.includes('Monthly report'));
  });

  // --- 10. Search logic + perf (findings 14, 15) ---
  await test('23. search q=prd returns 0 (substring, not char-set match)', async () => {
    const r = await req('GET', '/search?q=prd');
    assert.strictEqual(r.json.count, 0);
  });
  await test('24. search q=produk 5 returns 1111 (substring count)', async () => {
    const r = await req('GET', '/search?q=produk%205');
    assert.strictEqual(r.json.count, 1111);
  });
  await test('25. search q=kategori-3 returns 4286', async () => {
    const r = await req('GET', '/search?q=kategori-3');
    assert.strictEqual(r.json.count, 4286);
  });
  await test('26. search results do not leak the internal nameLower field', async () => {
    const r = await req('GET', '/search?q=produk%205');
    assert.ok(r.json.results.length > 0);
    for (const item of r.json.results) {
      assert.ok(!('nameLower' in item), 'internal field leaked: ' + JSON.stringify(item));
      assert.deepStrictEqual(Object.keys(item).sort(), ['id', 'name', 'price']);
    }
  });
  await test('27. loadItems() is cached (same reference, no re-read per request)', async () => {
    assert.strictEqual(store.loadItems(), store.loadItems());
    assert.strictEqual(store.loadItems().length, 30000);
  });

  // --- 11. Orders: validation (finding 18) ---
  await test('28. POST /orders amount -5 returns 400', async () => {
    const r = await req('POST', '/orders', { body: { sku: 'SKU-1', amount: -5 } });
    assert.strictEqual(r.status, 400);
  });
  await test('29. POST /orders amount "abc" returns 400', async () => {
    const r = await req('POST', '/orders', { body: { sku: 'SKU-1', amount: 'abc' } });
    assert.strictEqual(r.status, 400);
  });
  await test('30. POST /orders missing sku returns 400', async () => {
    const r = await req('POST', '/orders', { body: { amount: 1 } });
    assert.strictEqual(r.status, 400);
  });
  await test('31. POST /orders amount 0 returns 400', async () => {
    const r = await req('POST', '/orders', { body: { sku: 'SKU-1', amount: 0 } });
    assert.strictEqual(r.status, 400);
  });

  // --- 12. Orders: happy path + race (finding 17) ---
  await test('32. POST /orders valid returns 201 with an order', async () => {
    resetOrders();
    const r = await req('POST', '/orders', { body: { sku: 'SKU-1', amount: 2 } });
    assert.strictEqual(r.status, 201);
    assert.strictEqual(r.json.id, 1);
    assert.strictEqual(r.json.sku, 'SKU-1');
    assert.strictEqual(r.json.amount, 2);
  });
  await test('33. 30 parallel POST /orders keep all 30 with unique sequential ids (no lost updates)', async () => {
    resetOrders();
    const results = await Promise.all(Array.from({ length: 30 }, (_, i) =>
      req('POST', '/orders', { body: { sku: 'SKU-R' + i, amount: 1 } })));
    assert.ok(results.every((r) => r.status === 201), 'some order failed');
    const ids = results.map((r) => r.json.id);
    assert.strictEqual(new Set(ids).size, 30, 'duplicate ids: ' + JSON.stringify(ids));
    assert.deepStrictEqual([...ids].sort((a, b) => a - b), Array.from({ length: 30 }, (_, i) => i + 1));
    const saved = readOrders();
    assert.strictEqual(saved.orders.length, 30);
    assert.strictEqual(saved.lastId, 30);
  });

  // --- 13. Orders: swallowed error (finding 16) ---
  await test('34. corrupted orders.json returns 500 JSON (never hangs)', async () => {
    fs.writeFileSync(ORDERS_FILE, 'BUKAN JSON{{{');
    try {
      const r = await req('POST', '/orders', { body: { sku: 'SKU-1', amount: 1 } });
      assert.strictEqual(r.status, 500);
      assert.ok(r.json && r.json.error, 'expected JSON error body');
      assert.ok(!r.text.includes('<pre>'), 'must not leak a stack trace page');
    } finally {
      resetOrders();
    }
  });

  // --- 14. Request log bound (finding 19) ---
  await test('35. request log is bounded (<=100) and holds metadata only', async () => {
    for (let i = 0; i < 150; i++) {
      await fetch(BASE + '/health', { signal: AbortSignal.timeout(5000) });
    }
    assert.ok(app.requestLog.length <= 100, 'log length ' + app.requestLog.length);
    assert.ok(app.requestLog.length > 0);
    for (const entry of app.requestLog) {
      assert.ok(!('headers' in entry) && !('body' in entry), 'log entry keeps headers/body');
      assert.ok('method' in entry && 'url' in entry && 'status' in entry);
    }
  });

  // --- 15. DEBUG flag + body limit (findings 20, 21) ---
  await test('36. DEBUG is env-driven: unset -> no DEBUG MODE line on boot', async () => {
    const out = await bootAndCapture({ DEBUG: undefined, PORT: '18081' });
    assert.ok(out.includes('listening on port 18081'), 'server did not boot: ' + out);
    assert.ok(!out.includes('DEBUG MODE ON'), 'DEBUG line printed without DEBUG=true');
  });
  await test('37. DEBUG=true -> DEBUG MODE line appears on boot', async () => {
    const out = await bootAndCapture({ DEBUG: 'true', PORT: '18082' });
    assert.ok(out.includes('DEBUG MODE ON'), 'DEBUG line missing with DEBUG=true');
  });
  await test('38. JSON body over 100kb returns 413', async () => {
    const big = 'x'.repeat(150 * 1024);
    const res = await fetch(BASE + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: big, password: 'x' }),
      signal: AbortSignal.timeout(5000),
    });
    assert.strictEqual(res.status, 413);
  });

  // --- summary ---
  server.close();
  resetOrders();
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('Failed: ' + failures.join(', '));
    process.exitCode = 1;
  }
}

function bootAndCapture(extraEnv) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    for (const [k, v] of Object.entries(extraEnv)) {
      if (v === undefined) delete env[k];
      else env[k] = v;
    }
    const child = spawn('node', ['server.js'], { cwd: ROOT, env });
    let out = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('boot timeout, output so far: ' + out));
    }, 8000);
    child.stdout.on('data', (d) => {
      out += d.toString();
      if (out.includes('listening on port')) {
        clearTimeout(timer);
        child.kill();
        resolve(out);
      }
    });
    child.stderr.on('data', (d) => { out += d.toString(); });
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

main().catch((e) => {
  console.error('SUITE CRASH:', e);
  try { server && server.close(); } catch { /* ignore */ }
  try { resetOrders(); } catch { /* ignore */ }
  process.exitCode = 1;
});
