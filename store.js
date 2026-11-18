// storage layer — JSON file persistence
// Fixes vs the original:
//  1. Passwords were plaintext. Now scrypt hashes (salted, per user).
//     No plaintext password exists anywhere in this file.
//  2. loadItems() re-read + re-parsed a 30k-item JSON file on EVERY search
//     request. Now the catalog is loaded once and cached in memory, with
//     a precomputed lowercase name per item for the search.
//  3. exportReport() joined raw user input into a path (traversal:
//     ?file=../../server.js returned source). Now the target is resolved
//     inside data/reports and rejected when it escapes that directory.
//  4. createOrder() was a bare read-modify-write: 30 parallel orders kept
//     only 6 (lost updates) and torn concurrent writes made later reads
//     throw. Now writes are serialized with an in-process promise mutex
//     AND persisted via write-temp + atomic rename, so a reader never
//     sees a half-written file. (Multi-process safety would need a real
//     DB/lock — documented in README, out of scope for this file store.)
//  5. createOrder() accepted any amount (incl. negative). Now validated.
const fs = require('fs');
const path = require('path');

const USERS = [
  { id: 'u1', username: 'admin', password: 'scrypt:f802204e9279fe743881e3b1330a972d:7a4064aec7cafc412cf1f63ded8441759b8514abcedf4621325196b59ed30ba53428cd49246e29d4777eb5254160cdad1a9eaea36956a1768172732a19e6bcac', role: 'admin', profile: { name: 'Admin Utama', email: 'admin@local.test' } },
  { id: 'u2', username: 'alice', password: 'scrypt:23c75641036a11df2a0534be465a4944:bdebcc8d687055e3bc84e310288b18b98a13bfa8c63f463a73a455d5b2db3b04372976f60cdcbcdd3527e61a2e94c62b8ef6fb54d69184460a59d99b4d78aa49', role: 'user', profile: { name: 'Alice', email: 'alice@local.test' } },
  { id: 'u3', username: 'bob', password: 'scrypt:81581efe749350aceef50d22777d05f1:54a767f30272ce0f9f4694ef1305cf0ca6f00b639bbe07f9bdd89c2b586f6562fee2d40a932ea0af2ef10507e1a16fed6a97a1d8506677b03a30d931cb18bc74', role: 'user', profile: null },
];

function findUser(id) {
  return USERS.find(u => u.id === id || u.username === id);
}

function findUserByUsername(username) {
  return USERS.find(u => u.username === username);
}

function allUsers() {
  return USERS.map(u => ({ id: u.id, username: u.username, role: u.role, profile: u.profile }));
}

// build item catalog for search (deterministic)
function ensureItems() {
  const file = path.join(__dirname, 'data', 'items.json');
  if (!fs.existsSync(file)) {
    const items = [];
    for (let i = 0; i < 30000; i++) {
      items.push({ id: 'p' + i, name: 'Produk ' + i + ' kategori-' + (i % 7), price: 1000 + (i % 90) * 500 });
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(items));
  }
  return file;
}

// Cached catalog: loaded + parsed exactly once per process, lowercase
// names precomputed once. loadItems() returns the same array reference
// on every call — the search endpoint no longer touches disk per request.
let itemsCache = null;
function loadItems() {
  if (!itemsCache) {
    const file = ensureItems();
    itemsCache = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const item of itemsCache) {
      item.nameLower = item.name.toLowerCase();
    }
  }
  return itemsCache;
}

const REPORTS_DIR = path.join(__dirname, 'data', 'reports');

// Reads a report file. cb(err, data); err.code is 'INVALID_PATH' when the
// name escapes the reports directory, 'NOT_FOUND' when the file is missing.
function exportReport(file, cb) {
  if (typeof file !== 'string' || file.length === 0) {
    const err = new Error('file parameter is required');
    err.code = 'INVALID_PATH';
    cb(err, null);
    return;
  }
  const target = path.resolve(REPORTS_DIR, file);
  if (target !== REPORTS_DIR && !target.startsWith(REPORTS_DIR + path.sep)) {
    const err = new Error('path escapes reports directory');
    err.code = 'INVALID_PATH';
    cb(err, null);
    return;
  }
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) {
      if (err.code === 'ENOENT' || err.code === 'ENOTDIR') {
        const notFound = new Error('report not found');
        notFound.code = 'NOT_FOUND';
        cb(notFound, null);
        return;
      }
      cb(err, null);
      return;
    }
    cb(null, data);
  });
}

const ORDERS_FILE = path.join(__dirname, 'data', 'orders.json');

function validateOrderInput(sku, amount) {
  if (typeof sku !== 'string' || sku.trim().length === 0) {
    const err = new Error('sku is required and must be a non-empty string');
    err.code = 'VALIDATION';
    throw err;
  }
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
    const err = new Error('amount must be a positive number');
    err.code = 'VALIDATION';
    throw err;
  }
}

async function writeOrdersAtomically(current) {
  const tmp = ORDERS_FILE + '.tmp-' + process.pid;
  await fs.promises.writeFile(tmp, JSON.stringify(current));
  await fs.promises.rename(tmp, ORDERS_FILE);
}

async function doCreateOrder(sku, amount) {
  const current = JSON.parse(await fs.promises.readFile(ORDERS_FILE, 'utf8'));
  current.lastId = (current.lastId || 0) + 1;
  const order = { id: current.lastId, sku, amount, ts: Date.now() };
  current.orders.push(order);
  await writeOrdersAtomically(current);
  return order;
}

// Promise-chain mutex: concurrent createOrder calls run one after another,
// so no two calls can read the same lastId or interleave their writes.
let orderQueue = Promise.resolve();
function createOrder(sku, amount) {
  validateOrderInput(sku, amount);
  const run = orderQueue.then(() => doCreateOrder(sku, amount));
  // Keep the chain alive after a failure so one bad order cannot wedge
  // all later orders.
  orderQueue = run.catch(() => {});
  return run;
}

if (!fs.existsSync(ORDERS_FILE)) {
  fs.mkdirSync(path.dirname(ORDERS_FILE), { recursive: true });
  fs.writeFileSync(ORDERS_FILE, JSON.stringify({ lastId: 0, orders: [] }));
}

module.exports = { findUser, findUserByUsername, allUsers, loadItems, exportReport, createOrder };
