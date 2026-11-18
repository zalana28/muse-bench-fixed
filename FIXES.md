# FIXES — muse-bench-kit → muse-bench-fixed

README asli mengklaim "production-ready, fully tested, zero known issues".
Verifikasi dengan menjalankan membuktikan sebaliknya: aplikasi bahkan tidak
bisa start (syntax error), tidak ada satu pun test (`test/run.js` tidak ada),
dan ada 21 temuan berbeda di bawah ini. Setiap temuan: root cause (bukan
gejala), fix, dan test regression yang membuktikannya (`npm test`, 38 test).

## Temuan

| # | Temuan | Root cause | Fix | Test |
|---|---|---|---|---|
| 1 | **Syntax error** — app tidak bisa start sama sekali | `auth.js`: fungsi `authenticate()` tidak pernah ditutup (kurang `}`) → `SyntaxError: Unexpected end of input` saat `require('./auth')` | Tambah `}` penutup | 1 |
| 2 | **Login password asli DITOLAK** | `authenticate` membandingkan `stored.toUpperCase() === input` (input tidak di-uppercase). `'Admin123'.toUpperCase()` = `'ADMIN123'` ≠ `'Admin123'` → password benar gagal | Hapus case mangling; verifikasi hash scrypt eksak + `timingSafeEqual` | 2 |
| 3 | **Password all-caps DITERIMA** (sisi lain bug yang sama) | Perbandingan di atas menerima `'ADMIN123'` sebagai password kedua yang valid | Sama seperti #2 | 3 |
| 4 | **Login user tidak ada → crash 500** | `authenticate(undefined, ...)` mengakses `user.password` → `TypeError` | `authenticate` return `false` bila `!user` / password bukan string | 4 |
| 5 | **Password plaintext** di `store.js` | Kredensial disimpan apa adanya, tanpa hash | Hash scrypt bersalt per user (`scrypt:<salt>:<hash>`); tidak ada plaintext tersisa | 7 |
| 6 | **Admin auth bypass — token palsu diterima** | `requireAdmin` tidak pernah memverifikasi HMAC; ia `JSON.parse` segmen ke-2 token (tempat signature) sebagai payload. Token `x.base64({"role":"admin"})` → 200 | Verifikasi HMAC-SHA256 penuh (`timingSafeEqual`) atas segmen payload, di `verifyToken()` | 9 |
| 7 | **Token legit pun crash 500 di /admin/users** | Akar sama dengan #6: signature HMAC (bukan JSON) di-`JSON.parse` → `SyntaxError` → 500, bahkan untuk admin asli | Sama seperti #6 — payload di-parse, signature diverifikasi, bukan sebaliknya | 8 |
| 8 | **Token tanpa expiry** | Payload hanya punya `iat`, tidak pernah dicek | Tambah `exp` = iat + 1 jam; `verifyToken` menolak token kedaluwarsa | 11 |
| 9 | **Secret HMAC hard-coded** | `signToken` memakai `'dev-secret-123'` literal di `store.js` | `config.getSecret()`: secret HANYA dari `process.env.API_SECRET` (min 16 karakter); throw bila tidak di-set. Tidak ada default/fallback | 15 |
| 10 | **/health membocorkan secret** | Endpoint mengembalikan `process.env.API_SECRET \|\| 'dev-secret-123'` di respons | `/health` hanya `{ok, uptime}` | 16 |
| 11 | **/user/:id crash 500** | `user.profile.name` tanpa cek: user tidak ada → `TypeError` (`undefined.profile`); user bob (`profile: null`) → `TypeError` (`null.name`) | 404 bila user tidak ada; `name` null-safe | 17, 18 |
| 12 | **Login gagal → 200 {token:null}** | Handler login tidak membedakan sukses/gagal di status code | Gagal → `401 {error}`, field hilang → `400` | 5, 6 |
| 13 | **Path traversal di /reports/export** | `file` dari query langsung di-`path.join` tanpa validasi: `?file=../../server.js` mengembalikan source code | Resolve target di dalam `data/reports` dan tolak bila keluar direktori (`INVALID_PATH` → 403) | 19, 20 |
| 14 | **Error report ditelan → 200 body kosong** | Callback `exportReport` mengabaikan `err` dan selalu `res.send(data)` | Error dipetakan: `NOT_FOUND` → 404, `INVALID_PATH` → 403, lain → 500 JSON | 21 |
| 15 | **Search salah logika (char-set match)** | Loop memeriksa tiap KARAKTER query ada di nama item, bukan substring: `q=prd` cocok dengan semua 30.000 item; `q=produk 5` → 13.130 (seharusnya 1.111) | `item.nameLower.includes(q)` — substring match | 23, 24, 25 |
| 16 | **Search lambat: reload 30rb item per request** | `loadItems()` membaca + `JSON.parse` file katalog di SETIAP request, plus loop per-karakter | Katalog di-load sekali per proses (cache) + `nameLower` precomputed sekali | 26 |
| 17 | **Race condition di createOrder** | Read-modify-write `orders.json` tanpa lock: 30 order paralel → hanya 6 tersimpan (lost update); write bersamaan membuat file terpotong di tengah → read berikutnya throw | Promise-chain mutex (serialisasi) + tulis via temp file + atomic `rename` | 32 |
| 18 | **/orders tanpa validasi input** | `sku`/`amount` tidak dicek: `amount: -5` diterima dan tersimpan | Validasi di endpoint (400) dan di store (`VALIDATION`): sku string non-kosong, amount angka finite > 0 | 27–30 |
| 19 | **/orders error ditelan → request HANG selamanya** | `catch (e) {}` kosong: saat `createOrder` throw (mis. `orders.json` korup), tidak ada respons yang dikirim; client menunggu sampai timeout (terbukti: `curl` exit 28) | Catch mengembalikan `500 {error}`; central error handler JSON untuk semua error tak terduga | 33 |
| 20 | **Memory leak: requestLog tak terbatas** | Array menampung `{url, headers, body}` SEMUA request selamanya; README mengklaim "logs are rotated" — tidak ada rotasi | Ring buffer maks 100 entri, metadata saja (method/url/status/ms), tanpa headers/body | 34 |
| 21 | **DEBUG hard-coded ON** | `const DEBUG = true` + log "DEBUG MODE ON — stack traces enabled" | `DEBUG = process.env.DEBUG === 'true'` (opt-in) | 35, 36 |
| 22 | **Body limit 10 MB** (permukaan DoS) | `express.json({limit: '10mb'})` tanpa alasan | Turun ke `100kb`; error handler mengembalikan 413 | 38 |
| — | **Catatan smoke test**: field internal `nameLower` (precomputed untuk search) sempat bocor ke respons `/search` karena handler me-return objek item utuh. Diperbaiki dengan memproyeksikan hanya `{id, name, price}` | Field internal ikut ter-serialisasi ke JSON respons | Proyeksi field publik saja di handler `/search` | 26 |

## Yang juga diperbaiki (kualitas, bukan bug fungsional)

- `server.js` mengekspor `app` dan hanya `listen` saat dijalankan langsung
  (`require.main === module`), sehingga bisa di-test tanpa port tetap.
- Central error handler: error tak terduga → JSON 500 (bukan halaman HTML
  stack trace Express).
- `POST /orders` sukses → `201` (semula `200`).
- `data/items.json` (generated, deterministik) masuk `.gitignore`.
- README ditulis ulang secara jujur (tidak ada lagi klaim "zero known issues").

## Di luar scope (dicek, tidak diubah)

- `data/sales_messy.csv` (di repo asal, di luar folder aplikasi): tidak ada
  satu pun baris kode yang membacanya — file data untuk latihan lain, bukan
  bagian dari API ini. Dibiarkan apa adanya dan tidak ikut di repo ini.
- `createOrder` aman untuk SATU proses (mutex + atomic rename). Untuk
  multi-proses/multi-instance tetap butuh database atau distributed lock.

## BEFORE (bukti error asli, 2026-11-19 ~02:08–02:10 WIB)

```
$ node --check auth.js
auth.js:16  SyntaxError: Unexpected end of input   (exit 1)
$ npm test
Error: Cannot find module '.../test/run.js'  (MODULE_NOT_FOUND)
$ npm start  -> crash di require('./auth') (server.js:4)

$ GET /health        -> {"ok":true,"secret":"dev-secret-123","requests":1}
$ GET /user/u3       -> 500 TypeError: Cannot read properties of null (reading 'name')
$ GET /user/nope     -> 500 TypeError: Cannot read properties of undefined (reading 'profile')
$ POST /login {admin, Admin123}  -> 200 {"token":null}   (password asli DITOLAK)
$ POST /login {admin, ADMIN123}  -> 200 {"token":"eyJ..."} (all-caps DITERIMA)
$ POST /login {ghost, x}         -> 500 TypeError: Cannot read properties of undefined (reading 'password')
$ POST /login {admin, salah}     -> 200 {"token":null}   (bukan 401)
$ GET /admin/users  x-token: x.eyJyb2xlIjoiYWRtaW4ifQ== -> 200 + daftar semua user (FORGED)
$ GET /admin/users  (tanpa header)  -> 500 TypeError: Cannot read properties of undefined (reading 'split')
$ GET /admin/users  (token LEGIT admin) -> 500 (requireAdmin men-JSON.parse segmen signature)
$ GET /reports/export?file=../../server.js -> 200 + isi source server.js
$ GET /reports/export?file=tidak-ada.txt    -> 200 body kosong
$ GET /search?q=prd        -> {"count":30000,...}  (seharusnya 0)
$ GET /search?q=produk 5   -> {"count":13130,...}  (seharusnya 1111)
$ POST /orders {SKU-1, -5} -> 200 {"id":1,"sku":"SKU-1","amount":-5,...}
$ 30x POST /orders paralel -> hanya 6 order tersimpan (lastId 6), 24 request HANG
$ POST /orders (orders.json korup) -> curl exit 28 (timeout, tidak ada respons)
```

## AFTER (fresh, `npm test`, 2026-11-19 ~02:1x WIB)

```
38 passed, 0 failed
```

Termasuk: login password asli OK + all-caps ditolak; token palsu/wrong-secret/
kedaluwarsa → 401; admin legit → 200; `q=prd` → 0; `q=produk 5` → 1111;
30 order paralel → 30 id unik 1–30; `orders.json` korup → 500 JSON (tidak hang).
