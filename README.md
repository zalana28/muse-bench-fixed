# bench-api — Task Order API (fixed)

REST API hasil perbaikan dari `muse-bench-kit` (yang README-nya mengklaim
"production-ready, fully tested, zero known issues" — klaim itu salah;
buktinya ada di `FIXES.md`, termasuk output BEFORE/AFTER).

## Run

```
npm install
cp .env.example .env   # isi API_SECRET dengan string acak (min 16 karakter)
npm start              # listen di :3000 (atau $PORT)
npm test               # regression suite, test/run.js
```

`API_SECRET` wajib di-set — server menolak start dan menolak
sign/verify token tanpa secret dari environment. Tidak ada lagi secret
hard-coded di kode.

## Endpoints

- `GET /health` → `{ok: true, uptime: <detik>}`
- `POST /login {username, password}` → `200 {token}` atau `401 {error}`
- `GET /user/:id` → `200 {name, role}` atau `404 {error}`
- `GET /admin/users` (header: `x-token`) → `200` daftar user, `401` token
  tidak valid/kedaluwarsa, `403` bukan admin
- `GET /reports/export?file=monthly.txt` → isi file, atau `400`/`403`/`404`
- `GET /search?q=produk` → `{count, results}` (substring match, maks 20)
- `POST /orders {sku, amount}` → `201` order, `400` input tidak valid,
  `500` bila penyimpanan gagal

Demo accounts (password di-hash scrypt, lihat `store.js`):

- `admin` / `Admin123` (role admin)
- `alice` / `alicepw` (role user)
- `bob` / `bobpw` (role user)

## Notes

- Token: `base64(payload).base64url(HMAC-SHA256(payload, API_SECRET))`,
  payload `{sub, role, iat, exp}` dengan `exp` = 1 jam. Signature
  diverifikasi dengan `timingSafeEqual` di `requireAdmin`.
- Search memakai katalog yang di-cache di memori (load sekali per proses),
  bukan baca + parse file 30 ribu item per request.
- Order creation diserialisasi dengan promise mutex dan ditulis via
  write-temp + atomic rename. Ini aman untuk SATU proses; untuk
  multi-proses/multi-instance tetap butuh database atau distributed lock.
- `data/items.json` di-generate otomatis saat pertama dipakai (deterministik,
  30.000 item) dan masuk `.gitignore`.
- `data/orders.json` adalah file state runtime (awal: kosong).
