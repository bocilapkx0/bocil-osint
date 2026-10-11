# BOCIL OSINT — Intelligence Console

Dashboard OSINT ringan untuk memeriksa informasi publik dan menganalisis file secara lokal. Dibangun dengan React, TypeScript, dan Vite. Tidak ada login admin/user atau database cloud wajib. Modul Censys opsional membutuhkan Personal Access Token yang disimpan hanya pada backend Vercel sebagai Secret.

## Fitur

- **Domain Recon:** record DNS A, AAAA, MX, NS, TXT, CAA melalui Google Public DNS-over-HTTPS serta metadata domain melalui RDAP.
- **IP Intelligence:** konteks IPv4 publik, ASN, penyedia jaringan, negara, kota, dan zona waktu perkiraan melalui ipwho.is.
- **Censys Asset Intel:** lookup host berdasarkan IP, web property berdasarkan `hostname:port`, serta sertifikat berdasarkan fingerprint SHA-256 melalui Censys Platform API v3; token hanya dibaca server-side dari `CENSYS_API_TOKEN`.
- **URL Inspector:** analisis struktur URL di browser, termasuk protokol, simbol `@`, hostname berbentuk IP, punycode, pemendek URL, dan pola tertentu. URL tujuan tidak di-fetch.
- **Email Domain Check:** pemeriksaan sintaks dasar dan record MX publik. Tidak menguji apakah mailbox benar-benar ada.
- **Metadata Inspector:** membaca metadata yang tersedia dari berkas gambar melalui Exifr di perangkat pengguna.
- **File Hash Lab:** menghitung SHA-256 di browser dengan Web Crypto API.
- **Saved Findings:** menyimpan temuan secara lokal menggunakan `localStorage`; mendukung ekspor JSON.
- Responsive UI, mode gelap cinematic dengan satu aksen hijau, tanpa autentikasi.

## Menjalankan secara lokal

Persyaratan: Node.js 20 LTS atau lebih baru dan npm.

```bash
npm install
npm run dev
```

Buka URL lokal yang ditampilkan Vite, umumnya `http://localhost:5173`. Endpoint serverless Censys tidak berjalan pada Vite dev server biasa. Untuk menguji fungsi Censys secara lokal, gunakan `npx vercel dev` setelah menyiapkan `.env.local` seperti dijelaskan di `DEPLOY_GUIDE_ID.md`.

Tes build produksi:

```bash
npm run build
npm run preview
```

## Deploy

Baca [DEPLOY_GUIDE_ID.md](./DEPLOY_GUIDE_ID.md) untuk panduan lengkap mengunggah proyek ke GitHub dan GitLab, lalu men-deploy-nya ke Vercel.

## Sumber data dan ketergantungan

- DNS: `https://dns.google/resolve` (Google Public DNS JSON API)
- Domain registration: `https://rdap.org/` (RDAP redirect/bootstrap service)
- IP context: `https://ipwho.is/` (third-party public API)
- Censys asset records: Platform API v3 untuk host, web property, dan sertifikat
- File metadata: Exifr berjalan di browser.

API publik pihak ketiga dapat berubah, membatasi permintaan, atau mengalami gangguan. BOCIL OSINT bukan layanan reputasi/security verdict; hasil kosong tidak otomatis berarti aman atau tidak terdaftar.

## Batasan keamanan dan privasi

- Aplikasi tidak mempunyai login, database cloud, atau mekanisme sinkronisasi.
- `localStorage` tidak terenkripsi dan hanya ada pada browser/perangkat tempat data disimpan. Jangan gunakan pada komputer umum untuk temuan sensitif.
- Jangan memasukkan kata sandi, token sesi, private key, atau kredensial ke kolom pencarian.
- Jangan pernah memakai `VITE_CENSYS_API_TOKEN` atau mengirim token ke React/browser. Gunakan `CENSYS_API_TOKEN` hanya sebagai Secret server-side. Bila token pernah ditempel di chat, commit, screenshot, atau repository, segera cabut dan buat token baru.
- Metadata foto mungkin menyimpan koordinat GPS atau informasi pribadi.
- Geolokasi IP hanyalah perkiraan dan biasanya mencerminkan jaringan/ISP, bukan lokasi akurat seseorang.
- Endpoint Censys tanpa login dapat dipanggil siapa pun yang mengakses website publik. Rate limit ringan di fungsi server bersifat best-effort; cache CDN membantu mengurangi pemakaian kredit tetapi bukan perlindungan penyalahgunaan yang kuat. Jangan buka ke publik sebelum menguji kuota dan mempertimbangkan CAPTCHA/rate limit persisten.
- Gunakan untuk informasi publik dan aset yang kamu miliki atau berwenang kamu periksa. Tidak ada port scanning, eksploitasi, credential attack, atau akses ke akun orang lain.

## Lisensi

MIT — lihat file `LICENSE`.
