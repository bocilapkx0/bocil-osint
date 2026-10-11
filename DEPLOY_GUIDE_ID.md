# Panduan deploy BOCIL OSINT (GitHub + GitLab + Vercel)

Panduan ini untuk pemula dan bisa diikuti dari terminal Linux/Ubuntu. Semua langkah bisa dimulai dengan paket gratis. Perhatikan bahwa **Vercel Hobby ditujukan untuk penggunaan personal/nonkomersial**; jika BOCIL OSINT kelak dipakai untuk bisnis/layanan komersial, periksa kembali ketentuan dan paket yang sesuai.

## 1. Unduh dan ekstrak proyek

Ekstrak `bocil-osint.zip` ke folder yang mudah ditemukan. Contoh setelah diekstrak:

```bash
cd ~/Downloads/bocil-osint
```

Pastikan perintah ini menunjukkan isi proyek:

```bash
ls
```

Kamu seharusnya melihat `package.json`, `src`, `index.html`, `README.md`, dan `vercel.json`.

## 2. Jalankan di laptop terlebih dahulu

Persyaratan: Node.js 20 LTS atau lebih baru, npm, dan Git. Periksa:

```bash
node -v
npm -v
git --version
```

Kemudian pasang dependensi dan jalankan:

```bash
npm install
npm run dev
```

Vite akan menampilkan alamat lokal, biasanya `http://localhost:5173`. Buka alamat tersebut di Firefox. Hentikan server lokal dengan `Ctrl + C`.

Sebelum publish, tes build produksi:

```bash
npm run build
```

Jika berhasil, hasilnya masuk ke folder `dist/`. Kalau `npm install` gagal, cek koneksi internet dan versi Node.js, lalu ulangi perintahnya.

## 3. Siapkan Git secara lokal

Jalankan dari dalam folder proyek:

```bash
git init -b main
git add .
git commit -m "Initial commit - BOCIL OSINT"
```

Jika Git meminta nama dan email, atur identitas commit lokal (gunakan alamat email yang memang ingin kamu tampilkan pada riwayat Git):

```bash
git config --global user.name "Nama Kamu"
git config --global user.email "email-kamu@example.com"
```

Lalu ulangi `git commit`.

> Jangan pernah memasukkan token pribadi, file `.env`, password, API key privat, atau kredensial ke repository. File `.gitignore` pada proyek sudah mengecualikan `.env` dan folder hasil build.

## 4. Push ke GitHub (gratis)

1. Buka [github.com/new](https://github.com/new) dan login/daftar.
2. Buat repository bernama `bocil-osint`.
3. Pilih **Public** atau **Private** sesuai kebutuhanmu. Hindari menambahkan README, license, atau `.gitignore` baru di halaman GitHub karena berkas tersebut sudah ada secara lokal.
4. Salin URL repository yang tampil, kemudian di terminal jalankan (ganti `USERNAME` sesuai akunmu):

```bash
git remote add github https://github.com/USERNAME/bocil-osint.git
git push -u github main
```

GitHub mungkin meminta autentikasi melalui browser atau token/credential manager. Jangan menaruh token sebagai teks biasa di URL atau file proyek. Ikuti metode autentikasi resmi GitHub yang muncul pada perangkatmu.

Untuk memastikan remote sudah benar:

```bash
git remote -v
```

## 5. Push repository yang sama ke GitLab (gratis)

Kamu bisa menyimpan salinan repository yang sama di GitLab tanpa menyalin file secara manual.

1. Buka [gitlab.com/projects/new](https://gitlab.com/projects/new) dan login/daftar.
2. Buat project kosong bernama `bocil-osint`. Jangan buat README dari GitLab karena commit awal sudah ada di laptop.
3. Salin URL HTTPS project. Kemudian jalankan di folder proyek:

```bash
git remote add gitlab https://gitlab.com/USERNAME/bocil-osint.git
git push -u gitlab main
```

Ganti `USERNAME` dengan nama akun atau namespace GitLab kamu. Jika diminta autentikasi, ikuti metode GitLab. Pada beberapa konfigurasi, GitLab memerlukan personal access token sebagai password HTTPS; buat token dengan izin sesedikit mungkin dan jangan bagikan token tersebut.

Sekarang satu folder lokal mempunyai dua remote. Periksa:

```bash
git remote -v
```

Untuk mengirim pembaruan berikutnya ke kedua platform setelah mengubah kode:

```bash
git add .
git commit -m "Update BOCIL OSINT"
git push github main
git push gitlab main
```

Kamu bisa memilih hanya satu penyedia repository untuk Vercel. Menyimpan salinan di dua platform bukan syarat deploy.

## 6. Hosting gratis di Vercel dari GitHub

1. Buka [vercel.com](https://vercel.com/) lalu daftar/login. Kamu dapat menghubungkan akun GitHub.
2. Dari dashboard Vercel, pilih **Add New → Project**.
3. Pilih repository `bocil-osint` dari GitHub, lalu pilih **Import**.
4. Pastikan pengaturan build berikut terdeteksi atau isi manual:
   - Framework Preset: **Vite**
   - Build Command: `npm run build`
   - Output Directory: `dist`
   - Install Command: `npm install` (default boleh dipakai)
   - Root Directory: `./` atau kosong (root repository)
5. Tambahkan `CENSYS_API_TOKEN` sebagai **Secret** hanya di Vercel, sesuai bagian 6A. Jangan memasukkan token ke React, `.env.example`, commit Git, atau `vercel.json`. Modul Censys akan memberi pesan konfigurasi jika Secret belum ada.
6. Tekan **Deploy**. Jika build sukses, Vercel akan memberi URL berakhiran `.vercel.app`.

Setelah terhubung, push ke branch produksi (biasanya `main`) memicu deployment baru secara otomatis.

## 6A. Menambahkan Censys API secara aman

**Penting:** token Censys yang pernah ditempel di chat atau lokasi yang tidak privat harus dianggap terekspos. Buka [Censys Platform](https://accounts.censys.io/) → menu akun → **API Access / Personal Access Tokens**, hapus/revoke token tersebut, lalu buat Personal Access Token baru. Jangan kirim token baru ke chat, issue, screenshot, atau GitHub/GitLab.

Censys Platform API v3 memakai autentikasi `Authorization: Bearer ...`. Starter ini menambahkan tiga lookup aset: host berdasarkan IP, web property berdasarkan `hostname:port`, dan sertifikat berdasarkan fingerprint SHA-256. Pada paket Free, dokumentasi Censys menyatakan akses API terbatas antara lain ke lookup host, web property, dan sertifikat; akses search yang lebih luas bergantung pada tier/izin. Lihat [dokumentasi resmi API](https://docs.censys.com/reference/get-started) dan [endpoint host](https://docs.censys.com/reference/v3-globaldata-asset-host), [web property](https://docs.censys.com/reference/v3-globaldata-asset-webproperty), dan [sertifikat](https://docs.censys.com/reference/v3-globaldata-asset-certificate).

### Di Vercel (disarankan untuk deployment)

1. Buka proyek BOCIL OSINT di Vercel.
2. Masuk ke **Settings → Environment Variables**.
3. Tambahkan nama: `CENSYS_API_TOKEN`.
4. Tempel token baru hanya di kolom value. Pilih tipe **Secret** (bukan Config), dan aktifkan untuk **Production**. Aktifkan Preview hanya jika memang ingin menguji preview deployment.
5. Simpan lalu lakukan **Redeploy**. Environment variable baru tidak mengubah deployment lama sampai redeploy.

Jangan awali nama variabel dengan `VITE_`: variabel berawalan itu dapat dimasukkan ke bundle browser Vite. Fungsi backend membaca `process.env.CENSYS_API_TOKEN`; browser hanya memanggil `/api/censys-lookup?type=...&query=...` dan tidak menerima tokennya.

### Di laptop untuk pengujian lokal

Jalankan dari root folder proyek:

```bash
cp .env.example .env.local
nano .env.local
```

Masukkan token baru hanya di `.env.local`:

```dotenv
CENSYS_API_TOKEN=TOKEN_BARU_MU
```

Simpan. File `.env.local` sudah dicakup `.gitignore`, jadi jangan pakai `git add -f .env.local`. Untuk menjalankan fungsi API lokal gunakan Vercel CLI:

```bash
npx vercel dev
```

Ikuti instruksi link project bila diminta. Buka URL localhost yang diberikan Vercel CLI. `npm run dev` biasa hanya menjalankan Vite dan tidak menyediakan fungsi `/api`.

### Batas pengamanan untuk website tanpa login

- Token tetap berada di server, tetapi siapa pun dapat memanggil endpoint publik pada website tanpa login. Fungsi ini punya validasi IP publik, timeout, CDN cache, pemeriksaan Origin, dan rate limit per instance sebagai pertahanan dasar.
- Rate limit in-memory pada serverless **bukan** rate limit global yang kuat; pengguna yang berniat menyalahgunakan bisa berpindah IP atau mengenai instance berbeda. Untuk situs publik serius, tambahkan proteksi abuse persisten atau CAPTCHA sebelum memberi akses luas. Pantau kredit dan batas API Censys.
- Gunakan repository private bila tak ingin orang lain membaca source. Private repo tidak boleh dijadikan tempat menyimpan API key juga.

### Kalau token pernah ter-commit ke Git

1. Cabut token dan buat token baru terlebih dahulu; menghapus token dari commit terbaru saja tidak menghapusnya dari Git history.
2. Hapus token dari kode/riwayat yang terlihat dan pastikan `.env.local` tidak dilacak (`git status --short`).
3. Jangan gunakan kembali token lama. Jika repository publik, tinjau commit dan fork/clone yang mungkin sudah menyalinnya.

## 7. Alternatif: hosting Vercel langsung dari GitLab

Vercel mendukung GitLab Free. Ini alternatif jika kamu ingin menjadikan GitLab sumber deploy utama.

1. Di Vercel pilih **Add New → Project** dan hubungkan akun GitLab jika diminta.
2. Pilih project `bocil-osint` dari GitLab, kemudian pilih **Import**.
3. Gunakan pengaturan yang sama: preset Vite, build command `npm run build`, output directory `dist`, root directory `./`, serta atur `CENSYS_API_TOKEN` sebagai Secret di Vercel bila modul Censys ingin diaktifkan (lihat bagian 6A).
4. Tekan **Deploy** dan tunggu sampai build selesai.

Jangan menghubungkan dua repository sekaligus ke project Vercel yang sama. Pilih GitHub **atau** GitLab sebagai sumber deployment utama untuk menghindari bingung menentukan sumber versi terbaru.

## 8. Jika deploy gagal

**Build gagal / package tidak ditemukan**
- Buka tab Deployments di Vercel dan klik deployment yang gagal untuk membaca Build Logs.
- Pastikan `package.json` ada di root repository dan repository sudah berisi semua isi folder proyek.
- Jalankan `npm install` lalu `npm run build` di laptop; perbaiki error lokal sebelum push lagi.

**Vercel deploy dari private repository gagal**
- Untuk akun Hobby, repository private milik personal account umumnya bisa digunakan selama koneksi akun dan izin benar. Private repo yang dimiliki organisasi/Group dapat terkena batasan tambahan pada Hobby. Untuk percobaan awal, gunakan repository personal dan pastikan akun yang menghubungkan sumber Git adalah pemilik yang benar.
- Jangan membuat source publik apabila kamu tidak ingin kode terlihat orang lain. BOCIL OSINT versi ini tidak menyertakan secret API key, tetapi semua source code dari repository publik memang dapat dibaca orang lain.

**Tool menampilkan error atau hasil kosong**
- Domain recon, IP lookup, dan email MX memakai API publik eksternal. Hasil dapat terganggu oleh CORS, rate limit, kebijakan jaringan, atau layanan yang sedang down. Coba lagi nanti atau cek sumber publiknya secara langsung.
- URL Inspector, SHA-256, metadata parser tidak membutuhkan API OSINT. Untuk SHA-256, buka app melalui `localhost` atau HTTPS karena Web Crypto API memerlukan secure context.

**Tampilan atau styling bermasalah**
- Bersihkan cache browser, refresh halaman, dan pastikan deployment menggunakan commit terbaru.
- Font eksternal hanya untuk tampilan. Jika akses ke Google Fonts diblokir, aplikasi tetap memakai fallback font sistem.

## 9. Arti “gratis” dan batasan penting

- GitHub Free dan GitLab Free dapat menyimpan repository pada kuota dan batasan paket masing-masing.
- Vercel Hobby gratis untuk proyek personal/nonkomersial, dengan batas pemakaian. Batas produk bisa berubah; periksa dokumentasi paket sebelum menjalankan beban tinggi.
- Starter ini tidak memiliki database atau login cloud, jadi tidak ada biaya database wajib.
- API DNS/RDAP/IP merupakan layanan pihak ketiga. Endpoint gratis bukan jaminan SLA, privasi, atau ketersediaan selamanya.
- Domain `.vercel.app` biasanya cukup untuk demo awal. Domain custom biasanya perlu dibeli kecuali kamu sudah memilikinya.

## 10. Dokumentasi resmi

- [Deploy Git repositories to Vercel](https://vercel.com/docs/git)
- [Vercel Hobby Plan](https://vercel.com/docs/plans/hobby)
- [GitHub: push repository lokal](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github)
- [GitLab: create project with Git push](https://docs.gitlab.com/topics/git/project/)
- [GitLab integration on Vercel](https://vercel.com/docs/git/vercel-for-gitlab)
