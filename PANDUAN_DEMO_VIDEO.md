# Panduan Rekaman Video Demo Praktikum (Durasi: 6 – 9 Menit)
**Topik:** Zero Trust Security Architecture (NIST SP 800-207)  
**Mata Kuliah:** Keamanan Informasi - Informatika Universitas Siliwangi

---

## ⏱️ Rundown Durasi & Alur Presentasi

| Menit | Bagian | Fokus yang Ditampilkan di Layar |
|---|---|---|
| **00:00 - 01:00** | **1. Pembukaan & Pengenalan Arsitektur** | Tampilkan diagram arsitektur di README.md & terminal saat `npm start` |
| **01:00 - 02:45** | **2. Kebutuhan 4.1: Autentikasi & Token** | Tampilkan kode `src/gateway/auth.js` & `src/services/commonAuthMiddleware.js`, demo Postman login, refresh, logout, & bypass attack |
| **02:45 - 04:45** | **3. Kebutuhan 4.2: Kebijakan Akses (Least Privilege & IDOR)** | Tampilkan kode `src/gateway/policy.js`, demo Dosen vs Mahasiswa vs Admin, demo pencegahan IDOR |
| **04:45 - 06:15** | **4. Kebutuhan 4.2: Finalisasi & Panggilan Antar-Service** | Tampilkan kode `src/services/nilai/index.js` (bagian finalisasi), demo POST /kelas/1/finalisasi & sinkron transkrip via Gateway |
| **06:15 - 07:30** | **5. Kebutuhan 4.3: Verifikasi Konteks (Device & Jam Akses)** | Tampilkan kode konteks di `policy.js`, demo device tidak terdaftar & jam di luar 07.00-21.00 |
| **07:30 - 08:30** | **6. Kebutuhan 4.4: Audit Log & Penutup** | Tampilkan terminal Gateway dengan log live warna-warni `[ALLOW]` / `[DENY]` dan endpoint `GET /audit-logs` |

---

## 📝 Naskah & Panduan Praktik Langkah demi Langkah

### 1. Pembukaan & Pengenalan Arsitektur (00:00 – 01:00)
* **Aktivitas Layar:** Buka VS Code/IDE, buka file `README.md` pada bagian diagram arsitektur.
* **Narasi yang Diucapkan:**
  > *"Halo semuanya, perkenalkan nama saya [Nama Anda], NIM [NIM Anda]. Pada kesempatan kali ini saya akan mendemonstrasikan hasil pengerjaan Tugas Praktikum Individu Keamanan Informasi mengenai Zero Trust Security Architecture sesuai standar NIST SP 800-207.*  
  > *Pada sistem ini, kita menerapkan tiga prinsip utama Zero Trust: **Never Trust Always Verify**, **Least Privilege**, dan **Assume Breach** langsung pada level aplikasi web.*  
  > *Arsitektur terdiri dari tiga komponen utama:*  
  > *1. **API Gateway pada port 3000** yang bertindak sebagai Policy Enforcement Point (PEP) dan Policy Decision Point (PDP).*  
  > *2. **Service Nilai pada port 3001** sebagai resource.*  
  > *3. **Service Transkrip pada port 3002** sebagai resource.*  
  > *Mari kita jalankan sistemnya dengan mengetik `npm start`."*
* **Aktivitas Layar:** Jalankan terminal:
  ```bash
  npm start
  ```
  Tunjukkan bahwa ketiga service (port 3000, 3001, 3002) aktif berjalan.

---

### 2. Kebutuhan 4.1: Autentikasi, Token, & Defense in Depth (01:00 – 02:45)
* **Aktivitas Layar:** Buka file `src/gateway/auth.js` dan tunjukkan implementasi:
  - Access Token JWT 10 menit (baris 45-60)
  - Refresh Token 1 hari yang disimpan di tabel `refresh_tokens` (baris 61-75)
  - Fitur Logout yang mencabut token (`revoked = 1`) (baris 150-170)
  - Service Token untuk `Service Nilai` dengan masa aktif 5 menit (baris 180-215).
* **Narasi yang Diucapkan:**
  > *"Pada bagian 4.1, autentikasi user menghasilkan Access Token JWT yang berlaku singkat (10 menit) untuk meminimalisasi dampak pembajakan token. Gateway juga menerbitkan Refresh Token yang disimpan di database.*  
  > *Jika user melakukan logout, refresh token langsung dicabut statusnya (revoked), sehingga tidak bisa dipakai lagi."*
* **Aktivitas Layar (Demo Postman / curl):**
  1. Jalankan **1.1 Login Dosen Budi (Device Terdaftar)** -> Berhasil dapat Access Token & Refresh Token.
  2. Jalankan **1.6 Logout** -> Refresh token dicabut.
  3. Coba panggil **1.5 Refresh Token** dengan token yang sama -> Menghasilkan error `401 TOKEN_REVOKED`.
  4. Jalankan **1.7 POST /auth/service** -> Tunjukkan terbitnya service token dengan `role: "service"`.
* **Aktivitas Layar (Bypass Perimeter & Defense in Depth):**
  - Buka file `src/services/commonAuthMiddleware.js`.
  - Tunjukkan bahwa `Service Nilai` dan `Service Transkrip` memeriksa header `X-Gateway-Secret`.
  - Tunjukkan juga bahwa jika attacker memasukkan secret tapi tanpa token valid, service tetap memverifikasi ulang tanda tangan JWT (**Defense in Depth**).
  - Jalankan di Postman folder **4. Defense in Depth & Bypass Perimeter**:
    - Request langsung ke `http://localhost:3001/nilai` tanpa secret -> Ditolak `403 DIRECT_ACCESS_FORBIDDEN`.
    - Request dengan secret tapi tanpa token -> Ditolak `401 MISSING_TOKEN_AT_RESOURCE`.

---

### 3. Kebutuhan 4.2: Kebijakan Akses, Least Privilege, & Anti-IDOR (02:45 – 04:45)
* **Aktivitas Layar:** Buka file `src/gateway/policy.js` (Policy Engine / PDP).
* **Narasi yang Diucapkan:**
  > *"Selanjutnya pada bagian 4.2, Policy Engine di Gateway menegakkan kebijakan akses berdasarkan tabel kebijakan dan data kepemilikan di database (Least Privilege).*  
  > *Sebagai contoh, Mahasiswa hanya boleh melihat nilainya sendiri, sedangkan Dosen hanya boleh melihat dan mengedit kelas yang diampunya."*
* **Aktivitas Layar (Demo Postman):**
  1. Buka folder **2. Kebijakan Akses & Kontrol Nilai**:
     - Jalankan **2.1 GET /nilai oleh Mahasiswa Ahmad** -> Tunjukkan response hanya berisi nilai Ahmad.
     - Jalankan **2.2 GET /nilai oleh Dosen Budi** -> Tunjukkan response hanya menampilkan mahasiswa di Kelas 1 (Keamanan Informasi) yang diampu Pak Budi.
  2. **Uji Coba Serangan IDOR (Object-Level Authorization):**
     - Jalankan **2.3 PUT /nilai/1 oleh Dosen Budi** -> Berhasil mengubah nilai (karena kelas 1 milik Pak Budi).
     - Jalankan **2.4 PUT /nilai/4 oleh Dosen Budi** -> Tunjukkan response ditolak `403 OBJECT_ACCESS_DENIED`.  
     *Jelaskan ke video: ID 4 adalah nilai di kelas Sistem Terdistribusi yang diampu oleh Dosen Siti, sehingga Dosen Budi dicegah memanipulasi nilai kelas dosen lain!*

---

### 4. Kebutuhan 4.2: Finalisasi Kelas & Panggilan Antar-Service (04:45 – 06:15)
* **Aktivitas Layar:** Buka file `src/services/nilai/index.js` pada fungsi `app.post('/kelas/:id/finalisasi')` (baris 130-210).
* **Narasi yang Diucapkan:**
  > *"Salah satu implementasi Zero Trust paling penting di sini adalah **Panggilan Antar-Service**. Ketika Dosen memfinalisasi kelas, Service Nilai tidak boleh memanggil Service Transkrip secara langsung atau berasumsi bahwa jaringan lokal itu aman.*  
  > *Sesuai prinsip Zero Trust, Service Nilai meminta Service Token ke Gateway melalui `POST /auth/service`, lalu mengirimkan data sinkronisasi ke Gateway di `POST /transkrip/sinkron`.*  
  > *Gateway memverifikasi bahwa pemanggil ber-role `service`. Jika user biasa mencoba memanggil endpoint ini, gateway akan menolaknya."*
* **Aktivitas Layar (Demo Postman):**
  1. Jalankan **2.6 POST /kelas/1/finalisasi oleh Dosen Budi** -> Tunjukkan bahwa finalisasi sukses dan sinkronisasi transkrip berhasil.
  2. Buka terminal Gateway -> Tunjukkan log inter-service call:
     - `POST /auth/service` -> ALLOW
     - `POST /transkrip/sinkron` -> ALLOW (subject: service-nilai)
  3. Coba jalankan **2.7 PUT /nilai/1 Setelah Finalisasi** -> Tunjukkan ditolak `403 ALREADY_FINALIZED` (nilai yang sudah final tidak boleh diubah).
  4. Jalankan **3.4 User Memanggil POST /transkrip/sinkron Langsung** -> Tunjukkan ditolak `403 SERVICE_TOKEN_REQUIRED`.
  5. Jalankan **3.1 GET Transkrip Sendiri oleh Mahasiswa Ahmad** -> Tunjukkan nilai yang sudah difinalisasi kini masuk ke transkrip Ahmad beserta IPK-nya!
  6. Jalankan **3.2 GET Transkrip Mahasiswa Lain oleh Ahmad** -> Ditolak `403 UNAUTHORIZED_STUDENT_TRANSCRIPT`.
  7. Jalankan **3.3 GET Transkrip oleh Admin** -> Berhasil melihat semua NIM mahasiswa.

---

### 5. Kebutuhan 4.3: Verifikasi Konteks (Perangkat Terdaftar & Jam Akses) (06:15 – 07:30)
* **Aktivitas Layar:** Buka file `src/gateway/policy.js` pada bagian verifikasi `X-Device-ID` dan verifikasi jam operasional.
* **Narasi yang Diucapkan:**
  > *"Pada bagian 4.3, Zero Trust tidak hanya memeriksa identitas akun, tetapi juga **konteks request**:*  
  > *Pertama, **Device Terdaftar:** Setiap request user wajib membawa header `X-Device-ID` yang dicocokkan dengan tabel `registered_devices`.*  
  > *Kedua, **Jam Akses:** Perubahan dan finalisasi nilai hanya diizinkan pada jam 07.00 sampai 21.00."*
* **Aktivitas Layar (Demo Postman):**
  1. Jalankan **1.2 Login Dosen Budi (Device Tidak Terdaftar)** dengan header `X-Device-ID: DEV-UNREGISTERED-LAPTOP` -> Ditolak `403 UNREGISTERED_DEVICE`.
  2. Jalankan **2.5 PUT /nilai/1 di Luar Jam Akses** dengan header `X-Simulated-Hour: 23` -> Ditolak `403 OUTSIDE_ACCESS_HOURS`.

---

### 6. Kebutuhan 4.4: Audit Log & Penutup (07:30 – 08:30)
* **Aktivitas Layar:** Buka terminal yang menjalankan Gateway, lalu buka endpoint `GET http://localhost:3000/audit-logs` di browser / Postman.
* **Narasi yang Diucapkan:**
  > *"Kebutuhan terakhir adalah bagian 4.4 mengenai **Audit Log**. Sesuai tenet NIST SP 800-207, seluruh data akses harus dicatat untuk monitoring dan evaluasi.*  
  > *Gateway mencatat setiap keputusan baik ALLOW maupun DENY secara real-time ke terminal dan database: mencatat timestamp, subjek, endpoint, device ID, hasil, serta alasan penolakan/izinnya.*  
  > *Untuk memvalidasi keseluruhan sistem secara otomatis, kita juga dapat menjalankan `npm test` yang mengeksekusi 26 skenario pengujian sekaligus."*
* **Aktivitas Layar:** Buka terminal baru dan jalankan:
  ```bash
  npm test
  ```
  Tunjukkan bahwa **SELURUH 26 SKENARIO LOLOS (PASS: 26, FAIL: 0)**!
* **Kalimat Penutup:**
  > *"Dengan demikian, seluruh kebutuhan pada Bagian 4 dan prinsip Zero Trust Security (Never Trust Always Verify, Least Privilege, dan Defense in Depth) telah berhasil diimplementasikan secara utuh pada Sistem Nilai dan Transkrip ini.*  
  > *Terima kasih atas perhatiannya, wassalamu'alaikum warahmatullahi wabarakatuh."*
