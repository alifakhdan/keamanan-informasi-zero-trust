# Tugas Praktikum Individu: Zero Trust Security Architecture
**Mata Kuliah:** Keamanan Informasi (KP70065004)  
**Program Studi:** Informatika, Universitas Siliwangi  
**Standar Arsitektur:** NIST SP 800-207 (Zero Trust Architecture)

---

## 1. Ringkasan Sistem & Prinsip Zero Trust

Proyek ini mengimplementasikan **Sistem Pengelolaan Nilai dan Transkrip Mahasiswa** berbasis arsitektur **Zero Trust Security** sesuai pedoman **NIST SP 800-207**.

Tiga prinsip dasar Zero Trust yang diterapkan:
1. **Never Trust, Always Verify (Verify Explicitly):**
   - Tidak ada perimeter jaringan yang dipercaya secara otomatis.
   - Setiap permintaan (baik dari user luar maupun panggilan antar-service internal) wajib melewati **API Gateway (Policy Enforcement Point - PEP)** dan dievaluasi oleh **Policy Engine (Policy Decision Point - PDP)**.
   - Resource service (Port 3001 & 3002) menolak akses langsung yang membypass gateway dan menerapkan **Defense in Depth** (memverifikasi ulang keaslian JWT token).
2. **Least Privilege (Akses Minimum):**
   - Mahasiswa hanya dapat melihat nilai dan transkrip miliknya sendiri.
   - Dosen hanya dapat melihat, mengedit, dan memfinalisasi kelas yang diampunya (mencegah *Insecure Direct Object Reference* / IDOR).
   - Admin hanya dapat melihat transkrip, tidak dapat mengubah nilai.
   - Endpoint sinkronisasi transkrip hanya dapat diakses oleh Token Service, token user mana pun ditolak.
3. **Assume Breach:**
   - Token dibuat berumur pendek (*short-lived*): Access token 10 menit, Token service 5 menit.
   - Refresh token dapat dicabut seketika (*revoked*) saat user logout.
   - Setiap aktivitas dan keputusan (`ALLOW` / `DENY`) dicatat secara mendalam pada **Audit Log**.

---

## 2. Arsitektur Komponen & Port

```
                           +------------------------+
                           |  Client (Postman/curl) |
                           +-----------+------------+
                                       |
                   [access token + X-Device-ID]
                                       |
                                       v
        +-------------------------------------------------------------+
        |                 API GATEWAY (Port 3000)                     |
        |              Policy Enforcement Point (PEP)                 |
        |                                                             |
        |  +-------------------------+    +------------------------+  |
        |  | Policy Administrator/   |    |      Audit Logger      |  |
        |  | Policy Engine (PDP)     |    | (Mencatat ALLOW / DENY)|  |
        |  +-------------------------+    +------------------------+  |
        +---------------+-----------------------------+---------------+
                        |                             |
      [jika allow +     |                             | [jika allow +
       X-Gateway-Secret]|                             |  X-Gateway-Secret]
                        v                             v
        +-------------------------------+     +-------------------------------+
        |   Service Nilai (Port 3001)   |     | Service Transkrip (Port 3002) |
        |           (Resource)          |     |           (Resource)          |
        |   - Verifikasi Gateway Secret |     |   - Verifikasi Gateway Secret |
        |   - Verifikasi Ulang Token    |     |   - Verifikasi Ulang Token    |
        +---------------+---------------+     +---------------+---------------+
                        |                                     |
                        |      [Panggilan Antar-Service:      |
                        |     POST /transkrip/sinkron via GW] |
                        +-------------------------------------+
                                       |
                                       v
                        +-----------------------------+
                        |   SQLite Database (Shared)  |
                        +-----------------------------+
```

| Komponen | Peran NIST SP 800-207 | Port | Tanggung Jawab |
|---|---|---|---|
| **API Gateway** | Policy Enforcement Point (PEP) | 3000 | Satu-satunya pintu masuk. Memeriksa setiap request, meminta keputusan ke Policy Engine, mencatat audit log, lalu meneruskan request ke service tujuan. |
| **Policy Engine / PA** | Policy Decision Point (PDP) / PA | Di dalam Gateway | Menangani login, menerbitkan/mencabut token, serta memutuskan `ALLOW` atau `DENY` berdasarkan data context & database. |
| **Service Nilai** | Resource | 3001 | Mengelola data nilai dan kelas. Memverifikasi secret gateway & token. Saat finalisasi kelas, memanggil Service Transkrip melalui API Gateway menggunakan service token. |
| **Service Transkrip**| Resource | 3002 | Mengelola transkrip mahasiswa & perhitungan IPK. Menerima sinkronisasi nilai hanya dari token service. |
| **Database** | Resource | SQLite File | Database bersama untuk menyimpan data user, perangkat terdaftar, refresh token, kelas, nilai, transkrip, dan audit logs. |

---

## 3. Data Awal (Seed Data)

### 3.1 Daftar Akun Pengguna

| Username | Password | Role | Nama Lengkap | Identitas | Device ID Terdaftar |
|---|---|---|---|---|---|
| `admin` | `password123` | `admin` | Administrator Sistem | - | `DEV-ADMIN-01` |
| `dosen_budi` | `password123` | `dosen` | Dr. Budi Santoso, M.Kom. | NIDN: `0401018501` | `DEV-DOSEN-01` |
| `dosen_siti` | `password123` | `dosen` | Siti Aminah, M.T. | NIDN: `0402028802` | `DEV-DOSEN-02` |
| `mhs_ahmad` | `password123` | `mahasiswa` | Ahmad Pratama | NIM: `220001` | `DEV-MHS-01` |
| `mhs_dewi` | `password123` | `mahasiswa` | Dewi Lestari | NIM: `220002` | `DEV-MHS-02` |
| `mhs_rian` | `password123` | `mahasiswa` | Rian Hidayat | NIM: `220003` | `DEV-MHS-03` |

### 3.2 Data Kelas & Dosen Pengampu

| ID Kelas | Kode MK | Nama Mata Kuliah | SKS | Dosen Pengampu |
|---|---|---|---|---|
| `1` | `IF-301` | Keamanan Informasi | 3 | `dosen_budi` (Dr. Budi Santoso) |
| `2` | `IF-302` | Sistem Terdistribusi | 3 | `dosen_siti` (Siti Aminah, M.T.) |

### 3.3 Kredensial Service Antar-Komponen

- **Client ID:** `service-nilai`
- **Client Secret:** `secret-nilai-client-2024`
- **Gateway Secret:** `pep-gateway-internal-secret-token-xyz`

---

## 4. Cara Menjalankan

### Prasyarat
- **Node.js** v18+ (direkomendasikan v20+)
- **npm** v9+

### Langkah 1: Instalasi Dependensi
```bash
npm install
```

### Langkah 2: Seeding Database Awal
```bash
npm run seed
```

### Langkah 3: Menjalankan Sistem
Jalankan seluruh service (Gateway port 3000, Service Nilai port 3001, Service Transkrip port 3002) secara serentak:
```bash
npm start
```

*(Opsional: Anda juga dapat menjalankan setiap komponen di terminal terpisah)*:
- Terminal 1: `npm run start:gateway`
- Terminal 2: `npm run start:nilai`
- Terminal 3: `npm run start:transkrip`

### Langkah 4: Menjalankan Pengujian Otomatis
Tersedia suite pengujian otomatis yang menguji **26 skenario pengujian Zero Trust**:
```bash
npm test
```

---

## 5. Ringkasan Implementasi Kebutuhan Sistem (Bagian 4)

### 4.1 Autentikasi dan Token
- **Access Token:** JWT berumur 10 menit (`expiresIn: '10m'`) berisi identitas pengguna (`sub`, `role`, `nim`, `nidn`). Dikirim via header `Authorization: Bearer <token>`.
- **Refresh Token:** Berlaku 1 hari, dicatat di tabel `refresh_tokens`. Pemanggilan `POST /auth/logout` mencabut status token (`revoked = 1`) sehingga tidak dapat digunakan kembali.
- **Token Service:** `Service Nilai` meminta token melalui `POST /auth/service` menggunakan client ID dan client secret. Token memiliki klaim `role: "service"` dan kadaluarsa dalam 5 menit.
- **Gateway Secret & Defense in Depth:**
  - Gateway menyematkan header `X-Gateway-Secret` saat mem-proxy request.
  - Resource service menolak akses langsung tanpa header tersebut (HTTP 403).
  - Resource service **memverifikasi ulang** tanda tangan dan masa berlaku JWT (HTTP 401 jika token dimanipulasi atau tidak ada).

### 4.2 Kebijakan Akses (Policy Engine / PDP)
Kebijakan ditegakkan di API Gateway (`src/gateway/policy.js`):
- `GET /nilai`: Mahasiswa hanya melihat nilainya; Dosen hanya melihat kelas yang diampunya.
- `PUT /nilai/:id`: Dosen hanya dapat mengubah nilai kelas yang diampunya (perlindungan IDOR). Perubahan ditolak jika nilai sudah difinalisasi atau di luar jam operasional.
- `POST /kelas/:id/finalisasi`: Dosen memfinalisasi kelasnya. Service Nilai secara otomatis meminta token service ke Gateway lalu menyinkronkan data ke Service Transkrip via Gateway (`POST /transkrip/sinkron`).
- `GET /transkrip/:nim`: Mahasiswa hanya bisa membaca transkrip miliknya sendiri; Admin bisa membaca semua transkrip.
- `POST /transkrip/sinkron`: Secara ketat hanya diizinkan bagi token dengan `role: "service"`. Token user biasa ditolak.

### 4.3 Verifikasi Konteks
- **Device Terdaftar:** Setiap request user wajib membawa header `X-Device-ID`. Device diverifikasi ke tabel `registered_devices`. Jika tidak terdaftar, request ditolak (`UNREGISTERED_DEVICE`).
- **Jam Akses:** Operasi ubah nilai dan finalisasi dibatasi pada rentang jam **07.00–21.00**. Disediakan simulasi via header `X-Simulated-Hour` atau konfigurasi `.env`.

### 4.4 Audit Log
Setiap keputusan akses dicatat ke tabel `audit_logs` dan ditampilkan pada terminal Gateway:
- Waktu (ISO 8601 Timestamp)
- Subjek (User ID / Username / Service ID)
- Endpoint (`METHOD PATH`)
- Device ID
- Hasil (`ALLOW` / `DENY`)
- Alasan penolakan / izin

Daftar audit log dapat dilihat via browser atau Postman di:
`GET http://localhost:3000/audit-logs`

---

## 6. Koleksi Postman

File koleksi Postman siap pakai telah disediakan pada direktori:
`postman/Zero_Trust_Sistem_Nilai.postman_collection.json`

Cukup buka Postman -> **Import** -> pilih file tersebut.
