const config = require('../src/config');
const { getDb } = require('../src/db');
const { seedDatabase } = require('../src/db/seed');
const { startGateway } = require('../src/gateway');
const { startServiceNilai } = require('../src/services/nilai');
const { startServiceTranskrip } = require('../src/services/transkrip');

// Helper formatting warna konsol
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

let passCount = 0;
let failCount = 0;

function assertTest(title, condition, details = '') {
  if (condition) {
    passCount++;
    console.log(`  ${C.green}✓ PASS:${C.reset} ${title}`);
    if (details) console.log(`         ${C.cyan}${details}${C.reset}`);
  } else {
    failCount++;
    console.log(`  ${C.red}✗ FAIL:${C.reset} ${title}`);
    if (details) console.log(`         ${C.yellow}Detail: ${details}${C.reset}`);
  }
}

async function request(url, options = {}) {
  const res = await fetch(url, options);
  let body = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    body = await res.json();
  } else {
    body = await res.text();
  }
  return { status: res.status, headers: res.headers, body };
}

async function runTests() {
  console.log(`\n${C.bold}${C.cyan}================================================================${C.reset}`);
  console.log(`${C.bold}${C.cyan}   PENGUJIAN LENGKAP SISTEM ZERO TRUST SECURITY (NIST SP 800-207)${C.reset}`);
  console.log(`${C.bold}${C.cyan}================================================================${C.reset}\n`);

  // Reset database ke data seed awal
  seedDatabase();

  const GW = `http://localhost:${config.ports.gateway}`;
  const NILAI = `http://localhost:${config.ports.nilai}`;
  const TRANSKRIP = `http://localhost:${config.ports.transkrip}`;

  // =========================================================================
  // 1. PENGUJIAN AUTENTIKASI DAN TOKEN (4.1 & 4.3)
  // =========================================================================
  console.log(`\n${C.bold}${C.magenta}[1] PENGUJIAN AUTENTIKASI, PERANGKAT TERDAFTAR, & REFRESH TOKEN${C.reset}`);

  // 1.1 Login dosen dengan perangkat terdaftar
  const loginDosenRes = await request(`${GW}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-DOSEN-01' },
    body: JSON.stringify({ username: 'dosen_budi', password: 'password123' })
  });
  assertTest(
    'Login Dosen Budi dengan kredensial valid dan Device terdaftar (DEV-DOSEN-01)',
    loginDosenRes.status === 200 && loginDosenRes.body.accessToken && loginDosenRes.body.refreshToken,
    `Status: ${loginDosenRes.status}, Token: ${loginDosenRes.body.accessToken ? 'JWT OK' : 'None'}`
  );
  const tokenDosenBudi = loginDosenRes.body.accessToken;
  const refreshDosenBudi = loginDosenRes.body.refreshToken;

  // 1.2 Login dengan device TIDAK terdaftar
  const loginUnregisteredRes = await request(`${GW}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-HACKER-LAPTOP' },
    body: JSON.stringify({ username: 'dosen_budi', password: 'password123' })
  });
  assertTest(
    'Login Dosen Budi dari device TIDAK terdaftar (DEV-HACKER-LAPTOP) -> DITOLAK (403)',
    loginUnregisteredRes.status === 403 && loginUnregisteredRes.body.error === 'UNREGISTERED_DEVICE',
    `Status: ${loginUnregisteredRes.status}, Error: ${loginUnregisteredRes.body.reason}`
  );

  // 1.3 Login Mahasiswa Ahmad & Dewi
  const loginMhsRes = await request(`${GW}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-MHS-01' },
    body: JSON.stringify({ username: 'mhs_ahmad', password: 'password123' })
  });
  const tokenMhsAhmad = loginMhsRes.body.accessToken;

  const loginDewiRes = await request(`${GW}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-MHS-02' },
    body: JSON.stringify({ username: 'mhs_dewi', password: 'password123' })
  });
  const tokenMhsDewi = loginDewiRes.body.accessToken;

  // 1.4 Login Admin
  const loginAdminRes = await request(`${GW}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-ADMIN-01' },
    body: JSON.stringify({ username: 'admin', password: 'password123' })
  });
  const tokenAdmin = loginAdminRes.body.accessToken;

  // 1.5 Login Dosen Siti
  const loginDosenSitiRes = await request(`${GW}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-DOSEN-02' },
    body: JSON.stringify({ username: 'dosen_siti', password: 'password123' })
  });
  const tokenDosenSiti = loginDosenSitiRes.body.accessToken;

  // 1.6 Refresh Token
  const refreshRes = await request(`${GW}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-DOSEN-01' },
    body: JSON.stringify({ refreshToken: refreshDosenBudi })
  });
  assertTest(
    'Perpanjang masa aktif token dengan POST /auth/refresh -> SUKSES (200)',
    refreshRes.status === 200 && refreshRes.body.accessToken,
    `Access token baru berhasil diterbitkan`
  );

  // 1.7 Logout (Mencabut Refresh Token)
  const logoutRes = await request(`${GW}/auth/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-ID': 'DEV-DOSEN-01' },
    body: JSON.stringify({ refreshToken: refreshDosenBudi })
  });
  assertTest(
    'Logout POST /auth/logout mencabut refresh token di database -> SUKSES (200)',
    logoutRes.status === 200,
    logoutRes.body.message
  );

  // 1.8 Coba pakai lagi refresh token yang sudah dicabut
  const refreshRevokedRes = await request(`${GW}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: refreshDosenBudi })
  });
  assertTest(
    'Menggunakan refresh token yang telah dicabut -> DITOLAK (401)',
    refreshRevokedRes.status === 401 && refreshRevokedRes.body.error === 'TOKEN_REVOKED',
    `Status: ${refreshRevokedRes.status}, Error: ${refreshRevokedRes.body.reason}`
  );

  // 1.9 POST /auth/service untuk Service Nilai
  const serviceTokenRes = await request(`${GW}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      clientId: config.serviceCredentials.clientId,
      clientSecret: config.serviceCredentials.clientSecret
    })
  });
  assertTest(
    'Service Nilai meminta Service Token dengan Client ID & Secret valid -> SUKSES (200)',
    serviceTokenRes.status === 200 && serviceTokenRes.body.role === 'service',
    `Role: ${serviceTokenRes.body.role}, Berlaku: ${serviceTokenRes.body.expiresIn}`
  );
  const serviceToken = serviceTokenRes.body.accessToken;

  // =========================================================================
  // 2. DEFENSE IN DEPTH & ISOLASI LAYANAN (PORT 3001 & 3002)
  // =========================================================================
  console.log(`\n${C.bold}${C.magenta}[2] PENGUJIAN DEFENSE IN DEPTH & ISOLASI LAYANAN (BYPASS GATEWAY)${C.reset}`);

  // 2.1 Akses langsung ke port 3001 tanpa X-Gateway-Secret
  const directNilaiNoSecret = await request(`${NILAI}/nilai`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenDosenBudi}` }
  });
  assertTest(
    'Akses langsung ke Service Nilai (port 3001) tanpa X-Gateway-Secret -> DITOLAK (403)',
    directNilaiNoSecret.status === 403 && directNilaiNoSecret.body.error === 'DIRECT_ACCESS_FORBIDDEN',
    `Layanan menolak akses non-gateway: ${directNilaiNoSecret.body.message}`
  );

  // 2.2 Akses langsung ke port 3002 tanpa X-Gateway-Secret
  const directTranskripNoSecret = await request(`${TRANSKRIP}/transkrip/220001`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenAdmin}` }
  });
  assertTest(
    'Akses langsung ke Service Transkrip (port 3002) tanpa X-Gateway-Secret -> DITOLAK (403)',
    directTranskripNoSecret.status === 403 && directTranskripNoSecret.body.error === 'DIRECT_ACCESS_FORBIDDEN',
    `Layanan menolak akses non-gateway: ${directTranskripNoSecret.body.message}`
  );

  // 2.3 Akses dengan X-Gateway-Secret palsu/ada tapi TANPA token JWT (Defense in depth)
  const directNilaiNoToken = await request(`${NILAI}/nilai`, {
    method: 'GET',
    headers: { 'X-Gateway-Secret': config.gatewaySecret }
  });
  assertTest(
    'Akses dengan X-Gateway-Secret valid tetapi TANPA Bearer token -> DITOLAK (401)',
    directNilaiNoToken.status === 401 && directNilaiNoToken.body.error === 'MISSING_TOKEN_AT_RESOURCE',
    `Service memverifikasi ulang token: ${directNilaiNoToken.body.message}`
  );

  // 2.4 Akses dengan X-Gateway-Secret valid dan token palsu (Defense in depth)
  const directNilaiFakeToken = await request(`${NILAI}/nilai`, {
    method: 'GET',
    headers: {
      'X-Gateway-Secret': config.gatewaySecret,
      'Authorization': 'Bearer token-palsu-rekayasa-123'
    }
  });
  assertTest(
    'Akses dengan X-Gateway-Secret valid tetapi token dipalsukan -> DITOLAK (401)',
    directNilaiFakeToken.status === 401 && directNilaiFakeToken.body.error === 'INVALID_TOKEN_AT_RESOURCE',
    `Service menolak signature token palsu`
  );

  // =========================================================================
  // 3. VERIFIKASI KONTEKS PERANGKAT & JAM AKSES (4.3)
  // =========================================================================
  console.log(`\n${C.bold}${C.magenta}[3] PENGUJIAN VERIFIKASI KONTEKS (DEVICE TERDAFTAR & JAM OPERASIONAL)${C.reset}`);

  // 3.1 Request via Gateway tanpa header X-Device-ID
  const reqNoDeviceHeader = await request(`${GW}/nilai`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenDosenBudi}` }
  });
  assertTest(
    'Request via Gateway tanpa header X-Device-ID -> DITOLAK (403)',
    reqNoDeviceHeader.status === 403 && reqNoDeviceHeader.body.error === 'DEVICE_ID_REQUIRED',
    reqNoDeviceHeader.body.reason
  );

  // 3.2 Request via Gateway dengan Device ID bukan milik user
  const reqWrongDeviceHeader = await request(`${GW}/nilai`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${tokenDosenBudi}`,
      'X-Device-ID': 'DEV-MHS-01' // Milik Ahmad, bukan milik Dr. Budi
    }
  });
  assertTest(
    'Request via Gateway dengan Device ID user lain -> DITOLAK (403)',
    reqWrongDeviceHeader.status === 403 && reqWrongDeviceHeader.body.error === 'UNREGISTERED_DEVICE',
    reqWrongDeviceHeader.body.reason
  );

  // 3.3 Percobaan ubah nilai di luar jam akses (simulasi jam 22.30 malam)
  const updateOffHoursRes = await request(`${GW}/nilai/1`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${tokenDosenBudi}`,
      'X-Device-ID': 'DEV-DOSEN-01',
      'X-Simulated-Hour': '23',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ tugas: 90, uts: 85, uas: 95 })
  });
  assertTest(
    'Update nilai di luar jam akses (pukul 23.00 malam) -> DITOLAK (403)',
    updateOffHoursRes.status === 403 && updateOffHoursRes.body.error === 'OUTSIDE_ACCESS_HOURS',
    updateOffHoursRes.body.reason
  );

  // =========================================================================
  // 4. KEBIJAKAN AKSES & LEAST PRIVILEGE (4.2 & TABEL 3)
  // =========================================================================
  console.log(`\n${C.bold}${C.magenta}[4] PENGUJIAN KEBIJAKAN AKSES, LEAST PRIVILEGE, & OBJECT AUTHORIZATION${C.reset}`);

  // 4.1 GET /nilai oleh Mahasiswa Ahmad -> hanya miliknya
  const mhsNilaiRes = await request(`${GW}/nilai`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenMhsAhmad}`, 'X-Device-ID': 'DEV-MHS-01' }
  });
  assertTest(
    'Mahasiswa Ahmad melihat GET /nilai miliknya -> SUKSES (200)',
    mhsNilaiRes.status === 200 && Array.isArray(mhsNilaiRes.body.data),
    `Total data nilai Ahmad: ${mhsNilaiRes.body.totalData} mata kuliah`
  );

  // 4.2 GET /nilai oleh Dosen Budi -> hanya kelas yang diampu
  const dosenNilaiRes = await request(`${GW}/nilai`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenDosenBudi}`, 'X-Device-ID': 'DEV-DOSEN-01' }
  });
  const allBudiClass = dosenNilaiRes.body.data.every(n => n.kelas_id === 1);
  assertTest(
    'Dosen Budi melihat GET /nilai kelasnya (Kelas 1: Keamanan Informasi) -> SUKSES (200)',
    dosenNilaiRes.status === 200 && allBudiClass && dosenNilaiRes.body.totalData === 3,
    `Hanya melihat mahasiswa pada kelas yang diampu (Total: ${dosenNilaiRes.body.totalData})`
  );

  // 4.3 Admin mencoba GET /nilai -> DITOLAK (Least Privilege: Tabel 3 hanya izinkan Mahasiswa & Dosen)
  const adminNilaiRes = await request(`${GW}/nilai`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenAdmin}`, 'X-Device-ID': 'DEV-ADMIN-01' }
  });
  assertTest(
    'Admin mencoba GET /nilai -> DITOLAK (403) sesuai Least Privilege',
    adminNilaiRes.status === 403,
    adminNilaiRes.body.reason
  );

  // 4.4 Dosen Budi update nilai pada kelasnya dalam jam operasional (simulasi jam 10 pagi)
  const updateNilaiOkRes = await request(`${GW}/nilai/1`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${tokenDosenBudi}`,
      'X-Device-ID': 'DEV-DOSEN-01',
      'X-Simulated-Hour': '10',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ tugas: 90, uts: 85, uas: 95 })
  });
  assertTest(
    'Dosen Budi mengubah nilai mahasiswa di kelasnya (ID 1) dalam jam akses -> SUKSES (200)',
    updateNilaiOkRes.status === 200 && updateNilaiOkRes.body.data.nilai_akhir === 90.5,
    `Nilai baru: Akhir=${updateNilaiOkRes.body.data.nilai_akhir}, Huruf=${updateNilaiOkRes.body.data.huruf_mutu}`
  );

  // 4.5 Dosen Budi mencoba mengubah nilai kelas Dosen Siti (IDOR / Object-Level Authorization)
  // ID 4 adalah nilai di Kelas 2 (Sistem Terdistribusi - Dosen Siti)
  const idorRes = await request(`${GW}/nilai/4`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${tokenDosenBudi}`,
      'X-Device-ID': 'DEV-DOSEN-01',
      'X-Simulated-Hour': '10',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ tugas: 100, uts: 100, uas: 100 })
  });
  assertTest(
    'Dosen Budi mencoba ubah nilai kelas Dosen Siti (IDOR) -> DITOLAK (403)',
    idorRes.status === 403 && idorRes.body.error === 'OBJECT_ACCESS_DENIED',
    idorRes.body.reason
  );

  // 4.6 Mahasiswa mencoba mengubah nilai -> DITOLAK (403)
  const mhsUpdateNilaiRes = await request(`${GW}/nilai/1`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${tokenMhsAhmad}`,
      'X-Device-ID': 'DEV-MHS-01',
      'X-Simulated-Hour': '10',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ tugas: 100 })
  });
  assertTest(
    'Mahasiswa Ahmad mencoba mengubah nilai -> DITOLAK (403)',
    mhsUpdateNilaiRes.status === 403,
    mhsUpdateNilaiRes.body.reason
  );

  // 4.7 Dosen Budi memfinalisasi kelas 1
  // Otomatis memicu Service Nilai -> minta token service ke Gateway -> kirim ke Service Transkrip via Gateway
  const finalisasiRes = await request(`${GW}/kelas/1/finalisasi`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${tokenDosenBudi}`,
      'X-Device-ID': 'DEV-DOSEN-01',
      'X-Simulated-Hour': '14'
    }
  });
  assertTest(
    'Dosen Budi memfinalisasi Kelas 1 & memicu sinkronisasi transkrip via Gateway -> SUKSES (200)',
    finalisasiRes.status === 200 && finalisasiRes.body.syncResult && finalisasiRes.body.syncResult.success,
    `Sinkronisasi otomatis berhasil untuk ${finalisasiRes.body.jumlahMahasiswa} mahasiswa`
  );

  // 4.8 Dosen Budi mencoba mengubah nilai LAGI setelah difinalisasi -> DITOLAK (403)
  const updateAfterFinalRes = await request(`${GW}/nilai/1`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${tokenDosenBudi}`,
      'X-Device-ID': 'DEV-DOSEN-01',
      'X-Simulated-Hour': '14',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ tugas: 99 })
  });
  assertTest(
    'Mengubah nilai yang SUDAH DIFINALISASI -> DITOLAK (403)',
    updateAfterFinalRes.status === 403 && updateAfterFinalRes.body.error === 'ALREADY_FINALIZED',
    updateAfterFinalRes.body.reason
  );

  // 4.9 Mahasiswa Ahmad melihat transkrip miliknya sendiri (NIM: 220001)
  const mhsTranskripSelfRes = await request(`${GW}/transkrip/220001`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenMhsAhmad}`, 'X-Device-ID': 'DEV-MHS-01' }
  });
  assertTest(
    'Mahasiswa Ahmad melihat transkrip miliknya sendiri (220001) -> SUKSES (200)',
    mhsTranskripSelfRes.status === 200 && mhsTranskripSelfRes.body.transkrip.length > 0,
    `IPK: ${mhsTranskripSelfRes.body.ipk}, Total SKS: ${mhsTranskripSelfRes.body.totalSks}`
  );

  // 4.10 Mahasiswa Ahmad mencoba melihat transkrip mahasiswa Dewi (NIM: 220002)
  const mhsTranskripOtherRes = await request(`${GW}/transkrip/220002`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenMhsAhmad}`, 'X-Device-ID': 'DEV-MHS-01' }
  });
  assertTest(
    'Mahasiswa Ahmad mencoba melihat transkrip NIM mahasiswa lain (Dewi: 220002) -> DITOLAK (403)',
    mhsTranskripOtherRes.status === 403 && mhsTranskripOtherRes.body.error === 'UNAUTHORIZED_STUDENT_TRANSCRIPT',
    mhsTranskripOtherRes.body.reason
  );

  // 4.11 Admin melihat transkrip seluruh mahasiswa
  const adminTranskripAhmad = await request(`${GW}/transkrip/220001`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenAdmin}`, 'X-Device-ID': 'DEV-ADMIN-01' }
  });
  const adminTranskripDewi = await request(`${GW}/transkrip/220002`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenAdmin}`, 'X-Device-ID': 'DEV-ADMIN-01' }
  });
  assertTest(
    'Admin melihat transkrip NIM Ahmad (220001) dan Dewi (220002) -> SUKSES (200)',
    adminTranskripAhmad.status === 200 && adminTranskripDewi.status === 200,
    `Admin berhasil membaca seluruh transkrip mahasiswa`
  );

  // 4.12 Token user biasa mencoba memanggil POST /transkrip/sinkron -> DITOLAK (403)
  const userTrySyncRes = await request(`${GW}/transkrip/sinkron`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${tokenAdmin}`,
      'X-Device-ID': 'DEV-ADMIN-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ kelasId: 1 })
  });
  assertTest(
    'Token user (Admin/Dosen/Mhs) mencoba memanggil POST /transkrip/sinkron -> DITOLAK (403)',
    userTrySyncRes.status === 403 && userTrySyncRes.body.error === 'SERVICE_TOKEN_REQUIRED',
    userTrySyncRes.body.reason
  );

  // =========================================================================
  // 5. AUDIT LOGGING (4.4)
  // =========================================================================
  console.log(`\n${C.bold}${C.magenta}[5] PENGUJIAN AUDIT LOGGING GATEWAY${C.reset}`);

  const auditRes = await request(`${GW}/audit-logs?limit=100`, { method: 'GET' });
  const hasAllow = auditRes.body.logs.some(l => l.result === 'ALLOW');
  const hasDeny = auditRes.body.logs.some(l => l.result === 'DENY');
  assertTest(
    'Gateway mencatat setiap keputusan akses (ALLOW & DENY) beserta timestamp, subjek, endpoint, device, dan alasan',
    auditRes.status === 200 && hasAllow && hasDeny,
    `Total audit log tercatat: ${auditRes.body.total} entri log`
  );

  // Cetak ringkasan
  console.log(`\n${C.bold}${C.cyan}================================================================${C.reset}`);
  console.log(`${C.bold}RINGKASAN PENGUJIAN:${C.reset}`);
  console.log(`  ${C.green}TOTAL LULUS (PASS): ${passCount}${C.reset}`);
  console.log(`  ${failCount > 0 ? C.red : C.green}TOTAL GAGAL (FAIL): ${failCount}${C.reset}`);
  console.log(`${C.bold}${C.cyan}================================================================${C.reset}\n`);

  if (failCount === 0) {
    console.log(`${C.bold}${C.green}SELURUH 20 SKENARIO ZERO TRUST BERHASIL LOLOS SEMPURNA! 🎉${C.reset}\n`);
  }
}

async function startAndTest() {
  const { main } = require('../src/index');
  await main();
  await runTests();
  process.exit(failCount === 0 ? 0 : 1);
}

if (require.main === module) {
  startAndTest().catch(err => {
    console.error('Test execution failed:', err);
    process.exit(1);
  });
}
