const jwt = require('jsonwebtoken');
const config = require('../config');
const { getDb } = require('../db');
const { logAudit } = require('./audit');

/**
 * Policy Engine (PDP - Policy Decision Point)
 * Memeriksa identitas, token, device, context (jam akses), dan object-level authorization (IDOR).
 */
function evaluatePolicy(req, res, next) {
  const db = getDb();
  const endpoint = `${req.method} ${req.path}`;
  const deviceId = req.headers['x-device-id'] || null;

  // 1. Endpoint /auth/* dikecualikan dari pemeriksaan token PEP (karena login/refresh ditangani di PA)
  if (req.path.startsWith('/auth/')) {
    return next();
  }

  // 2. Verifikasi Token Authorization Bearer
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    const reason = 'Header Authorization: Bearer <token> wajib disertakan';
    logAudit({ subject: 'anonymous', endpoint, deviceId, result: 'DENY', reason });
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      policyResult: 'DENY',
      reason
    });
  }

  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = jwt.verify(token, config.jwt.secret);
  } catch (err) {
    const reason = `Verifikasi token gagal: ${err.message}`;
    logAudit({ subject: 'anonymous', endpoint, deviceId, result: 'DENY', reason });
    return res.status(401).json({
      error: 'INVALID_TOKEN',
      policyResult: 'DENY',
      reason
    });
  }

  const subject = decoded.sub ? String(decoded.sub) : 'unknown';
  const role = decoded.role;
  req.user = decoded; // Pasang decoded user ke req

  // 3. Verifikasi Konteks Perangkat (Device Terdaftar)
  // Untuk user normal (bukan service token), header X-Device-ID wajib ada dan cocok dengan yang terdaftar di DB
  if (role !== 'service') {
    if (!deviceId) {
      const reason = 'Header X-Device-ID wajib disertakan untuk setiap request user';
      logAudit({ subject, endpoint, deviceId: '-', result: 'DENY', reason });
      return res.status(403).json({
        error: 'DEVICE_ID_REQUIRED',
        policyResult: 'DENY',
        reason
      });
    }

    const userIdNum = Number(decoded.id || decoded.sub);
    const deviceRow = db.prepare(`
      SELECT * FROM registered_devices 
      WHERE user_id = ? AND device_id = ? AND is_active = 1
    `).get(userIdNum, deviceId);

    if (!deviceRow) {
      const reason = `Device [${deviceId}] tidak terdaftar atau tidak aktif untuk user [${decoded.username || subject}]`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({
        error: 'UNREGISTERED_DEVICE',
        policyResult: 'DENY',
        reason
      });
    }
  }

  // 4. Verifikasi Jam Akses (Context Verification: 07.00 - 21.00)
  // Hanya berlaku untuk perubahan nilai (PUT /nilai/:id) dan finalisasi (POST /kelas/:id/finalisasi)
  const isTimeRestrictedOperation =
    (req.method === 'PUT' && /^\/nilai\/\d+$/.test(req.path)) ||
    (req.method === 'POST' && /^\/kelas\/\d+\/finalisasi$/.test(req.path));

  if (isTimeRestrictedOperation) {
    // Dukung header X-Simulated-Hour untuk mempermudah demonstrasi jam di luar batas (cth: 22 atau 23)
    const simulatedHour = req.headers['x-simulated-hour'] !== undefined 
      ? parseInt(req.headers['x-simulated-hour'], 10) 
      : null;
    const currentHour = simulatedHour !== null ? simulatedHour : new Date().getHours();

    const { start, end, bypassForTest } = config.accessHours;
    if (!bypassForTest && (currentHour < start || currentHour >= end)) {
      const reason = `Operasi ditolak di luar jam akses operasional (${start}:00 - ${end}:00). Jam request saat ini: ${String(currentHour).padStart(2, '0')}:00`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({
        error: 'OUTSIDE_ACCESS_HOURS',
        policyResult: 'DENY',
        reason,
        currentHour,
        allowedRange: `${start}:00 - ${end}:00`
      });
    }
  }

  // 5. Evaluasi Kebijakan Akses Endpoint Spesifik (Tabel 3 NIST SP 800-207)

  // A. GET /nilai
  if (req.method === 'GET' && req.path === '/nilai') {
    if (role === 'mahasiswa' || role === 'dosen') {
      const reason = `Diizinkan: User [${decoded.username}] role [${role}] mengakses /nilai`;
      logAudit({ subject, endpoint, deviceId, result: 'ALLOW', reason });
      return next();
    }
    const reason = `Role [${role}] tidak diizinkan mengakses GET /nilai (Least Privilege: hanya Mahasiswa & Dosen)`;
    logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
    return res.status(403).json({ error: 'FORBIDDEN', policyResult: 'DENY', reason });
  }

  // B. PUT /nilai/:id
  const putNilaiMatch = req.path.match(/^\/nilai\/(\d+)$/);
  if (req.method === 'PUT' && putNilaiMatch) {
    if (role !== 'dosen') {
      const reason = `Hanya role dosen yang dapat mengubah nilai (Role pemohon: ${role})`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({ error: 'FORBIDDEN', policyResult: 'DENY', reason });
    }

    const nilaiId = parseInt(putNilaiMatch[1], 10);
    // Cek object-level: apakah nilai ini milik kelas yang diampu dosen ini?
    const row = db.prepare(`
      SELECT n.id, n.kelas_id, n.is_final as nilai_final, k.dosen_id, k.is_final as kelas_final, k.nama as nama_kelas
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.id = ?
    `).get(nilaiId);

    if (!row) {
      const reason = `Data nilai dengan ID ${nilaiId} tidak ditemukan`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(404).json({ error: 'NOT_FOUND', policyResult: 'DENY', reason });
    }

    const currentDosenId = Number(decoded.id || decoded.sub);
    if (Number(row.dosen_id) !== currentDosenId) {
      const reason = `Pelanggaran Object-Level Authorization (IDOR): Dosen [${decoded.username}] bukan pengampu kelas [${row.nama_kelas}]`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({ error: 'OBJECT_ACCESS_DENIED', policyResult: 'DENY', reason });
    }

    if (row.kelas_final === 1 || row.nilai_final === 1) {
      const reason = `Nilai ID ${nilaiId} sudah difinalisasi dan tidak dapat diubah lagi`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({ error: 'ALREADY_FINALIZED', policyResult: 'DENY', reason });
    }

    const reason = `Diizinkan: Dosen [${decoded.username}] memperbarui nilai ID [${nilaiId}] pada kelas [${row.nama_kelas}]`;
    logAudit({ subject, endpoint, deviceId, result: 'ALLOW', reason });
    return next();
  }

  // C. POST /kelas/:id/finalisasi
  const finalisasiMatch = req.path.match(/^\/kelas\/(\d+)\/finalisasi$/);
  if (req.method === 'POST' && finalisasiMatch) {
    if (role !== 'dosen') {
      const reason = `Hanya role dosen yang dapat memfinalisasi nilai kelas (Role pemohon: ${role})`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({ error: 'FORBIDDEN', policyResult: 'DENY', reason });
    }

    const kelasId = parseInt(finalisasiMatch[1], 10);
    const kelasRow = db.prepare('SELECT * FROM kelas WHERE id = ?').get(kelasId);

    if (!kelasRow) {
      const reason = `Kelas dengan ID ${kelasId} tidak ditemukan`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(404).json({ error: 'NOT_FOUND', policyResult: 'DENY', reason });
    }

    const currentDosenId = Number(decoded.id || decoded.sub);
    if (Number(kelasRow.dosen_id) !== currentDosenId) {
      const reason = `Dosen [${decoded.username}] bukan pengampu kelas [${kelasRow.nama}] (IDOR terdeteksi)`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({ error: 'OBJECT_ACCESS_DENIED', policyResult: 'DENY', reason });
    }

    if (kelasRow.is_final === 1) {
      const reason = `Kelas [${kelasRow.nama}] sudah difinalisasi sebelumnya`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(400).json({ error: 'ALREADY_FINALIZED', policyResult: 'DENY', reason });
    }

    const reason = `Diizinkan: Dosen [${decoded.username}] memfinalisasi kelas [${kelasRow.nama}]`;
    logAudit({ subject, endpoint, deviceId, result: 'ALLOW', reason });
    return next();
  }

  // D. GET /transkrip/:nim
  const transkripMatch = req.path.match(/^\/transkrip\/([a-zA-Z0-9_-]+)$/);
  if (req.method === 'GET' && transkripMatch) {
    const requestedNim = transkripMatch[1];

    if (role === 'admin') {
      const reason = `Diizinkan: Admin [${decoded.username}] melihat transkrip NIM [${requestedNim}]`;
      logAudit({ subject, endpoint, deviceId, result: 'ALLOW', reason });
      return next();
    }

    if (role === 'mahasiswa') {
      if (decoded.nim === requestedNim) {
        const reason = `Diizinkan: Mahasiswa [${decoded.username}] melihat transkrip miliknya sendiri (NIM: ${requestedNim})`;
        logAudit({ subject, endpoint, deviceId, result: 'ALLOW', reason });
        return next();
      }
      const reason = `Akses ditolak: Mahasiswa NIM [${decoded.nim}] mencoba mengakses transkrip NIM lain [${requestedNim}]`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({ error: 'UNAUTHORIZED_STUDENT_TRANSCRIPT', policyResult: 'DENY', reason });
    }

    const reason = `Role [${role}] tidak memiliki hak untuk mengakses transkrip`;
    logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
    return res.status(403).json({ error: 'FORBIDDEN', policyResult: 'DENY', reason });
  }

  // E. POST /transkrip/sinkron
  if (req.method === 'POST' && req.path === '/transkrip/sinkron') {
    if (role !== 'service') {
      const reason = `Akses ditolak: POST /transkrip/sinkron hanya dapat dipanggil menggunakan Token Service. Token yang digunakan ber-role [${role}]`;
      logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
      return res.status(403).json({
        error: 'SERVICE_TOKEN_REQUIRED',
        policyResult: 'DENY',
        reason
      });
    }

    const reason = `Diizinkan: Token Service [${subject}] melakukan sinkronisasi transkrip`;
    logAudit({ subject, endpoint, deviceId: '-', result: 'ALLOW', reason });
    return next();
  }

  // Jika ada endpoint lain yang tidak dikenal
  const reason = `Endpoint [${endpoint}] tidak diizinkan oleh kebijakan API Gateway`;
  logAudit({ subject, endpoint, deviceId, result: 'DENY', reason });
  return res.status(404).json({ error: 'ROUTE_NOT_PERMITTED', policyResult: 'DENY', reason });
}

module.exports = {
  evaluatePolicy
};
