const express = require('express');
const cors = require('cors');
const config = require('../../config');
const { getDb } = require('../../db');
const { verifyGatewayAndToken } = require('../commonAuthMiddleware');

const app = express();

app.use(cors());
app.use(express.json());

// Pasang middleware Zero Trust Defense-in-Depth
app.use(verifyGatewayAndToken);

function hitungNilai(tugas, uts, uas) {
  const akhir = (tugas * 0.3) + (uts * 0.3) + (uas * 0.4);
  const bulat = Math.round(akhir * 10) / 10;
  let huruf = 'E';
  if (bulat >= 85) huruf = 'A';
  else if (bulat >= 75) huruf = 'B+';
  else if (bulat >= 70) huruf = 'B';
  else if (bulat >= 65) huruf = 'C+';
  else if (bulat >= 55) huruf = 'C';
  else if (bulat >= 45) huruf = 'D';

  return { nilaiAkhir: bulat, hurufMutu: huruf };
}

// 1. GET /nilai
// Mahasiswa: hanya nilai miliknya.
// Dosen: hanya kelas yang diampu.
app.get('/nilai', (req, res) => {
  const db = getDb();
  const role = req.user.role;
  const userId = req.user.id || req.user.sub;

  if (role === 'mahasiswa') {
    const rows = db.prepare(`
      SELECT 
        n.id as nilai_id,
        n.kelas_id,
        k.kode as kode_mk,
        k.nama as nama_mk,
        k.sks,
        d.nama as nama_dosen,
        n.tugas,
        n.uts,
        n.uas,
        n.nilai_akhir,
        n.huruf_mutu,
        n.is_final,
        n.updated_at
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      JOIN users d ON k.dosen_id = d.id
      WHERE n.mahasiswa_id = ?
      ORDER BY k.id ASC
    `).all(userId);

    return res.json({
      role: 'mahasiswa',
      nim: req.user.nim,
      nama: req.user.nama,
      totalData: rows.length,
      data: rows
    });
  }

  if (role === 'dosen') {
    const rows = db.prepare(`
      SELECT 
        n.id as nilai_id,
        n.kelas_id,
        k.kode as kode_mk,
        k.nama as nama_mk,
        k.sks,
        m.id as mahasiswa_id,
        m.nim,
        m.nama as nama_mahasiswa,
        n.tugas,
        n.uts,
        n.uas,
        n.nilai_akhir,
        n.huruf_mutu,
        n.is_final,
        k.is_final as kelas_final,
        n.updated_at
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      JOIN users m ON n.mahasiswa_id = m.id
      WHERE k.dosen_id = ?
      ORDER BY k.id ASC, m.nim ASC
    `).all(userId);

    return res.json({
      role: 'dosen',
      dosen: req.user.nama,
      nidn: req.user.nidn,
      totalData: rows.length,
      data: rows
    });
  }

  return res.status(403).json({ error: 'FORBIDDEN', message: 'Role tidak diizinkan mengakses data nilai' });
});

// 2. PUT /nilai/:id
// Dosen mengubah nilai kelas yang diampu
app.put('/nilai/:id', (req, res) => {
  const db = getDb();
  const nilaiId = parseInt(req.params.id, 10);
  const { tugas, uts, uas } = req.body || {};

  const current = db.prepare('SELECT * FROM nilai WHERE id = ?').get(nilaiId);
  if (!current) {
    return res.status(404).json({ error: 'NOT_FOUND', message: 'Data nilai tidak ditemukan' });
  }

  if (current.is_final === 1) {
    return res.status(403).json({ error: 'ALREADY_FINALIZED', message: 'Nilai sudah berstatus final dan tidak dapat diubah' });
  }

  const newTugas = tugas !== undefined ? parseFloat(tugas) : current.tugas;
  const newUts = uts !== undefined ? parseFloat(uts) : current.uts;
  const newUas = uas !== undefined ? parseFloat(uas) : current.uas;

  const { nilaiAkhir, hurufMutu } = hitungNilai(newTugas, newUts, newUas);
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE nilai 
    SET tugas = ?, uts = ?, uas = ?, nilai_akhir = ?, huruf_mutu = ?, updated_at = ?
    WHERE id = ?
  `).run(newTugas, newUts, newUas, nilaiAkhir, hurufMutu, now, nilaiId);

  const updated = db.prepare(`
    SELECT n.*, m.nama as nama_mahasiswa, m.nim, k.nama as nama_mk
    FROM nilai n
    JOIN users m ON n.mahasiswa_id = m.id
    JOIN kelas k ON n.kelas_id = k.id
    WHERE n.id = ?
  `).get(nilaiId);

  return res.json({
    message: 'Nilai berhasil diupdate oleh dosen',
    data: updated
  });
});

// 3. POST /kelas/:id/finalisasi
// Dosen memfinalisasi kelas yang diampu, lalu memanggil sinkron transkrip melalui gateway menggunakan token service
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const db = getDb();
  const kelasId = parseInt(req.params.id, 10);
  const now = new Date().toISOString();

  const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(kelasId);
  if (!kelas) {
    return res.status(404).json({ error: 'NOT_FOUND', message: 'Kelas tidak ditemukan' });
  }

  if (kelas.is_final === 1) {
    return res.status(400).json({ error: 'ALREADY_FINALIZED', message: 'Kelas sudah difinalisasi sebelumnya' });
  }

  // 1. Update status kelas dan nilai menjadi final
  db.prepare('UPDATE kelas SET is_final = 1, finalized_at = ? WHERE id = ?').run(now, kelasId);
  db.prepare('UPDATE nilai SET is_final = 1, updated_at = ? WHERE id = ?').run(now, kelasId);

  // 2. Ambil seluruh data nilai mahasiswa pada kelas ini
  const nilaiRows = db.prepare(`
    SELECT n.*, m.nim, m.nama as nama_mahasiswa, k.kode as kode_mk, k.nama as nama_mk, k.sks
    FROM nilai n
    JOIN users m ON n.mahasiswa_id = m.id
    JOIN kelas k ON n.kelas_id = k.id
    WHERE n.kelas_id = ?
  `).all(kelasId);

  // 3. Panggilan Antar-Service Sesuai NIST SP 800-207:
  // Service Nilai TIDAK BISA memanggil Service Transkrip secara langsung.
  // Service Nilai harus:
  // a. Meminta Service Token ke Gateway (POST /auth/service)
  // b. Memanggil endpoint /transkrip/sinkron melalui API Gateway (port 3000) dengan header Authorization Bearer service token.
  let syncResult = null;
  try {
    console.log(`[SERVICE_NILAI] Meminta token service ke Gateway (POST /auth/service)...`);
    const authServiceRes = await fetch(`http://localhost:${config.ports.gateway}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientId: config.serviceCredentials.clientId,
        clientSecret: config.serviceCredentials.clientSecret
      })
    });

    if (!authServiceRes.ok) {
      const errBody = await authServiceRes.text();
      throw new Error(`Gagal memperoleh service token dari Gateway: ${errBody}`);
    }

    const { accessToken: serviceToken } = await authServiceRes.json();
    console.log(`[SERVICE_NILAI] Token service diperoleh. Mengirim data sinkronisasi ke Gateway (POST /transkrip/sinkron)...`);

    // Panggil Service Transkrip melalui Gateway
    const syncRes = await fetch(`http://localhost:${config.ports.gateway}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`
      },
      body: JSON.stringify({
        kelasId: kelas.id,
        kodeMk: kelas.kode,
        namaMk: kelas.nama,
        sks: kelas.sks,
        nilaiList: nilaiRows.map(r => ({
          mahasiswaId: r.mahasiswa_id,
          nim: r.nim,
          nilaiAngka: r.nilai_akhir,
          nilaiHuruf: r.huruf_mutu
        }))
      })
    });

    syncResult = await syncRes.json();
    console.log(`[SERVICE_NILAI] Sinkronisasi transkrip berhasil direspon oleh Gateway.`);
  } catch (err) {
    console.error(`[SERVICE_NILAI_ERROR] Panggilan sinkron transkrip gagal:`, err.message);
    return res.status(500).json({
      error: 'SYNC_ERROR',
      message: `Finalisasi nilai tersimpan, namun sinkronisasi ke Service Transkrip via Gateway gagal: ${err.message}`
    });
  }

  return res.json({
    message: `Kelas [${kelas.nama}] berhasil difinalisasi dan nilai otomatis disinkronkan ke Service Transkrip melalui API Gateway`,
    kelasId: kelas.id,
    jumlahMahasiswa: nilaiRows.length,
    syncResult
  });
});

function startServiceNilai() {
  return new Promise((resolve) => {
    const server = app.listen(config.ports.nilai, () => {
      console.log(`[SERVICE NILAI] Service Nilai (Resource) aktif berjalan di port http://localhost:${config.ports.nilai}`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  startServiceNilai();
}

module.exports = { app, startServiceNilai };
