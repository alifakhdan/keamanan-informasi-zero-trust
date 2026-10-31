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

function getBobotHuruf(huruf) {
  switch (huruf) {
    case 'A': return 4.0;
    case 'B+': return 3.5;
    case 'B': return 3.0;
    case 'C+': return 2.5;
    case 'C': return 2.0;
    case 'D': return 1.0;
    default: return 0.0;
  }
}

// 1. GET /transkrip/:nim
// Mahasiswa: hanya NIM sendiri. Admin: semua NIM.
app.get('/transkrip/:nim', (req, res) => {
  const db = getDb();
  const requestedNim = req.params.nim;

  // Cek apakah mahasiswa terdaftar
  const student = db.prepare("SELECT id, nama, nim FROM users WHERE nim = ? AND role = 'mahasiswa'").get(requestedNim);
  if (!student) {
    return res.status(404).json({ error: 'NOT_FOUND', message: `Mahasiswa dengan NIM ${requestedNim} tidak ditemukan` });
  }

  const items = db.prepare(`
    SELECT id, kelas_id, kode_mk, nama_mk, sks, nilai_angka, nilai_huruf, synced_at
    FROM transkrip
    WHERE nim = ?
    ORDER BY kode_mk ASC
  `).all(requestedNim);

  // Hitung total SKS dan Indeks Prestasi Kumulatif (IPK)
  let totalSks = 0;
  let totalBobotSks = 0;

  for (const item of items) {
    totalSks += item.sks;
    totalBobotSks += (item.sks * getBobotHuruf(item.nilai_huruf));
  }

  const ipk = totalSks > 0 ? Math.round((totalBobotSks / totalSks) * 100) / 100 : 0.0;

  return res.json({
    mahasiswa: {
      id: student.id,
      nama: student.nama,
      nim: student.nim
    },
    totalSks,
    ipk,
    totalMataKuliah: items.length,
    transkrip: items
  });
});

// 2. POST /transkrip/sinkron
// Hanya token service. Token user mana pun ditolak.
app.post('/transkrip/sinkron', (req, res) => {
  const role = req.user.role;
  if (role !== 'service') {
    return res.status(403).json({
      error: 'FORBIDDEN_SERVICE_ONLY',
      message: 'Defense in depth: Endpoint ini secara ketat hanya menerima panggilan dari Token Service'
    });
  }

  const db = getDb();
  const { kelasId, kodeMk, namaMk, sks, nilaiList } = req.body || {};

  if (!kelasId || !kodeMk || !namaMk || !Array.isArray(nilaiList)) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'Payload data sinkronisasi tidak lengkap' });
  }

  const now = new Date().toISOString();
  let insertOrUpdateCount = 0;

  const checkStmt = db.prepare('SELECT id FROM transkrip WHERE nim = ? AND kelas_id = ?');
  const updateStmt = db.prepare(`
    UPDATE transkrip 
    SET nilai_angka = ?, nilai_huruf = ?, synced_at = ?
    WHERE id = ?
  `);
  const insertStmt = db.prepare(`
    INSERT INTO transkrip (mahasiswa_id, nim, kelas_id, kode_mk, nama_mk, sks, nilai_angka, nilai_huruf, synced_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const item of nilaiList) {
    const existing = checkStmt.get(item.nim, kelasId);
    if (existing) {
      updateStmt.run(item.nilaiAngka, item.nilaiHuruf, now, existing.id);
    } else {
      insertStmt.run(
        item.mahasiswaId,
        item.nim,
        kelasId,
        kodeMk,
        namaMk,
        sks || 3,
        item.nilaiAngka,
        item.nilaiHuruf,
        now
      );
    }
    insertOrUpdateCount++;
  }

  console.log(`[SERVICE_TRANSKRIP] Berhasil menyinkronkan ${insertOrUpdateCount} nilai mahasiswa untuk kelas [${namaMk}]`);

  return res.json({
    success: true,
    message: `Berhasil menyinkronkan nilai kelas [${namaMk}] ke transkrip mahasiswa`,
    kelasId,
    syncedCount: insertOrUpdateCount,
    timestamp: now
  });
});

function startServiceTranskrip() {
  return new Promise((resolve) => {
    const server = app.listen(config.ports.transkrip, () => {
      console.log(`[SERVICE TRANSKRIP] Service Transkrip (Resource) aktif berjalan di port http://localhost:${config.ports.transkrip}`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  startServiceTranskrip();
}

module.exports = { app, startServiceTranskrip };
