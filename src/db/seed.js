const { getDb } = require('./index');
const config = require('../config');

function seedDatabase() {
  const db = getDb();
  console.log('[SEED] Memulai seeding database Zero Trust...');

  // Bersihkan data lama
  db.exec(`
    DELETE FROM transkrip;
    DELETE FROM nilai;
    DELETE FROM kelas;
    DELETE FROM refresh_tokens;
    DELETE FROM registered_devices;
    DELETE FROM service_clients;
    DELETE FROM users;
    DELETE FROM audit_logs;
    DELETE FROM sqlite_sequence WHERE name IN ('users', 'kelas', 'nilai', 'transkrip', 'refresh_tokens', 'registered_devices', 'audit_logs');
  `);

  // 1. Seed Users (1 Admin, 2 Dosen, 3 Mahasiswa)
  const insertUser = db.prepare(`
    INSERT INTO users (username, password, role, nama, nim, nidn)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  insertUser.run('admin', 'password123', 'admin', 'Administrator Sistem', null, null);
  insertUser.run('dosen_budi', 'password123', 'dosen', 'Dr. Budi Santoso, M.Kom.', null, '0401018501');
  insertUser.run('dosen_siti', 'password123', 'dosen', 'Siti Aminah, M.T.', null, '0402028802');
  insertUser.run('mhs_ahmad', 'password123', 'mahasiswa', 'Ahmad Pratama', '220001', null);
  insertUser.run('mhs_dewi', 'password123', 'mahasiswa', 'Dewi Lestari', '220002', null);
  insertUser.run('mhs_rian', 'password123', 'mahasiswa', 'Rian Hidayat', '220003', null);

  const users = db.prepare('SELECT id, username, role FROM users').all();
  const userMap = {};
  for (const u of users) {
    userMap[u.username] = u.id;
  }

  // 2. Seed Registered Devices (Setiap user memiliki 1 device terdaftar)
  const insertDevice = db.prepare(`
    INSERT INTO registered_devices (user_id, device_id, device_name)
    VALUES (?, ?, ?)
  `);

  insertDevice.run(userMap['admin'], 'DEV-ADMIN-01', 'Workstation Admin Ruang Server');
  insertDevice.run(userMap['dosen_budi'], 'DEV-DOSEN-01', 'ThinkPad Kampus Dr. Budi');
  insertDevice.run(userMap['dosen_siti'], 'DEV-DOSEN-02', 'MacBook Air Dosen Siti');
  insertDevice.run(userMap['mhs_ahmad'], 'DEV-MHS-01', 'Laptop Pribadi Ahmad');
  insertDevice.run(userMap['mhs_dewi'], 'DEV-MHS-02', 'Laptop Pribadi Dewi');
  insertDevice.run(userMap['mhs_rian'], 'DEV-MHS-03', 'PC Rumah Rian');

  // 3. Seed Service Client untuk Service Nilai
  const insertServiceClient = db.prepare(`
    INSERT INTO service_clients (client_id, client_secret, service_name)
    VALUES (?, ?, ?)
  `);
  insertServiceClient.run(
    config.serviceCredentials.clientId,
    config.serviceCredentials.clientSecret,
    'Service Nilai (Resource Port 3001)'
  );

  // 4. Seed Kelas (2 Kelas dengan dosen berbeda)
  const insertKelas = db.prepare(`
    INSERT INTO kelas (kode, nama, sks, dosen_id, is_final)
    VALUES (?, ?, ?, ?, ?)
  `);

  const kelas1 = insertKelas.run('IF-301', 'Keamanan Informasi', 3, userMap['dosen_budi'], 0);
  const kelas2 = insertKelas.run('IF-302', 'Sistem Terdistribusi', 3, userMap['dosen_siti'], 0);

  const kelas1Id = Number(kelas1.lastInsertRowid);
  const kelas2Id = Number(kelas2.lastInsertRowid);

  // 5. Seed Nilai Awal untuk 3 Mahasiswa di kedua kelas
  const insertNilai = db.prepare(`
    INSERT INTO nilai (kelas_id, mahasiswa_id, tugas, uts, uas, nilai_akhir, huruf_mutu, is_final, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const nowIso = new Date().toISOString();

  // Kelas 1 (Dr. Budi - Keamanan Informasi)
  insertNilai.run(kelas1Id, userMap['mhs_ahmad'], 85, 80, 88, 84.4, 'A', 0, nowIso);
  insertNilai.run(kelas1Id, userMap['mhs_dewi'], 75, 78, 80, 77.9, 'B+', 0, nowIso);
  insertNilai.run(kelas1Id, userMap['mhs_rian'], 70, 65, 70, 68.5, 'B', 0, nowIso);

  // Kelas 2 (Siti Aminah - Sistem Terdistribusi)
  insertNilai.run(kelas2Id, userMap['mhs_ahmad'], 90, 85, 90, 88.5, 'A', 0, nowIso);
  insertNilai.run(kelas2Id, userMap['mhs_dewi'], 82, 80, 85, 82.5, 'A', 0, nowIso);
  insertNilai.run(kelas2Id, userMap['mhs_rian'], 78, 75, 80, 77.7, 'B+', 0, nowIso);

  console.log('[SEED] Seeding selesai dengan sukses!');
  console.log('       - 1 Admin, 2 Dosen, 3 Mahasiswa');
  console.log('       - 6 Perangkat terdaftar (1 per user)');
  console.log('       - 1 Service Client (Service Nilai)');
  console.log('       - 2 Kelas & 6 Data Nilai siap diuji');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
