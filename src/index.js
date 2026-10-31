const config = require('./config');
const { getDb } = require('./db');
const { seedDatabase } = require('./db/seed');
const { startGateway } = require('./gateway');
const { startServiceNilai } = require('./services/nilai');
const { startServiceTranskrip } = require('./services/transkrip');

async function main() {
  console.log('\n===============================================================');
  console.log('   MENJALANKAN SISTEM ZERO TRUST SECURITY - KEAMANAN INFORMASI');
  console.log('   Informatika Universitas Siliwangi                           ');
  console.log('===============================================================\n');

  // Pastikan database dan data awal (seed) tersedia
  const db = getDb();
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount === 0) {
    console.log('[INIT] Database kosong, melakukan seeding data awal...');
    seedDatabase();
  }

  // Jalankan ketiga komponen sistem
  await startServiceNilai();
  await startServiceTranskrip();
  await startGateway();

  console.log('\n===============================================================');
  console.log('   STATUS SISTEM: SEMUA KOMPONEN BERHASIL AKTIF               ');
  console.log(`   - API Gateway (PEP/PDP)   : http://localhost:${config.ports.gateway}`);
  console.log(`   - Service Nilai (Resource): http://localhost:${config.ports.nilai}`);
  console.log(`   - Service Transkrip (Res) : http://localhost:${config.ports.transkrip}`);
  console.log('===============================================================\n');
}

if (require.main === module) {
  main().catch(err => {
    console.error('Fatal Error starting Zero Trust system:', err);
    process.exit(1);
  });
}

module.exports = { main };
