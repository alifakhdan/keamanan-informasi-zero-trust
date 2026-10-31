const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');
const config = require('../config');

// Pastikan folder data tersedia
const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

let dbInstance = null;

function getDb() {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(config.dbPath);
    initTables(dbInstance);
  }
  return dbInstance;
}

function initTables(db) {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      nama TEXT NOT NULL,
      nim TEXT UNIQUE,
      nidn TEXT UNIQUE
    );

    CREATE TABLE IF NOT EXISTS registered_devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT,
      is_active INTEGER DEFAULT 1,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      revoked INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS service_clients (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      service_name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS kelas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kode TEXT NOT NULL,
      nama TEXT NOT NULL,
      sks INTEGER NOT NULL DEFAULT 3,
      dosen_id INTEGER NOT NULL,
      is_final INTEGER DEFAULT 0,
      finalized_at TEXT,
      FOREIGN KEY (dosen_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS nilai (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kelas_id INTEGER NOT NULL,
      mahasiswa_id INTEGER NOT NULL,
      tugas REAL DEFAULT 0,
      uts REAL DEFAULT 0,
      uas REAL DEFAULT 0,
      nilai_akhir REAL DEFAULT 0,
      huruf_mutu TEXT DEFAULT 'E',
      is_final INTEGER DEFAULT 0,
      updated_at TEXT,
      FOREIGN KEY (kelas_id) REFERENCES kelas(id),
      FOREIGN KEY (mahasiswa_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS transkrip (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL,
      nim TEXT NOT NULL,
      kelas_id INTEGER NOT NULL,
      kode_mk TEXT NOT NULL,
      nama_mk TEXT NOT NULL,
      sks INTEGER NOT NULL,
      nilai_angka REAL NOT NULL,
      nilai_huruf TEXT NOT NULL,
      synced_at TEXT NOT NULL,
      FOREIGN KEY (mahasiswa_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      subject TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      device_id TEXT,
      result TEXT NOT NULL,
      reason TEXT NOT NULL
    );
  `);
}

module.exports = {
  getDb
};
