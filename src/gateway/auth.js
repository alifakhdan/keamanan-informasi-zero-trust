const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { getDb } = require('../db');
const { logAudit } = require('./audit');

const router = express.Router();

// 1. POST /auth/login
// Kredensial valid dan device terdaftar
router.post('/login', (req, res) => {
  const db = getDb();
  const endpoint = 'POST /auth/login';
  const { username, password } = req.body || {};
  const deviceId = req.headers['x-device-id'];

  if (!username || !password) {
    const reason = 'Username dan password wajib diisi';
    logAudit({ subject: username || 'anonymous', endpoint, deviceId, result: 'DENY', reason });
    return res.status(400).json({ error: 'BAD_REQUEST', reason });
  }

  // Cari user di database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || user.password !== password) {
    const reason = 'Kredensial login (username/password) tidak valid';
    logAudit({ subject: username, endpoint, deviceId, result: 'DENY', reason });
    return res.status(401).json({ error: 'INVALID_CREDENTIALS', reason });
  }

  // Verifikasi Konteks: Device wajib disertakan dan terdaftar untuk user
  if (!deviceId) {
    const reason = 'Header X-Device-ID wajib disertakan saat login';
    logAudit({ subject: username, endpoint, deviceId: '-', result: 'DENY', reason });
    return res.status(403).json({ error: 'DEVICE_ID_REQUIRED', reason });
  }

  const device = db.prepare(`
    SELECT * FROM registered_devices 
    WHERE user_id = ? AND device_id = ? AND is_active = 1
  `).get(user.id, deviceId);

  if (!device) {
    const reason = `Device [${deviceId}] tidak terdaftar untuk akun [${username}]`;
    logAudit({ subject: username, endpoint, deviceId, result: 'DENY', reason });
    return res.status(403).json({ error: 'UNREGISTERED_DEVICE', reason });
  }

  // Buat Access Token (10 menit)
  const payload = {
    sub: user.id,
    id: user.id,
    username: user.username,
    role: user.role,
    nama: user.nama,
    nim: user.nim,
    nidn: user.nidn
  };

  const accessToken = jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.accessExpires
  });

  // Buat Refresh Token (1 hari, disimpan di DB)
  const refreshToken = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens (token, user_id, expires_at, revoked, created_at)
    VALUES (?, ?, ?, 0, ?)
  `).run(refreshToken, user.id, expiresAt, now.toISOString());

  const reason = `Login berhasil dari perangkat terdaftar [${deviceId}]`;
  logAudit({ subject: username, endpoint, deviceId, result: 'ALLOW', reason });

  return res.json({
    message: 'Login berhasil',
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: config.jwt.accessExpires,
    user: {
      id: user.id,
      username: user.username,
      nama: user.nama,
      role: user.role,
      nim: user.nim,
      nidn: user.nidn
    }
  });
});

// 2. POST /auth/refresh
// Refresh token valid dan belum dicabut
router.post('/refresh', (req, res) => {
  const db = getDb();
  const endpoint = 'POST /auth/refresh';
  const { refreshToken } = req.body || {};
  const deviceId = req.headers['x-device-id'] || '-';

  if (!refreshToken) {
    const reason = 'refreshToken wajib disertakan pada body';
    logAudit({ subject: 'anonymous', endpoint, deviceId, result: 'DENY', reason });
    return res.status(400).json({ error: 'BAD_REQUEST', reason });
  }

  const tokenRecord = db.prepare(`
    SELECT rt.*, u.username, u.role, u.nama, u.nim, u.nidn
    FROM refresh_tokens rt
    JOIN users u ON rt.user_id = u.id
    WHERE rt.token = ?
  `).get(refreshToken);

  if (!tokenRecord) {
    const reason = 'Refresh token tidak ditemukan di database';
    logAudit({ subject: 'anonymous', endpoint, deviceId, result: 'DENY', reason });
    return res.status(401).json({ error: 'INVALID_REFRESH_TOKEN', reason });
  }

  if (tokenRecord.revoked === 1) {
    const reason = `Refresh token telah dicabut (revoked) untuk user [${tokenRecord.username}]`;
    logAudit({ subject: tokenRecord.username, endpoint, deviceId, result: 'DENY', reason });
    return res.status(401).json({ error: 'TOKEN_REVOKED', reason });
  }

  if (new Date(tokenRecord.expires_at) < new Date()) {
    const reason = `Refresh token telah kadaluarsa untuk user [${tokenRecord.username}]`;
    logAudit({ subject: tokenRecord.username, endpoint, deviceId, result: 'DENY', reason });
    return res.status(401).json({ error: 'TOKEN_EXPIRED', reason });
  }

  // Terbitkan access token baru
  const payload = {
    sub: tokenRecord.user_id,
    id: tokenRecord.user_id,
    username: tokenRecord.username,
    role: tokenRecord.role,
    nama: tokenRecord.nama,
    nim: tokenRecord.nim,
    nidn: tokenRecord.nidn
  };

  const newAccessToken = jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.accessExpires
  });

  const reason = `Access token diperbarui menggunakan refresh token untuk user [${tokenRecord.username}]`;
  logAudit({ subject: tokenRecord.username, endpoint, deviceId, result: 'ALLOW', reason });

  return res.json({
    message: 'Token berhasil di-refresh',
    accessToken: newAccessToken,
    tokenType: 'Bearer',
    expiresIn: config.jwt.accessExpires
  });
});

// 3. POST /auth/logout
// Logout mencabut refresh token
router.post('/logout', (req, res) => {
  const db = getDb();
  const endpoint = 'POST /auth/logout';
  const { refreshToken } = req.body || {};
  const deviceId = req.headers['x-device-id'] || '-';

  if (!refreshToken) {
    const reason = 'refreshToken wajib disertakan pada body logout';
    logAudit({ subject: 'anonymous', endpoint, deviceId, result: 'DENY', reason });
    return res.status(400).json({ error: 'BAD_REQUEST', reason });
  }

  const tokenRecord = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refreshToken);
  if (tokenRecord) {
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(refreshToken);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(tokenRecord.user_id);
    const username = user ? user.username : 'user';
    const reason = `Logout berhasil: refresh token dicabut untuk user [${username}]`;
    logAudit({ subject: username, endpoint, deviceId, result: 'ALLOW', reason });
  } else {
    logAudit({ subject: 'anonymous', endpoint, deviceId, result: 'ALLOW', reason: 'Logout request diproses' });
  }

  return res.json({
    message: 'Logout berhasil, refresh token telah dicabut'
  });
});

// 4. POST /auth/service
// Service Nilai memperoleh token menggunakan client ID dan secret. Berlaku 5 menit dengan role: service.
router.post('/service', (req, res) => {
  const db = getDb();
  const endpoint = 'POST /auth/service';
  const { clientId, clientSecret } = req.body || {};

  if (!clientId || !clientSecret) {
    const reason = 'clientId dan clientSecret wajib disertakan';
    logAudit({ subject: clientId || 'unknown-service', endpoint, deviceId: '-', result: 'DENY', reason });
    return res.status(400).json({ error: 'BAD_REQUEST', reason });
  }

  const client = db.prepare('SELECT * FROM service_clients WHERE client_id = ?').get(clientId);
  if (!client || client.client_secret !== clientSecret) {
    const reason = `Kredensial client ID atau secret tidak valid untuk service [${clientId}]`;
    logAudit({ subject: clientId, endpoint, deviceId: '-', result: 'DENY', reason });
    return res.status(401).json({ error: 'INVALID_SERVICE_CREDENTIALS', reason });
  }

  // Buat Token Service dengan role: service (berlaku 5 menit)
  const payload = {
    sub: client.client_id,
    serviceName: client.service_name,
    role: 'service'
  };

  const serviceToken = jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.serviceExpires
  });

  const reason = `Token service berhasil diterbitkan untuk [${client.client_id}]`;
  logAudit({ subject: client.client_id, endpoint, deviceId: '-', result: 'ALLOW', reason });

  return res.json({
    message: 'Service token berhasil diterbitkan',
    accessToken: serviceToken,
    tokenType: 'Bearer',
    expiresIn: config.jwt.serviceExpires,
    role: 'service'
  });
});

module.exports = router;
