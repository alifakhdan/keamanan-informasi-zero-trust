const { getDb } = require('../db');

function logAudit({ subject, endpoint, deviceId, result, reason }) {
  try {
    const db = getDb();
    const timestamp = new Date().toISOString();
    const sub = subject || 'anonymous';
    const dev = deviceId || '-';
    const res = result || 'DENY';
    const rsn = reason || '-';

    const stmt = db.prepare(`
      INSERT INTO audit_logs (timestamp, subject, endpoint, device_id, result, reason)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(timestamp, sub, endpoint, dev, res, rsn);

    // Live terminal log formatted like Zero Trust PDP Monitor
    const colorTag = res === 'ALLOW' ? '\x1b[32m[ ALLOW ]\x1b[0m' : '\x1b[31m[ DENY  ]\x1b[0m';
    console.log(`${colorTag} ${timestamp} | sub:${sub} | dev:${dev} | ${endpoint} -> ${rsn}`);
  } catch (err) {
    console.error('[AUDIT_ERROR] Failed to record audit log:', err.message);
  }
}

function getRecentAuditLogs(limit = 50) {
  const db = getDb();
  return db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?').all(limit);
}

module.exports = {
  logAudit,
  getRecentAuditLogs
};
