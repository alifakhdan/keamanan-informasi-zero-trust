const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Middleware Pertahanan Berlapis (Defense in Depth) untuk Resource Services
 * Memastikan:
 * 1. Gateway Secret valid (Layanan tidak bisa diakses langsung membypass Gateway).
 * 2. Token JWT valid dan belum kadaluarsa (Service tidak percaya begitu saja, tetap verifikasi ulang tanda tangan).
 */
function verifyGatewayAndToken(req, res, next) {
  // 1. Verifikasi Gateway Secret
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!gatewaySecret || gatewaySecret !== config.gatewaySecret) {
    return res.status(403).json({
      error: 'DIRECT_ACCESS_FORBIDDEN',
      message: 'Akses langsung ditolak: Header X-Gateway-Secret tidak valid atau tidak disertakan. Semua akses wajib melalui API Gateway.'
    });
  }

  // 2. Verifikasi Ulang Token JWT (Defense in Depth)
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'MISSING_TOKEN_AT_RESOURCE',
      message: 'Defense in Depth: Header Authorization Bearer token wajib ada di level resource service'
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({
      error: 'INVALID_TOKEN_AT_RESOURCE',
      message: `Defense in Depth: Token tidak sah atau kadaluarsa di level resource service (${err.message})`
    });
  }
}

module.exports = {
  verifyGatewayAndToken
};
