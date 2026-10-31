const express = require('express');
const cors = require('cors');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const config = require('../config');
const authRouter = require('./auth');
const { evaluatePolicy } = require('./policy');
const { getRecentAuditLogs } = require('./audit');

const app = express();

app.use(cors());
app.use(express.json());

// Banner awal
console.log('\x1b[36m%s\x1b[0m', '=====================================================');
console.log('\x1b[36m%s\x1b[0m', '   ZERO TRUST ARCHITECTURE - API GATEWAY (PEP / PDP) ');
console.log('\x1b[36m%s\x1b[0m', '   NIST SP 800-207 Policy Enforcement Point          ');
console.log('\x1b[36m%s\x1b[0m', '=====================================================');

// 1. Modul Policy Administrator (Auth Routes)
app.use('/auth', authRouter);

// 2. Monitoring Endpoint untuk Audit Logs (Dapat diakses untuk demo audit log)
app.get('/audit-logs', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 50;
  const logs = getRecentAuditLogs(limit);
  res.json({ total: logs.length, logs });
});

// 3. Status Health Check Gateway
app.get('/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    role: 'Policy Enforcement Point (PEP) & Policy Decision Point (PDP)',
    port: config.ports.gateway,
    timestamp: new Date().toISOString()
  });
});

// 4. Policy Enforcement Point (PEP) Middleware untuk semua request ke resource
app.use(evaluatePolicy);

// 5. Proxy ke Service Nilai (Port 3001) untuk /nilai dan /kelas
const nilaiProxy = createProxyMiddleware({
  target: `http://localhost:${config.ports.nilai}`,
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req, res) => {
      // Zero Trust: Gateway menyertakan X-Gateway-Secret
      proxyReq.setHeader('X-Gateway-Secret', config.gatewaySecret);

      // Teruskan header identitas untuk memudahkan service
      if (req.user) {
        proxyReq.setHeader('X-User-Sub', String(req.user.sub || req.user.id));
        proxyReq.setHeader('X-User-Role', String(req.user.role));
        if (req.user.nim) proxyReq.setHeader('X-User-Nim', String(req.user.nim));
        if (req.user.nidn) proxyReq.setHeader('X-User-Nidn', String(req.user.nidn));
      }

      // Pastikan body yang telah diparse Express diteruskan ke service target
      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[GATEWAY_PROXY_ERROR] Service Nilai unavailable:', err.message);
      res.status(502).json({
        error: 'BAD_GATEWAY',
        message: 'Service Nilai (port 3001) sedang tidak dapat dihubungi'
      });
    }
  }
});

// 6. Proxy ke Service Transkrip (Port 3002) untuk /transkrip
const transkripProxy = createProxyMiddleware({
  target: `http://localhost:${config.ports.transkrip}`,
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req, res) => {
      // Zero Trust: Gateway menyertakan X-Gateway-Secret
      proxyReq.setHeader('X-Gateway-Secret', config.gatewaySecret);

      if (req.user) {
        proxyReq.setHeader('X-User-Sub', String(req.user.sub || req.user.id));
        proxyReq.setHeader('X-User-Role', String(req.user.role));
        if (req.user.nim) proxyReq.setHeader('X-User-Nim', String(req.user.nim));
      }

      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[GATEWAY_PROXY_ERROR] Service Transkrip unavailable:', err.message);
      res.status(502).json({
        error: 'BAD_GATEWAY',
        message: 'Service Transkrip (port 3002) sedang tidak dapat dihubungi'
      });
    }
  }
});

// Daftarkan rute proxy tanpa stripping URL path
app.use((req, res, next) => {
  if (req.path.startsWith('/nilai') || req.path.startsWith('/kelas')) {
    return nilaiProxy(req, res, next);
  }
  if (req.path.startsWith('/transkrip')) {
    return transkripProxy(req, res, next);
  }
  next();
});

// 404 handler fallback
app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', message: 'Route tidak ditemukan di API Gateway' });
});

function startGateway() {
  return new Promise((resolve) => {
    const server = app.listen(config.ports.gateway, () => {
      console.log(`[GATEWAY] API Gateway (PEP) aktif berjalan di port http://localhost:${config.ports.gateway}`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  startGateway();
}

module.exports = { app, startGateway };
