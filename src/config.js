require('dotenv').config();
const path = require('path');

module.exports = {
  ports: {
    gateway: parseInt(process.env.PORT_GATEWAY, 10) || 3000,
    nilai: parseInt(process.env.PORT_NILAI, 10) || 3001,
    transkrip: parseInt(process.env.PORT_TRANSKRIP, 10) || 3002
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'zero-trust-jwt-super-secret-key-2024',
    accessExpires: '10m',
    refreshExpiresDays: 1,
    serviceExpires: '5m'
  },
  gatewaySecret: process.env.GATEWAY_SECRET || 'pep-gateway-internal-secret-token-xyz',
  serviceCredentials: {
    clientId: process.env.SERVICE_NILAI_CLIENT_ID || 'service-nilai',
    clientSecret: process.env.SERVICE_NILAI_CLIENT_SECRET || 'secret-nilai-client-2024'
  },
  accessHours: {
    start: parseInt(process.env.ACCESS_HOURS_START, 10) ?? 7,
    end: parseInt(process.env.ACCESS_HOURS_END, 10) ?? 21,
    bypassForTest: process.env.BYPASS_ACCESS_HOURS === '1'
  },
  dbPath: path.resolve(process.env.DB_PATH || './data/database.sqlite')
};
