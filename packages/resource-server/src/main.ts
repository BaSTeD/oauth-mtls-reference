import { createResourceServer, loadTls } from './server.js';

const port = Number(process.env.PORT ?? 8443);
const certDir = process.env.CERT_DIR ?? './certs';

const server = createResourceServer({
  issuer: process.env.ISSUER ?? 'https://auth-server:8443',
  audience: process.env.RESOURCE ?? 'https://resource-server:8443',
  requiredScope: 'accounts:read',
  algorithms: ['ES256', 'PS256'],
  tls: loadTls(certDir, 'resource-server'),
});

server.listen(port, () => console.log(`resource server listening on :${port}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
