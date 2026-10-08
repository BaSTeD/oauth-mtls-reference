import { createAuthServer, loadFiles } from './server.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env.example)`);
  return value;
}

const port = Number(process.env.PORT ?? 8443);

const server = createAuthServer({
  issuer: process.env.ISSUER ?? 'https://auth-server:8443',
  resource: process.env.RESOURCE ?? 'https://resource-server:8443',
  redirectUri: process.env.REDIRECT_URI ?? 'https://demo-client.localhost/callback',
  cookieSecret: required('COOKIE_SECRET'),
  demoUser: { username: required('DEMO_USERNAME'), password: required('DEMO_PASSWORD') },
  ...loadFiles(process.env.CERT_DIR ?? './certs'),
});

server.listen(port, () => console.log(`authorization server listening on :${port}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
