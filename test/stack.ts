import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuthServer, loadFiles } from '../packages/auth-server/src/server.js';
import type { ClientConfig } from '../packages/demo-client/src/flow.js';
import type { TlsIdentity } from '../packages/demo-client/src/http.js';
import { createResourceServer, loadTls } from '../packages/resource-server/src/server.js';

const ROOT = join(import.meta.dirname, '..');
const USER = { username: 'alice', password: 'test-only-password' };

export interface Stack {
  certDir: string;
  client: ClientConfig;
  apiUrl: string;
  identity(name: string): TlsIdentity;
  /** Runs scripts/rotate-client.sh and returns the new client identity. */
  rotateClientCertificate(): TlsIdentity;
  stop(): Promise<void>;
}

/** Generates a fresh PKI and starts both servers in-process on random ports. */
export async function startStack(): Promise<Stack> {
  const certDir = mkdtempSync(join(tmpdir(), 'oauth-mtls-'));
  execFileSync(join(ROOT, 'scripts/gen-certs.sh'), [certDir], { stdio: 'pipe' });

  const read = (path: string) => readFileSync(join(certDir, path), 'utf8');
  const identity = (name: string): TlsIdentity => ({
    cert: read(`client/${name}.crt`),
    key: read(`client/${name}.key`),
  });

  // Both identifiers contain the port, so reserve the ports first.
  const [authPort, apiPort] = await Promise.all([freePort(), freePort()]);
  const issuer = `https://localhost:${authPort}`;
  const resource = `https://localhost:${apiPort}`;
  const redirectUri = 'https://demo-client.localhost/callback';

  const authServer = createAuthServer({
    issuer,
    resource,
    redirectUri,
    cookieSecret: 'test-only-cookie-secret',
    demoUser: USER,
    ...loadFiles(certDir),
  });
  const resourceServer = createResourceServer({
    issuer,
    audience: resource,
    requiredScope: 'accounts:read',
    algorithms: ['ES256', 'PS256'],
    tls: loadTls(certDir, 'resource-server'),
  });
  await Promise.all([listen(authServer, authPort), listen(resourceServer, apiPort)]);

  return {
    certDir,
    apiUrl: `${resource}/api/accounts`,
    identity,
    client: {
      issuer,
      clientId: 'demo-client',
      redirectUri,
      resource,
      scope: 'openid accounts:read',
      clientAuthKey: read('keys/client-auth.key'),
      identity: identity('demo-client'),
      ca: read('ca-chain.pem'),
      user: USER,
    },
    rotateClientCertificate() {
      execFileSync(join(ROOT, 'scripts/rotate-client.sh'), [certDir], { stdio: 'pipe' });
      return identity('demo-client');
    },
    async stop() {
      await Promise.all([close(authServer), close(resourceServer)]);
      rmSync(certDir, { recursive: true, force: true });
    },
  };
}

async function freePort(): Promise<number> {
  const { createServer } = await import('node:net');
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolve(port));
    });
  });
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}
