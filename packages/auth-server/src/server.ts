import { readFileSync } from 'node:fs';
import https from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider from 'oidc-provider';
import { buildConfiguration, credentialsMatch, type AuthServerConfig } from './config.js';

export type { AuthServerConfig } from './config.js';

/**
 * Authorization server: a configured `oidc-provider` plus the minimal login
 * interaction it needs. The protocol work is done by the library.
 */
export function createAuthServer(config: AuthServerConfig): https.Server {
  const provider = new Provider(config.issuer, buildConfiguration(config));
  const oidc = provider.callback();

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const { pathname } = new URL(req.url ?? '/', config.issuer);

    if (req.method === 'GET' && pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"status":"ok"}');
      return;
    }

    const match = /^\/interaction\/([\w-]+)(\/login)?$/.exec(pathname);
    if (!match) {
      await oidc(req, res);
      return;
    }

    // Throws when the interaction session cookie is missing or expired.
    const details = await provider.interactionDetails(req, res);
    const noStore = { 'cache-control': 'no-store' };

    if (req.method === 'GET' && !match[2]) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...noStore });
      res.end(loginPage(details.uid));
      return;
    }

    if (req.method === 'POST' && match[2]) {
      const form = new URLSearchParams(await readBody(req));
      const username = form.get('username') ?? '';
      const password = form.get('password') ?? '';

      if (!credentialsMatch(config.demoUser, username, password)) {
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', ...noStore });
        res.end(loginPage(details.uid, 'Invalid username or password.'));
        return;
      }
      await provider.interactionFinished(
        req,
        res,
        { login: { accountId: username } },
        { mergeWithLastSubmission: false },
      );
      return;
    }

    res.writeHead(405, noStore);
    res.end();
  }

  return https.createServer(
    {
      cert: config.tls.cert,
      key: config.tls.key,
      ca: config.tls.ca,
      minVersion: 'TLSv1.3',
      // Client certificates are optional at the TLS layer: browsers reach the
      // authorization endpoint without one. Endpoints that need a certificate
      // check `socket.authorized` (see getCertificate in config.ts).
      requestCert: true,
      rejectUnauthorized: false,
    },
    (req, res) => {
      handle(req, res).catch((err: unknown) => {
        console.error(err);
        if (!res.headersSent) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end('{"error":"invalid_request"}');
        }
      });
    },
  );
}

function loginPage(uid: string, error?: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign in</title></head>
<body>
  <h1>Sign in</h1>
  ${error ? `<p role="alert">${error}</p>` : ''}
  <form method="post" action="/interaction/${uid}/login">
    <label>Username <input name="username" autocomplete="username" required></label>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`;
}

async function readBody(req: IncomingMessage, limit = 10_000): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function loadFiles(certDir: string): Pick<AuthServerConfig, 'keys' | 'tls'> {
  const read = (path: string) => readFileSync(`${certDir}/${path}`, 'utf8');
  return {
    keys: {
      signing: read('keys/as-signing.key'),
      clientAuthPublic: read('keys/client-auth.pub'),
    },
    tls: {
      cert: read('server/auth-server.crt'),
      key: read('server/auth-server.key'),
      ca: read('ca-chain.pem'),
    },
  };
}
