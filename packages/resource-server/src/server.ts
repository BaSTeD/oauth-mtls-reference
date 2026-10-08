import { readFileSync } from 'node:fs';
import https from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { TLSSocket } from 'node:tls';
import { createRemoteJWKSet, customFetch, jwtVerify, errors as joseErrors } from 'jose';
import { Agent, fetch as undiciFetch } from 'undici';
import { isBoundToCertificate } from './binding.js';

export interface ResourceServerConfig {
  /** Issuer identifier of the authorization server, e.g. https://auth-server:8443 */
  issuer: string;
  /** This API's identifier. Tokens must carry it as `aud`. */
  audience: string;
  /** Scope required to read accounts. */
  requiredScope: string;
  /** Accepted token signature algorithms. */
  algorithms: string[];
  tls: {
    /** Server certificate chain (PEM). */
    cert: string;
    /** Server private key (PEM). */
    key: string;
    /** CA bundle used to verify client certificates and the authorization server. */
    ca: string;
  };
}

const ACCOUNTS = [
  { id: 'DE00-0001', name: 'Current account', currency: 'EUR', balance: '1204.56' },
  { id: 'DE00-0002', name: 'Savings', currency: 'EUR', balance: '8300.00' },
];

class Unauthorized extends Error {}
class Forbidden extends Error {}

export function createResourceServer(config: ResourceServerConfig): https.Server {
  // The authorization server uses a certificate from the private test CA, so
  // the JWKS request needs that CA as its trust anchor.
  const dispatcher = new Agent({ connect: { ca: config.tls.ca } });
  const jwks = createRemoteJWKSet(new URL(`${config.issuer}/jwks`), {
    [customFetch]: ((url: string, init: object) =>
      undiciFetch(url, { ...init, dispatcher })) as unknown as typeof fetch,
  });

  async function authorize(req: IncomingMessage): Promise<{ sub?: string }> {
    // 1. The caller must have completed a TLS handshake with a client
    //    certificate that chains to a CA we trust.
    const socket = req.socket as TLSSocket;
    const cert = socket.authorized ? socket.getPeerX509Certificate() : undefined;
    if (!cert) throw new Unauthorized('a trusted client certificate is required');

    // 2. Standard JWT access token validation (RFC 9068).
    const header = req.headers.authorization ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) {
      throw new Unauthorized('missing bearer token');
    }
    const { payload } = await jwtVerify(token, jwks, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: config.algorithms,
      typ: 'at+jwt',
      requiredClaims: ['exp', 'iat', 'sub', 'client_id', 'jti'],
    });

    // 3. RFC 8705: the token is only valid on a connection authenticated with
    //    the certificate it was issued to. A stolen token is useless without
    //    the matching private key.
    if (!isBoundToCertificate(payload, cert)) {
      throw new Unauthorized('access token is not bound to the presented client certificate');
    }

    const scopes = typeof payload.scope === 'string' ? payload.scope.split(' ') : [];
    if (!scopes.includes(config.requiredScope)) {
      throw new Forbidden(`scope ${config.requiredScope} is required`);
    }
    return { sub: payload.sub };
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const { pathname } = new URL(req.url ?? '/', 'https://placeholder.invalid');

    if (req.method === 'GET' && pathname === '/healthz') {
      return send(res, 200, { status: 'ok' });
    }
    if (req.method !== 'GET' || pathname !== '/api/accounts') {
      return send(res, 404, { error: 'not_found' });
    }

    try {
      const { sub } = await authorize(req);
      send(res, 200, { owner: sub, accounts: ACCOUNTS });
    } catch (err) {
      if (err instanceof Forbidden) {
        return deny(res, 403, 'insufficient_scope', err.message);
      }
      if (err instanceof Unauthorized) {
        return deny(res, 401, 'invalid_token', err.message);
      }
      if (err instanceof joseErrors.JOSEError) {
        // Do not leak which check failed beyond the generic category.
        return deny(res, 401, 'invalid_token', 'access token validation failed');
      }
      throw err;
    }
  }

  return https.createServer(
    {
      cert: config.tls.cert,
      key: config.tls.key,
      ca: config.tls.ca,
      minVersion: 'TLSv1.3',
      // Ask for a client certificate, but answer missing or untrusted ones
      // with a proper 401 instead of a failed handshake. `authorize` enforces
      // `socket.authorized` for every protected request.
      requestCert: true,
      rejectUnauthorized: false,
    },
    (req, res) => {
      handle(req, res).catch((err: unknown) => {
        console.error(err);
        if (!res.headersSent) send(res, 500, { error: 'server_error' });
      });
    },
  );
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

function deny(res: ServerResponse, status: number, error: string, description: string): void {
  send(res, status, { error, error_description: description }, {
    'www-authenticate': `Bearer error="${error}", error_description="${description}"`,
  });
}

export function loadTls(certDir: string, name: string): ResourceServerConfig['tls'] {
  return {
    cert: readFileSync(`${certDir}/server/${name}.crt`, 'utf8'),
    key: readFileSync(`${certDir}/server/${name}.key`, 'utf8'),
    ca: readFileSync(`${certDir}/ca-chain.pem`, 'utf8'),
  };
}
