import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeJwt, decodeProtectedHeader, importPKCS8, SignJWT, type JWTPayload } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { callApi, obtainToken, type FlowResult } from '../packages/demo-client/src/flow.js';
import { createFetch } from '../packages/demo-client/src/http.js';
import { certificateThumbprint } from '../packages/resource-server/src/binding.js';
import { startStack, type Stack } from './stack.js';

let stack: Stack;
let token: FlowResult;

beforeAll(async () => {
  stack = await startStack();
  token = await obtainToken(stack.client);
});
afterAll(() => stack.stop());

const call = (accessToken: string, identityName?: string) =>
  callApi(stack.apiUrl, accessToken, stack.client.ca, identityName ? stack.identity(identityName) : undefined);

describe('issued access token', () => {
  it('is a short-lived, audience-restricted JWT signed with ES256', () => {
    const header = decodeProtectedHeader(token.accessToken);
    const claims = decodeJwt(token.accessToken);

    expect(header).toMatchObject({ alg: 'ES256', typ: 'at+jwt' });
    expect(claims.iss).toBe(stack.client.issuer);
    expect(claims.aud).toBe(stack.client.resource);
    expect(claims.scope).toBe('accounts:read');
    expect(claims.exp! - claims.iat!).toBe(300);
  });

  it('carries the thumbprint of the client certificate in cnf.x5t#S256', () => {
    const cert = new X509Certificate(stack.client.identity!.cert);
    expect(token.boundThumbprint).toBe(certificateThumbprint(cert));
  });

  it('was requested through PAR', () => {
    expect(token.requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
  });
});

describe('resource server', () => {
  it('serves the request when token and certificate belong together', async () => {
    const response = await call(token.accessToken, 'demo-client');

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ owner: 'alice' });
  });

  it('rejects a stolen token presented with a different valid certificate', async () => {
    const response = await call(token.accessToken, 'intruder');

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({
      error: 'invalid_token',
      error_description: 'access token is not bound to the presented client certificate',
    });
  });

  it('rejects the token without any client certificate', async () => {
    const response = await call(token.accessToken);
    expect(response.status).toBe(401);
  });

  it('rejects a certificate that does not chain to the trusted CA', async () => {
    const dir = stack.certDir;
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
      '-subj', '/CN=demo-client', '-days', '1',
      '-keyout', join(dir, 'client/self-signed.key'), '-out', join(dir, 'client/self-signed.crt'),
    ], { stdio: 'pipe' });

    const response = await call(token.accessToken, 'self-signed');
    expect(response.status).toBe(401);
  });

  it('rejects a request without a token', async () => {
    const response = await createFetch(stack.client.ca, stack.client.identity)(stack.apiUrl);

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('Bearer error="invalid_token"');
  });

  it('rejects a token whose payload was modified', async () => {
    const [header, , signature] = token.accessToken.split('.');
    const original: JWTPayload = decodeJwt(token.accessToken);
    const claims = { ...original, sub: 'mallory' };
    const forged = [header, Buffer.from(JSON.stringify(claims)).toString('base64url'), signature].join('.');

    expect((await call(forged, 'demo-client')).status).toBe(401);
  });

  it('rejects an unsigned token (alg none)', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'at+jwt' })).toString('base64url');
    const unsigned = `${header}.${token.accessToken.split('.')[1]}.`;

    expect((await call(unsigned, 'demo-client')).status).toBe(401);
  });

  // The remaining cases need tokens the authorization server would never
  // issue, so the tests sign them with its key.
  describe('with correctly signed but unacceptable tokens', () => {
    const mint = async (overrides: Record<string, unknown> = {}, expiresIn = 300) => {
      const key = await importPKCS8(readFileSync(join(stack.certDir, 'keys/as-signing.key'), 'utf8'), 'ES256');
      const now = Math.floor(Date.now() / 1000);
      const original: JWTPayload = decodeJwt(token.accessToken);
      return new SignJWT({
        ...original,
        iat: now,
        exp: now + expiresIn,
        ...overrides,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: 'as-signing-1' })
        .sign(key);
    };

    it('accepts a token minted this way when nothing is wrong with it', async () => {
      expect((await call(await mint(), 'demo-client')).status).toBe(200);
    });

    it('rejects an expired token', async () => {
      expect((await call(await mint({}, -60), 'demo-client')).status).toBe(401);
    });

    it('rejects a plain bearer token without certificate binding', async () => {
      expect((await call(await mint({ cnf: undefined }), 'demo-client')).status).toBe(401);
    });

    it('rejects a token issued for another audience', async () => {
      expect((await call(await mint({ aud: 'https://other-api.example' }), 'demo-client')).status).toBe(401);
    });

    it('rejects a token from another issuer', async () => {
      expect((await call(await mint({ iss: 'https://evil.example' }), 'demo-client')).status).toBe(401);
    });

    it('answers 403 when the scope is missing', async () => {
      const response = await call(await mint({ scope: 'profile' }), 'demo-client');

      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({ error: 'insufficient_scope' });
    });
  });
});

describe('authorization server', () => {
  const metadata = async () =>
    (await (await createFetch(stack.client.ca)(`${stack.client.issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;

  it('advertises only what this setup is meant to allow', async () => {
    const m = await metadata();

    expect(m.require_pushed_authorization_requests).toBe(true);
    expect(m.token_endpoint_auth_methods_supported).toEqual(['private_key_jwt']);
    expect(m.token_endpoint_auth_signing_alg_values_supported).toEqual(['ES256', 'PS256']);
    expect(m.id_token_signing_alg_values_supported).toEqual(['ES256']);
    expect(m.code_challenge_methods_supported).toEqual(['S256']);
    expect(m.response_types_supported).toEqual(['code']);
    expect(m.tls_client_certificate_bound_access_tokens).toBe(true);
    expect(m.authorization_response_iss_parameter_supported).toBe(true);
  });

  it('refuses authorization requests that bypass PAR', async () => {
    const url = new URL((await metadata()).authorization_endpoint as string);
    url.search = new URLSearchParams({
      client_id: stack.client.clientId,
      redirect_uri: stack.client.redirectUri,
      response_type: 'code',
      scope: stack.client.scope,
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    }).toString();

    const response = await createFetch(stack.client.ca)(url, { redirect: 'manual' });
    const location = response.headers.get('location') ?? '';

    expect(location.startsWith('/interaction/')).toBe(false);
    expect(`${location} ${await response.text()}`).toContain('invalid_request');
  });

  it('refuses a pushed request from a client that cannot prove its identity', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const attackerKey = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

    await expect(obtainToken({ ...stack.client, clientAuthKey: attackerKey })).rejects.toMatchObject({
      error: 'invalid_client',
    });
  });

  it('refuses the code when the PKCE verifier does not match', async () => {
    await expect(
      obtainToken(stack.client, { pkceCodeVerifier: 'wrong-verifier-wrong-verifier-wrong-verifier-000' }),
    ).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('refuses to issue a token when the client presents no certificate', async () => {
    await expect(obtainToken({ ...stack.client, identity: undefined })).rejects.toMatchObject({
      error: 'invalid_grant',
    });
  });

  it('refuses a login with wrong credentials', async () => {
    await expect(
      obtainToken({ ...stack.client, user: { username: 'alice', password: 'guess' } }),
    ).rejects.toThrow(/HTTP 401/);
  });
});

describe('certificate rotation', () => {
  it('invalidates tokens bound to the previous certificate and works with a new token', async () => {
    const rotated = stack.rotateClientCertificate();
    const ca = stack.client.ca;

    const oldToken = await callApi(stack.apiUrl, token.accessToken, ca, rotated);
    expect(oldToken.status).toBe(401);

    const fresh = await obtainToken({ ...stack.client, identity: rotated });
    expect(fresh.boundThumbprint).not.toBe(token.boundThumbprint);
    expect((await callApi(stack.apiUrl, fresh.accessToken, ca, rotated)).status).toBe(200);
  });
});
