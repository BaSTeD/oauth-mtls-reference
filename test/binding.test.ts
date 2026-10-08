import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { certificateThumbprint, isBoundToCertificate } from '../packages/resource-server/src/binding.js';

let dir: string;
let client: X509Certificate;
let intruder: X509Certificate;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'oauth-mtls-unit-'));
  execFileSync(join(import.meta.dirname, '../scripts/gen-certs.sh'), [dir], { stdio: 'pipe' });
  client = new X509Certificate(readFileSync(join(dir, 'client/demo-client.crt')));
  intruder = new X509Certificate(readFileSync(join(dir, 'client/intruder.crt')));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('certificateThumbprint', () => {
  it('matches the SHA-256 digest OpenSSL computes over the DER encoding', () => {
    const der = execFileSync('openssl', ['x509', '-in', join(dir, 'client/demo-client.crt'), '-outform', 'DER']);
    const digest = execFileSync('openssl', ['dgst', '-sha256', '-binary'], { input: der });

    expect(certificateThumbprint(client)).toBe(digest.toString('base64url'));
  });

  it('is unpadded base64url of 32 bytes', () => {
    expect(certificateThumbprint(client)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('differs between certificates', () => {
    expect(certificateThumbprint(client)).not.toBe(certificateThumbprint(intruder));
  });
});

describe('isBoundToCertificate', () => {
  const bound = () => ({ cnf: { 'x5t#S256': certificateThumbprint(client) } });

  it('accepts the certificate the token was issued to', () => {
    expect(isBoundToCertificate(bound(), client)).toBe(true);
  });

  it('rejects any other certificate', () => {
    expect(isBoundToCertificate(bound(), intruder)).toBe(false);
  });

  it.each([
    ['no cnf claim', {}],
    ['cnf is not an object', { cnf: 'x5t#S256' }],
    ['cnf is null', { cnf: null }],
    ['cnf without x5t#S256', { cnf: { jkt: 'abc' } }],
    ['empty thumbprint', { cnf: { 'x5t#S256': '' } }],
    ['thumbprint is not a string', { cnf: { 'x5t#S256': 42 } }],
    ['truncated thumbprint', { cnf: { 'x5t#S256': 'abc' } }],
  ])('rejects a token with %s', (_name, claims) => {
    expect(isBoundToCertificate(claims, client)).toBe(false);
  });
});
