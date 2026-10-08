import { readFileSync } from 'node:fs';
import { callApi, obtainToken, type ClientConfig } from './flow.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env.example)`);
  return value;
}

const certDir = process.env.CERT_DIR ?? './certs';
const read = (path: string) => readFileSync(`${certDir}/${path}`, 'utf8');
const identity = (name: string) => ({
  cert: read(`client/${name}.crt`),
  key: read(`client/${name}.key`),
});

const resource = process.env.RESOURCE ?? 'https://resource-server:8443';
const config: ClientConfig = {
  issuer: process.env.ISSUER ?? 'https://auth-server:8443',
  clientId: 'demo-client',
  redirectUri: process.env.REDIRECT_URI ?? 'https://demo-client.localhost/callback',
  resource,
  scope: 'openid accounts:read',
  clientAuthKey: read('keys/client-auth.key'),
  identity: identity('demo-client'),
  ca: read('ca-chain.pem'),
  user: { username: required('DEMO_USERNAME'), password: required('DEMO_PASSWORD') },
};
const api = `${resource}/api/accounts`;

const step = (label: string, detail: string) => console.log(`${label.padEnd(44)} ${detail}`);
const verdict = (status: number, body: unknown) =>
  status === 200
    ? `200 OK, ${(body as { accounts: unknown[] }).accounts.length} accounts returned`
    : `${status} ${(body as { error_description?: string }).error_description ?? ''}`;

console.log('\nOAuth 2.0 with PAR, PKCE, private_key_jwt and certificate-bound tokens\n');

const token = await obtainToken(config);
step('1. Pushed authorization request', token.requestUri);
step('2. User signed in, code returned', 'PKCE S256, state and issuer verified');
step('3. Token issued over mutual TLS', `expires in ${token.expiresIn}s`);
step('   bound to certificate (cnf.x5t#S256)', token.boundThumbprint ?? 'MISSING');

console.log('\nCalling the API with the same access token:\n');

const legitimate = await callApi(api, token.accessToken, config.ca, config.identity);
step('4. with the client certificate', verdict(legitimate.status, legitimate.body));

const stolen = await callApi(api, token.accessToken, config.ca, identity('intruder'));
step('5. with another valid certificate', verdict(stolen.status, stolen.body));

const bare = await callApi(api, token.accessToken, config.ca);
step('6. without a certificate', verdict(bare.status, bare.body));

const ok = legitimate.status === 200 && stolen.status === 401 && bare.status === 401;
console.log(ok ? '\nThe token only works together with the certificate it was issued to.\n' : '\nUnexpected result.\n');
process.exit(ok ? 0 : 1);
