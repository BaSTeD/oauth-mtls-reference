import { importPKCS8 } from 'jose';
import * as oauth from 'openid-client';
import { CookieJar, createFetch, type TlsIdentity } from './http.js';

export interface ClientConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Identifier of the API the token is requested for (RFC 8707). */
  resource: string;
  scope: string;
  /** EC private key (PEM) for private_key_jwt client authentication. */
  clientAuthKey: string;
  /** TLS client certificate the access token will be bound to. */
  identity?: TlsIdentity;
  /** CA bundle of the private test PKI. */
  ca: string;
  /** Credentials of the demo user who approves the request. */
  user: { username: string; password: string };
}

export interface FlowResult {
  accessToken: string;
  expiresIn: number | undefined;
  /** `cnf.x5t#S256` from the access token. */
  boundThumbprint: string | undefined;
  /** The `request_uri` returned by the PAR endpoint. */
  requestUri: string;
}

/** Hooks that let tests tamper with individual steps of the flow. */
export interface FlowOverrides {
  pkceCodeVerifier?: string;
}

export async function discover(config: ClientConfig): Promise<oauth.Configuration> {
  // Every back-channel request goes out with the TLS client certificate.
  const mtlsFetch = createFetch(config.ca, config.identity);
  const key = await importPKCS8(config.clientAuthKey, 'ES256');

  const configuration = await oauth.discovery(
    new URL(config.issuer),
    config.clientId,
    { token_endpoint_auth_signing_alg: 'ES256' },
    oauth.PrivateKeyJwt({ key: key as CryptoKey, kid: 'client-auth-1' }),
    { [oauth.customFetch]: mtlsFetch as oauth.CustomFetch },
  );
  configuration[oauth.customFetch] = mtlsFetch as oauth.CustomFetch;
  return configuration;
}

/**
 * Runs the complete flow and returns a certificate-bound access token:
 * PAR -> authorization code with PKCE -> token request with private_key_jwt
 * over mutual TLS.
 */
export async function obtainToken(config: ClientConfig, overrides: FlowOverrides = {}): Promise<FlowResult> {
  const configuration = await discover(config);

  const codeVerifier = oauth.randomPKCECodeVerifier();
  const state = oauth.randomState();

  // 1. Pushed Authorization Request (RFC 9126). The parameters are sent
  //    directly to the authorization server, authenticated as the client.
  const authorizationUrl = await oauth.buildAuthorizationUrlWithPAR(configuration, {
    redirect_uri: config.redirectUri,
    scope: config.scope,
    resource: config.resource,
    code_challenge: await oauth.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
  });
  const requestUri = authorizationUrl.searchParams.get('request_uri') ?? '';

  // 2. The user's browser. It has no client certificate, only the request_uri.
  const callbackUrl = await signInAndApprove(config, authorizationUrl);

  // 3. Token request: private_key_jwt for client authentication, PKCE verifier
  //    for code binding, mutual TLS so the token gets bound to our certificate.
  const tokens = await oauth.authorizationCodeGrant(configuration, callbackUrl, {
    pkceCodeVerifier: overrides.pkceCodeVerifier ?? codeVerifier,
    expectedState: state,
  });

  return {
    accessToken: tokens.access_token,
    expiresIn: tokens.expires_in,
    boundThumbprint: readThumbprint(tokens.access_token),
    requestUri,
  };
}

/**
 * Stands in for the user and their browser: follows the redirects, submits
 * the login form and returns the final redirect back to the client.
 */
async function signInAndApprove(config: ClientConfig, authorizationUrl: URL): Promise<URL> {
  const browserFetch = createFetch(config.ca);
  const jar = new CookieJar();
  const redirectOrigin = new URL(config.redirectUri).origin;

  let url = authorizationUrl;
  let init: { method: string; headers?: Record<string, string>; body?: string } = { method: 'GET' };

  for (let hop = 0; hop < 10; hop++) {
    const response = await browserFetch(url, {
      ...init,
      redirect: 'manual',
      headers: { ...init.headers, cookie: jar.header(url) },
    });
    jar.store(response);

    const location = response.headers.get('location');
    if (location) {
      const next = new URL(location, url);
      if (next.origin === redirectOrigin) return next;
      url = next;
      init = { method: 'GET' };
      continue;
    }

    if (response.ok && url.pathname.startsWith('/interaction/')) {
      url = new URL(`${url.pathname}/login`, url);
      init = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(config.user).toString(),
      };
      continue;
    }

    throw new Error(`authorization failed with HTTP ${response.status}: ${await response.text()}`);
  }
  throw new Error('too many redirects during authorization');
}

export interface ApiResponse {
  status: number;
  body: unknown;
}

/** Calls the protected API with the given token, authenticating with `identity` (or no certificate). */
export async function callApi(
  url: string,
  accessToken: string,
  ca: string,
  identity?: TlsIdentity,
): Promise<ApiResponse> {
  const response = await createFetch(ca, identity)(url, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  return { status: response.status, body: await response.json() };
}

function readThumbprint(jwt: string): string | undefined {
  const payload = jwt.split('.')[1];
  if (!payload) return undefined;
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
    cnf?: Record<string, string>;
  };
  return claims.cnf?.['x5t#S256'];
}
