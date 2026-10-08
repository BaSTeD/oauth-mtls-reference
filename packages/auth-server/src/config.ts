import { createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import type { Configuration, KoaContextWithOIDC } from 'oidc-provider';

export interface AuthServerConfig {
  /** Issuer identifier. Must be the https origin clients reach this server at. */
  issuer: string;
  /** Identifier of the protected API. Becomes the access token `aud`. */
  resource: string;
  /** Redirect URI registered for the demo client. */
  redirectUri: string;
  /** Secret used to sign session cookies. */
  cookieSecret: string;
  /** The single demo account. Real deployments plug in their user store here. */
  demoUser: { username: string; password: string };
  keys: {
    /** EC private key (PEM, PKCS#8) that signs ID tokens and access tokens. */
    signing: string;
    /** Public key (PEM) the demo client uses for private_key_jwt. */
    clientAuthPublic: string;
  };
  tls: { cert: string; key: string; ca: string };
}

export const CLIENT_ID = 'demo-client';
export const API_SCOPE = 'accounts:read';

/** Only asymmetric algorithms with strong defaults. No RS256, no HS256. */
const ALGS = ['ES256', 'PS256'] as const;

const ACCESS_TOKEN_TTL = 5 * 60;

export function buildConfiguration(config: AuthServerConfig): Configuration {
  const signingJwk = createPrivateKey(config.keys.signing).export({ format: 'jwk' });
  const clientJwk = createPublicKey(config.keys.clientAuthPublic).export({ format: 'jwk' });

  return {
    clients: [
      {
        client_id: CLIENT_ID,
        redirect_uris: [config.redirectUri],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        // RFC 7523: the client proves its identity with a signed assertion
        // instead of a shared secret.
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [{ ...clientJwk, use: 'sig', alg: 'ES256', kid: 'client-auth-1' }] },
        // RFC 8705: every access token for this client is bound to the TLS
        // client certificate used at the token endpoint.
        tls_client_certificate_bound_access_tokens: true,
        id_token_signed_response_alg: 'ES256',
      },
    ],

    jwks: { keys: [{ ...signingJwk, use: 'sig', alg: 'ES256', kid: 'as-signing-1' }] },
    cookies: { keys: [config.cookieSecret] },

    clientAuthMethods: ['private_key_jwt'],
    responseTypes: ['code'],
    scopes: ['openid'],
    pkce: { required: () => true },

    enabledJWA: {
      clientAuthSigningAlgValues: [...ALGS],
      idTokenSigningAlgValues: [...ALGS],
      requestObjectSigningAlgValues: [...ALGS],
      userinfoSigningAlgValues: [...ALGS],
      introspectionSigningAlgValues: [...ALGS],
      authorizationSigningAlgValues: [...ALGS],
    },

    ttl: {
      AccessToken: ACCESS_TOKEN_TTL,
      AuthorizationCode: 60,
      PushedAuthorizationRequest: 60,
      IdToken: ACCESS_TOKEN_TTL,
      Interaction: 10 * 60,
      Session: 60 * 60,
      Grant: 60 * 60,
    },

    features: {
      // The built-in development login accepts any credentials. Replaced by
      // the minimal login in interactions.ts.
      devInteractions: { enabled: false },

      // FAPI 2.0 Security Profile behaviours of the provider.
      fapi: { enabled: true, profile: '2.0' },

      // RFC 9126: authorization parameters travel over an authenticated
      // back channel, never through the browser.
      pushedAuthorizationRequests: {
        enabled: true,
        requirePushedAuthorizationRequests: true,
      },

      mTLS: {
        enabled: true,
        certificateBoundAccessTokens: true,
        getCertificate,
      },

      // RFC 8707 and RFC 9068: audience-restricted JWT access tokens.
      resourceIndicators: {
        enabled: true,
        defaultResource: () => config.resource,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, indicator) => {
          if (indicator !== config.resource) {
            throw new Error(`unknown resource ${indicator}`);
          }
          return {
            scope: API_SCOPE,
            audience: config.resource,
            accessTokenTTL: ACCESS_TOKEN_TTL,
            accessTokenFormat: 'jwt',
            jwt: { sign: { alg: 'ES256' } },
          };
        },
      },
    },

    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
    },

    findAccount: (_ctx, id) => ({
      accountId: id,
      claims: () => ({ sub: id }),
    }),

    // The demo client is first-party, so there is no consent screen. The
    // grant is created once the user has logged in.
    loadExistingGrant: async (ctx) => {
      const { client, session, provider } = ctx.oidc;
      if (!client || !session?.accountId) return undefined;

      const existing = session.grantIdFor(client.clientId);
      if (existing) {
        const grant = await provider.Grant.find(existing);
        if (grant) return grant;
      }
      if (client.clientId !== CLIENT_ID) return undefined;

      const grant = new provider.Grant({
        clientId: client.clientId,
        accountId: session.accountId,
      });
      grant.addOIDCScope('openid');
      grant.addResourceScope(config.resource, API_SCOPE);
      await grant.save();
      return grant;
    },
  };
}

/**
 * Hands the verified TLS client certificate to the provider.
 *
 * The server accepts connections without a client certificate, because the
 * browser-facing authorization endpoint must stay reachable. A certificate
 * therefore only counts when Node verified its chain against our CA.
 *
 * Behind a TLS-terminating proxy this function would read the certificate
 * from a header instead, and the proxy would have to strip that header from
 * incoming requests.
 */
function getCertificate(ctx: KoaContextWithOIDC) {
  const socket = ctx.socket as TLSSocket;
  return socket.authorized ? socket.getPeerX509Certificate() : undefined;
}

export function credentialsMatch(
  expected: AuthServerConfig['demoUser'],
  username: string,
  password: string,
): boolean {
  return safeEqual(expected.username, username) && safeEqual(expected.password, password);
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
