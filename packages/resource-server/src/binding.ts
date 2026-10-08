import { createHash, timingSafeEqual, type X509Certificate } from 'node:crypto';

/**
 * SHA-256 thumbprint of the DER-encoded certificate, base64url without
 * padding. This is the value RFC 8705 section 3.1 puts into `cnf.x5t#S256`.
 */
export function certificateThumbprint(cert: X509Certificate): string {
  return createHash('sha256').update(cert.raw).digest('base64url');
}

/**
 * True when the access token's confirmation claim matches the certificate the
 * caller authenticated with on this TLS connection.
 *
 * A token without `cnf.x5t#S256` is a plain bearer token and is never
 * accepted: this API only serves sender-constrained tokens.
 */
export function isBoundToCertificate(
  claims: Record<string, unknown>,
  cert: X509Certificate,
): boolean {
  const cnf = claims.cnf;
  if (typeof cnf !== 'object' || cnf === null) return false;

  const expected = (cnf as Record<string, unknown>)['x5t#S256'];
  if (typeof expected !== 'string' || expected.length === 0) return false;

  const a = Buffer.from(expected);
  const b = Buffer.from(certificateThumbprint(cert));
  return a.length === b.length && timingSafeEqual(a, b);
}
