import { Agent, fetch as undiciFetch } from 'undici';

/** PEM-encoded TLS client certificate and key. */
export interface TlsIdentity {
  cert: string;
  key: string;
}

/**
 * A fetch function that trusts the given CA and, when an identity is passed,
 * authenticates with that client certificate.
 */
export function createFetch(ca: string, identity?: TlsIdentity): Fetch {
  const dispatcher = new Agent({ connect: { ca, ...identity } });
  return (input, init) =>
    undiciFetch(input, { ...init, dispatcher } as never) as unknown as Promise<Response>;
}

// Loose on purpose: the same function serves openid-client and our own calls.
export type Fetch = (input: string | URL, init?: object) => Promise<Response>;

/**
 * Just enough of a cookie jar to walk through the login redirect chain the
 * way a browser would. Honours the Path attribute, nothing else.
 */
export class CookieJar {
  private readonly cookies = new Map<string, { value: string; path: string }>();

  store(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair = '', ...attributes] = header.split(';').map((part) => part.trim());
      const separator = pair.indexOf('=');
      if (separator < 1) continue;
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      const pathAttribute = attributes.find((a) => a.toLowerCase().startsWith('path='));
      const path = pathAttribute ? pathAttribute.slice(5) : '/';
      const expired = attributes.some((a) => /^expires=Thu, 01 Jan 1970/i.test(a));
      if (expired || value === '') this.cookies.delete(`${name};${path}`);
      else this.cookies.set(`${name};${path}`, { value, path });
    }
  }

  header(url: URL): string {
    return [...this.cookies.entries()]
      .filter(([, cookie]) => url.pathname.startsWith(cookie.path))
      .map(([key, cookie]) => `${key.split(';')[0]}=${cookie.value}`)
      .join('; ');
  }
}
