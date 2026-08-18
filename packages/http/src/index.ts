/**
 * @impacket/http - TypeScript port of impacket/http.py
 *
 * HTTP client security provider for MS-RPCH and NTLM relay scenarios.
 */

import { Buffer } from 'node:buffer';
import * as http from 'node:http';
import * as https from 'node:https';

// ---------------------------------------------------------------------------
// Auth types
// ---------------------------------------------------------------------------

export const AUTH_AUTO      = 'Auto';
export const AUTH_BASIC     = 'Basic';
export const AUTH_NTLM      = 'NTLM';
export const AUTH_NEGOTIATE = 'Negotiate';
export const AUTH_BEARER    = 'Bearer';
export const AUTH_DIGEST    = 'Digest';

export type AuthType =
  | typeof AUTH_AUTO
  | typeof AUTH_BASIC
  | typeof AUTH_NTLM
  | typeof AUTH_NEGOTIATE
  | typeof AUTH_BEARER
  | typeof AUTH_DIGEST;

// ---------------------------------------------------------------------------
// HTTPClientSecurityProvider
// ---------------------------------------------------------------------------

/**
 * An NTLM/Basic auth negotiation helper.
 *
 * NOTE: The original Python code depends on `impacket.ntlm` for NTLM
 * message construction. This port provides the structural scaffolding;
 * NTLM helpers should be supplied from `@impacket/ntlm` when available.
 */
export class HTTPClientSecurityProvider {
  private _username: string | null = null;
  private _password: string | null = null;
  private _domain   = '';
  private _lmhash: Buffer | string = '';
  private _nthash: Buffer | string = '';
  private _aesKey  = '';
  private _TGT: unknown = null;
  private _TGS: unknown = null;

  private _authType: AuthType;
  private _authTypes: AuthType[] = [];
  private _ntlmsspInfo: unknown = null;

  constructor(authType: AuthType = AUTH_AUTO) {
    this._authType = authType;
  }

  setAuthType(authType: AuthType): void { this._authType = authType; }
  getAuthType(): AuthType { return this._authType; }
  getAuthTypes(): AuthType[] { return this._authTypes; }
  getNtlmsspInfo(): unknown { return this._ntlmsspInfo; }

  setCredentials(
    username: string,
    password: string,
    domain = '',
    lmhash = '',
    nthash = '',
    aesKey = '',
    TGT: unknown = null,
    TGS: unknown = null,
  ): void {
    this._username = username;
    this._password = password;
    this._domain   = domain;

    if (lmhash !== '' || nthash !== '') {
      let lm = lmhash;
      let nt = nthash;
      if (lm.length % 2) lm = '0' + lm;
      if (nt.length % 2) nt = '0' + nt;
      try {
        this._lmhash = Buffer.from(lm, 'hex');
        this._nthash = Buffer.from(nt, 'hex');
      } catch {
        this._lmhash = lm;
        this._nthash = nt;
      }
    }

    this._aesKey = aesKey;
    this._TGT    = TGT;
    this._TGS    = TGS;
  }

  parseWwwAuthenticate(header: string): AuthType[] {
    const ret: AuthType[] = [];
    if (header.includes('NTLM'))      ret.push(AUTH_NTLM);
    if (header.includes('Basic'))     ret.push(AUTH_BASIC);
    if (header.includes('Negotiate')) ret.push(AUTH_NEGOTIATE);
    if (header.includes('Bearer'))    ret.push(AUTH_BEARER);
    if (header.includes('Digest'))    ret.push(AUTH_DIGEST);
    return ret;
  }

  connect(protocol: 'http' | 'https', hostL6: string): http.Agent {
    if (protocol === 'http') {
      return new http.Agent({ keepAlive: true });
    } else {
      return new https.Agent({
        keepAlive: true,
        rejectUnauthorized: false,
      });
    }
  }

  /**
   * Make an HTTP request helper. Returns [response, responseBody].
   */
  private _request(
    protocol: 'http' | 'https',
    host: string,
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: string | Buffer,
  ): Promise<[http.IncomingMessage, Buffer]> {
    return new Promise((resolve, reject) => {
      const mod = protocol === 'https' ? https : http;
      const req = mod.request(
        {
          hostname: host,
          method,
          path,
          headers,
          rejectUnauthorized: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => resolve([res, Buffer.concat(chunks)]));
        },
      );
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  }

  getAuthHeadersBasic(): [Record<string, string>, null] {
    if (
      this._lmhash !== '' || this._nthash !== '' ||
      this._aesKey !== '' || this._TGT != null || this._TGS != null
    ) {
      throw new Error(
        'Basic authentication in HTTP connection used, so set plaintext credentials to connect.',
      );
    }

    let authLine: string;
    if (this._domain === '') {
      authLine = `${this._username}:${this._password}`;
    } else {
      authLine = `${this._domain}\\${this._username}:${this._password}`;
    }

    const authLineHttp = `Basic ${Buffer.from(authLine, 'utf-8').toString('base64')}`;
    return [{ Authorization: authLineHttp }, null];
  }

  /**
   * Send an NTLM Type 1 (Negotiate) message to the server.
   *
   * Returns [serverChallenge, null] or [null, null] if NTLM is not offered.
   *
   * @param protocol - 'http' or 'https'
   * @param host - target host
   * @param method - HTTP method
   * @param path - HTTP path
   * @param headers - base request headers
   * @param negotiateMessage - NTLM Type 1 message buffer
   */
  async sendNtlmType1(
    protocol: 'http' | 'https',
    host: string,
    method: string,
    path: string,
    headers: Record<string, string>,
    negotiateMessage: Buffer,
  ): Promise<[Buffer | null, null]> {
    const authHeaders = { ...headers };
    authHeaders['Content-Length'] = '0';
    authHeaders['Authorization'] = `NTLM ${negotiateMessage.toString('base64')}`;

    const [res] = await this._request(protocol, host, method, path, authHeaders);

    if (res.statusCode !== 401) {
      throw new Error(
        `Status code returned: ${res.statusCode}. Authentication does not seem required for url ${path}`,
      );
    }

    const wwwAuth = res.headers['www-authenticate'];
    if (!wwwAuth) {
      throw new Error(`No authentication requested by the server for url ${path}`);
    }

    if (this._authTypes.length === 0) {
      this._authTypes = this.parseWwwAuthenticate(wwwAuth);
    }

    if (!this._authTypes.includes(AUTH_NTLM)) {
      return [null, null];
    }

    const match = /NTLM ([a-zA-Z0-9+/]+={0,2})/.exec(wwwAuth);
    if (!match) {
      throw new Error(`No NTLM challenge returned from server for url ${path}`);
    }

    const serverChallenge = Buffer.from(match[1]!, 'base64');
    return [serverChallenge, null];
  }
}
