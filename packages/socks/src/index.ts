import { Socket } from 'node:net';
import { connect as tlsConnect, type TLSSocket, type ConnectionOptions } from 'node:tls';

export interface ProxyConfig {
  host: string;
  port: number;
  username?: string;
  password?: string;
}

let _globalProxy: ProxyConfig | null = null;

export function setGlobalProxy(config: ProxyConfig | null): void {
  _globalProxy = config;
}

export function getGlobalProxy(): ProxyConfig | null {
  return _globalProxy;
}

export function parseProxyUrl(url: string): ProxyConfig {
  const m = url.match(/^socks[45a]?:\/\/(?:([^:@]+)(?::([^@]+))?@)?([^:]+):(\d+)$/i);
  if (!m) throw new Error(`Invalid proxy URL: ${url} (expected socks5://[user:pass@]host:port)`);
  return {
    host: m[3]!,
    port: parseInt(m[4]!, 10),
    username: m[1],
    password: m[2],
  };
}

export function initProxy(proxyArg?: string): void {
  const url = proxyArg || process.env.JSPACKET_PROXY;
  if (url) {
    setGlobalProxy(parseProxyUrl(url));
    console.log(`[*] Using SOCKS5 proxy: ${_globalProxy!.host}:${_globalProxy!.port}`);
  }
}

function readExact(sock: Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const tryRead = () => {
      while (buf.length < n) {
        const chunk = sock.read(n - buf.length) as Buffer | null;
        if (chunk === null) return;
        buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      }
      sock.removeListener('readable', tryRead);
      sock.removeListener('error', onError);
      sock.removeListener('close', onClose);
      resolve(buf.subarray(0, n));
    };
    const onError = (err: Error) => {
      sock.removeListener('readable', tryRead);
      sock.removeListener('close', onClose);
      reject(new Error(`SOCKS5 handshake error: ${err.message}`));
    };
    const onClose = () => {
      sock.removeListener('readable', tryRead);
      sock.removeListener('error', onError);
      reject(new Error('Connection closed during SOCKS5 handshake'));
    };
    sock.on('readable', tryRead);
    sock.on('error', onError);
    sock.on('close', onClose);
    tryRead();
  });
}

const SOCKS5_ERRORS: Record<number, string> = {
  0x01: 'general failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

export function socks5Connect(
  targetHost: string,
  targetPort: number,
  proxy?: ProxyConfig,
): Promise<Socket> {
  const p = proxy ?? _globalProxy;
  if (!p) throw new Error('No proxy configured');

  return new Promise<Socket>((resolve, reject) => {
    const sock = new Socket();
    sock.setNoDelay(true);

    const onConnectError = (err: Error) => {
      reject(new Error(`Proxy connection failed (${p.host}:${p.port}): ${err.message}`));
    };
    sock.once('error', onConnectError);

    sock.connect(p.port, p.host, async () => {
      sock.removeListener('error', onConnectError);
      try {
        const hasAuth = !!(p.username && p.password);
        const greeting = hasAuth
          ? Buffer.from([0x05, 0x02, 0x00, 0x02])
          : Buffer.from([0x05, 0x01, 0x00]);
        sock.write(greeting);

        const methodResp = await readExact(sock, 2);
        if (methodResp[0] !== 0x05) throw new Error('Not a SOCKS5 proxy');

        if (methodResp[1] === 0x02) {
          if (!p.username || !p.password) throw new Error('Proxy requires auth but none provided');
          const uBuf = Buffer.from(p.username, 'utf8');
          const pBuf = Buffer.from(p.password, 'utf8');
          sock.write(Buffer.concat([
            Buffer.from([0x01, uBuf.length]), uBuf,
            Buffer.from([pBuf.length]), pBuf,
          ]));
          const authResp = await readExact(sock, 2);
          if (authResp[1] !== 0x00) throw new Error('SOCKS5 authentication failed');
        } else if (methodResp[1] === 0xff) {
          throw new Error('SOCKS5 proxy rejected all auth methods');
        }

        const hostBuf = Buffer.from(targetHost, 'utf8');
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(targetPort, 0);
        sock.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          portBuf,
        ]));

        const connResp = await readExact(sock, 4);
        if (connResp[0] !== 0x05) throw new Error('Invalid SOCKS5 response');
        if (connResp[1] !== 0x00) {
          throw new Error(`SOCKS5 connect failed: ${SOCKS5_ERRORS[connResp[1]!] ?? `code 0x${connResp[1]!.toString(16)}`}`);
        }

        const addrType = connResp[3]!;
        if (addrType === 0x01) {
          await readExact(sock, 4 + 2);
        } else if (addrType === 0x03) {
          const lenBuf = await readExact(sock, 1);
          await readExact(sock, lenBuf[0]! + 2);
        } else if (addrType === 0x04) {
          await readExact(sock, 16 + 2);
        }

        resolve(sock);
      } catch (err) {
        sock.destroy();
        reject(err);
      }
    });
  });
}

export async function createSocket(host: string, port: number): Promise<Socket> {
  const proxy = _globalProxy;
  if (proxy) return socks5Connect(host, port, proxy);
  return new Promise((resolve, reject) => {
    const sock = new Socket();
    sock.setNoDelay(true);
    sock.connect(port, host, () => resolve(sock));
    sock.on('error', reject);
  });
}

export async function createTlsSocket(
  host: string,
  port: number,
  tlsOptions?: Omit<ConnectionOptions, 'host' | 'port' | 'socket'>,
): Promise<TLSSocket> {
  const proxy = _globalProxy;
  if (proxy) {
    const rawSock = await socks5Connect(host, port, proxy);
    return new Promise((resolve, reject) => {
      const sock = tlsConnect({ ...tlsOptions, socket: rawSock }, () => resolve(sock));
      sock.once('error', reject);
    });
  }
  return new Promise((resolve, reject) => {
    const sock = tlsConnect({ ...tlsOptions, host, port }, () => resolve(sock));
    sock.once('error', reject);
  });
}
