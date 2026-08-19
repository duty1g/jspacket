import { Buffer } from 'node:buffer';
import net from 'node:net';
import { Constants, Keytab } from '@impacket/krb5';
import { getGlobalProxy, createSocket } from '@impacket/socks';
export { initProxy, setGlobalProxy, getGlobalProxy } from '@impacket/socks';

const targetRegex = /(?:(?:([^/@:]*)\/)?(([^@:]+))(?::([^@]*))?@)?(.*)/;
const credentialRegex = /(?:(?:([^/:]*)\/)?([^:]*)(?::(.*))?)?/;

export const VERSION = '0.1.1';
const C = '\x1b[38;2;78;201;176m';
const X = '\x1b[0m';
const ASCII_ART = String.raw`
     ____.      __________                __           __
    |    | _____\______   \_____    ____ |  | __ _____/  |_
    |    |/  ___/|     ___/\__  \ _/ ___\|  |/ // __ \   __\
/\__|    |\___ \ |    |     / __ \\  \___|    <\  ___/|  |
\________/____  >|____|    (____  /\___  >__|_ \\___  >__|
              \/                \/     \/     \/    \/`;
export const BANNER = `${C}${ASCII_ART}\n                                \x1b[35mv\x1b[1;91m${VERSION}\x1b[96m{\x1b[32m#dev}${X}@\x1b[93mduty1g${X}`;

export const EMPTY_LM_HASH = 'AAD3B435B51404EEAAD3B435B51404EE';

export function parseTarget(target: string): [string, string, string, string] {
  const m = targetRegex.exec(target);
  let domain = m?.[1] ?? '';
  let username = m?.[2] ?? '';
  let password = m?.[4] ?? '';
  let remoteName = m?.[5] ?? '';

  if (remoteName.includes('@')) {
    const lastAt = remoteName.lastIndexOf('@');
    password = password + '@' + remoteName.substring(0, lastAt);
    remoteName = remoteName.substring(lastAt + 1);
  }

  return [domain, username, password, remoteName];
}

export function parseCredentials(credentials: string): [string, string, string] {
  const m = credentialRegex.exec(credentials);
  return [m?.[1] ?? '', m?.[2] ?? '', m?.[3] ?? ''];
}

export function parseIdentity(
  credentials: string,
  opts: { hashes?: string | null; noPass?: boolean; aesKey?: string | null; k?: boolean } = {},
): { domain: string; username: string; password: string; lmhash: string; nthash: string; doKerberos: boolean } {
  let [domain, username, password] = parseCredentials(credentials);
  let doKerberos = opts.k ?? false;

  if (opts.aesKey) {
    doKerberos = true;
  }

  let lmhash = '';
  let nthash = '';
  if (opts.hashes) {
    const parts = opts.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
    if (lmhash === '') lmhash = EMPTY_LM_HASH;
  }

  return { domain, username, password, lmhash, nthash, doKerberos };
}

export function getAddress(ip: string, port: number, ipv6 = false): { family: number; address: [string, number] } {
  if (ipv6) {
    const parts = ip.split('%');
    return { family: 6, address: [parts[0]!, port] };
  }
  return { family: 4, address: [ip, port] };
}

export async function getConnectedSocket(ip: string, port: number, ipv6 = false): Promise<net.Socket> {
  if (getGlobalProxy()) {
    const { address } = getAddress(ip, port, ipv6);
    return createSocket(address[0], address[1]);
  }
  return new Promise((resolve, reject) => {
    const sock = new net.Socket();
    const { address } = getAddress(ip, port, ipv6);
    sock.connect(address[1], address[0], () => resolve(sock));
    sock.on('error', reject);
  });
}

export function normalizeArgs(args: string[]): string[] {
  return args.map(arg => {
    if (arg.startsWith('-') && !arg.startsWith('--') && arg.length > 2) {
      return '-' + arg;
    }
    return arg;
  });
}

export function loadKeytabKeys(keytabPath: string): { aesKey: string; nthash: string } {
  const kt = Keytab.Keytab.loadFile(keytabPath);
  let aesKey = '';
  let nthash = '';
  for (const entry of kt.entries) {
    if (entry.keyblock.keytype === Constants.EncryptionTypes.aes256_cts_hmac_sha1_96) {
      aesKey = Buffer.from(entry.keyblock.keyvalue.data).toString('hex');
    } else if (entry.keyblock.keytype === Constants.EncryptionTypes.aes128_cts_hmac_sha1_96 && !aesKey) {
      aesKey = Buffer.from(entry.keyblock.keyvalue.data).toString('hex');
    } else if (entry.keyblock.keytype === Constants.EncryptionTypes.rc4_hmac) {
      nthash = Buffer.from(entry.keyblock.keyvalue.data).toString('hex');
    }
  }
  return { aesKey, nthash };
}
