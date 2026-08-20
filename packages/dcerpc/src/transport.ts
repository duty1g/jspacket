import { Buffer } from 'node:buffer';
import * as net from 'node:net';
import * as dgram from 'node:dgram';
import * as dns from 'node:dns';
import * as ntlm from '@impacket/ntlm';
import { DCERPCException, DCERPC_v5, type IDCERPCTransport } from './rpcrt';
import { SMBConnection } from '@impacket/smb-connection';
import { getGlobalProxy, createSocket } from '@impacket/socks';
import { RPCProxyClient, type RpcProxyUrl } from './rpch.js';
import type { AuthType } from '@impacket/http';

const PARSER_RE =
  /^(?:([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})@)?([_a-zA-Z0-9]*):([^\[]*)(?:\[([^\]]*)\])?/;

export class DCERPCStringBinding {
  private uuid: string | null;
  private ps: string;
  private na: string;
  private endpoint: string;
  private options: Record<string, string>;

  constructor(stringbinding: string) {
    const match = PARSER_RE.exec(stringbinding);
    if (!match) throw new DCERPCException(`Invalid string binding: ${stringbinding}`);
    this.uuid = match[1] ?? null;
    this.ps = match[2] ?? '';
    this.na = match[3] ?? '';
    const opts = match[4];
    this.options = {};
    if (opts) {
      const parts = opts.split(',');
      this.endpoint = parts[0] ?? '';
      if (this.endpoint.includes('endpoint=')) {
        this.endpoint = this.endpoint.slice('endpoint='.length);
      }
      for (const opt of parts.slice(1)) {
        const [k, ...vParts] = opt.split('=');
        this.options[k!] = vParts.length > 0 ? vParts.join('=') : '';
      }
    } else {
      this.endpoint = '';
    }
  }

  getUuid(): string | null { return this.uuid; }
  getProtocolSequence(): string { return this.ps; }
  getNetworkAddress(): string { return this.na; }
  setNetworkAddress(addr: string): void { this.na = addr; }
  getEndpoint(): string { return this.endpoint; }
  getOptions(): Record<string, string> { return this.options; }
  getOption(name: string): string { return this.options[name]!; }
  isOptionSet(name: string): boolean { return name in this.options; }
  unsetOption(name: string): void { delete this.options[name]; }
  toString(): string { return DCERPCStringBindingCompose(this.uuid ?? undefined, this.ps, this.na, this.endpoint, this.options); }
}

export function DCERPCStringBindingCompose(
  uuid?: string,
  protocolSequence = '',
  networkAddress = '',
  endpoint = '',
  options: Record<string, string> = {},
): string {
  let s = '';
  if (uuid) s += `${uuid}@`;
  s += `${protocolSequence}:`;
  if (networkAddress) s += networkAddress;
  if (endpoint || Object.keys(options).length > 0) {
    s += `[${endpoint}`;
    const optParts = Object.entries(options).map(([k, v]) => (v === '' ? k : `${k}=${v}`));
    if (optParts.length > 0) s += `,${optParts.join(',')}`;
    s += ']';
  }
  return s;
}

export function DCERPCTransportFactory(stringbinding: string): DCERPCTransport {
  const sb = new DCERPCStringBinding(stringbinding);
  const na = sb.getNetworkAddress();
  const ps = sb.getProtocolSequence();
  let rpctransport: DCERPCTransport;

  if (ps === 'ncadg_ip_udp') {
    const port = sb.getEndpoint();
    rpctransport = new UDPTransport(na, port ? Number(port) : 135);
  } else if (ps === 'ncacn_ip_tcp') {
    const port = sb.getEndpoint();
    rpctransport = new TCPTransport(na, port ? Number(port) : 135);
  } else if (ps === 'ncacn_np') {
    let namedPipe = sb.getEndpoint();
    if (namedPipe.startsWith('\\pipe')) namedPipe = namedPipe.slice('\\pipe'.length);
    rpctransport = new SMBTransport(na, 445, namedPipe);
  } else if (ps === 'ncacn_http') {
    const port = sb.getEndpoint();
    const rpcProxyHost = sb.isOptionSet('RpcProxy') ? sb.getOption('RpcProxy') : null;
    rpctransport = new RPCHTTPTransport(na, port ? Number(port) : 593, rpcProxyHost);
  } else {
    throw new DCERPCException(`Unknown protocol sequence: ${ps}`);
  }

  rpctransport.setStringBinding(sb);
  return rpctransport;
}

export abstract class DCERPCTransport implements IDCERPCTransport {
  protected remoteName: string;
  protected remoteHost: string;
  protected dstport: number;
  protected stringbinding: DCERPCStringBinding | null = null;
  protected maxSendFrag: number | null = null;
  protected maxRecvFrag: number | null = null;
  protected username = '';
  protected password = '';
  protected domain = '';
  protected lmhash: Buffer | string = '';
  protected nthash: Buffer | string = '';
  protected aesKey: string | null = null;
  protected TGT: unknown = null;
  protected TGS: unknown = null;
  protected kdcHost: string | null = null;
  protected doKerberos = false;
  protected connectTimeout: number | null = null;

  constructor(remoteName: string, dstport: number) {
    this.remoteName = remoteName;
    this.remoteHost = remoteName;
    this.dstport = dstport;
    this.lmhash = '';
    this.nthash = '';
  }

  abstract connect(): Promise<void>;
  abstract send(data: Buffer, forceWriteAndx?: number, forceRecv?: number): Promise<void>;
  abstract recv(forceRecv?: number, count?: number): Promise<Buffer>;
  abstract disconnect(): Promise<void>;

  getConnectTimeout(): number | null { return this.connectTimeout; }
  setConnectTimeout(timeout: number): void { this.connectTimeout = timeout; }

  getRemoteName(): string { return this.remoteName; }
  setRemoteName(remoteName: string): void { this.remoteName = remoteName; }
  getRemoteHost(): string { return this.remoteHost; }
  setRemoteHost(remoteHost: string): void { this.remoteHost = remoteHost; }
  getDport(): number { return this.dstport; }
  setDport(dport: number): void { this.dstport = dport; }

  getStringBinding(): DCERPCStringBinding | null { return this.stringbinding; }
  setStringBinding(sb: DCERPCStringBinding): void { this.stringbinding = sb; }

  setKerberos(flag: boolean, kdcHost: string | null = null): void {
    this.doKerberos = flag;
    this.kdcHost = kdcHost;
  }
  getKerberos(): boolean { return this.doKerberos; }
  getKdcHost(): string | null { return this.kdcHost; }

  setMaxFragmentSize(sendFragmentSize: number): void {
    if (sendFragmentSize === -1) {
      this.maxSendFrag = 0;
    } else {
      this.maxSendFrag = sendFragmentSize;
    }
  }

  getCredentials(): [string | null, string | null, string, Buffer | string, Buffer | string, string, unknown, unknown] {
    return [this.username || null, this.password || null, this.domain, this.lmhash, this.nthash, this.aesKey ?? '', this.TGT, this.TGS];
  }

  setCredentials(
    username: string,
    password: string,
    domain = '',
    lmhash = '',
    nthash = '',
    aesKey: string | null = null,
    TGT: unknown = null,
    TGS: unknown = null,
  ): void {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.aesKey = aesKey;
    this.TGT = TGT;
    this.TGS = TGS;
    this.lmhash = '';
    this.nthash = '';
    if (lmhash || nthash) {
      if (lmhash.length % 2) lmhash = `0${lmhash}`;
      if (nthash.length % 2) nthash = `0${nthash}`;
      try {
        this.lmhash = Buffer.from(lmhash, 'hex');
        this.nthash = Buffer.from(nthash, 'hex');
      } catch {
        this.lmhash = Buffer.from(lmhash);
        this.nthash = Buffer.from(nthash);
      }
    }
  }

  doesSupportNTLMv2(): boolean { return ntlm.USE_NTLMv2; }

  getDceRpc(): DCERPC_v5 { return new DCERPC_v5(this); }
}

export class UDPTransport extends DCERPCTransport {
  private socket: dgram.Socket | null = null;
  private recvAddr: string = '';

  constructor(remoteName: string, dstport = 135) {
    super(remoteName, dstport);
    this.setConnectTimeout(30);
  }

  async connect(): Promise<void> {
    this.socket = dgram.createSocket('udp4');
  }

  async disconnect(): Promise<void> {
    return new Promise((resolve) => {
      if (this.socket) {
        this.socket.close(() => { this.socket = null; resolve(); });
      } else {
        resolve();
      }
    });
  }

  async send(data: Buffer, _forceWriteAndx = 0, _forceRecv = 0): Promise<void> {
    if (!this.socket) throw new DCERPCException('Socket not connected');
    return new Promise((resolve, reject) => {
      this.socket!.send(data, this.dstport, this.remoteHost, (err) => {
        if (err) reject(new DCERPCException(`Send error: ${err.message}`));
        else resolve();
      });
    });
  }

  async recv(_forceRecv = 0, _count = 0): Promise<Buffer> {
    if (!this.socket) throw new DCERPCException('Socket not connected');
    return new Promise((resolve, reject) => {
      this.socket!.once('message', (msg, rinfo) => {
        this.recvAddr = rinfo.address;
        resolve(Buffer.from(msg));
      });
      this.socket!.once('error', (err) => {
        reject(new DCERPCException(`Recv error: ${err.message}`));
      });
    });
  }

  getSocket(): dgram.Socket | null { return this.socket; }
}

export class TCPTransport extends DCERPCTransport {
  protected socket: net.Socket | null = null;
  private recvBuffer: Buffer = Buffer.alloc(0);

  constructor(remoteName: string, dstport = 135) {
    super(remoteName, dstport);
    this.setConnectTimeout(30);
  }

  async connect(): Promise<void> {
    if (getGlobalProxy()) {
      try {
        const socket = await createSocket(this.remoteHost, this.dstport);
        socket.setTimeout(0);
        this.socket = socket;
      } catch (err) {
        throw new DCERPCException(`Could not connect: ${(err as Error).message}`);
      }
      return;
    }
    const lookup = await dns.promises.lookup(this.remoteHost);
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      socket.setTimeout((this.connectTimeout ?? 30) * 1000);
      const onError = (err: Error): void => {
        reject(new DCERPCException(`Could not connect: ${err.message}`));
      };
      const onTimeout = (): void => {
        socket.destroy();
        reject(new DCERPCException('Connection timed out'));
      };
      socket.setNoDelay(true);
      socket.connect(this.dstport, lookup.address, () => {
        socket.removeListener('error', onError);
        socket.removeListener('timeout', onTimeout);
        socket.setTimeout(0);
        this.socket = socket;
        resolve();
      });
      socket.on('error', onError);
      socket.on('timeout', onTimeout);
    });
  }

  async disconnect(): Promise<void> {
    return new Promise((resolve) => {
      if (this.socket) {
        this.socket.end(() => { this.socket = null; resolve(); });
      } else {
        resolve();
      }
    });
  }

  async send(data: Buffer, _forceWriteAndx = 0, _forceRecv = 0): Promise<void> {
    if (!this.socket) throw new DCERPCException('Socket not connected');
    if (this.socket.destroyed) throw new DCERPCException('Socket destroyed');
    return new Promise((resolve, reject) => {
      const sendBuf = data;
      if (this.maxSendFrag && this.maxSendFrag > 0) {
        const writeChunk = (offset: number) => {
          const toSend = sendBuf.subarray(offset, offset + this.maxSendFrag!);
          if (toSend.length === 0) { resolve(); return; }
          this.socket!.write(toSend, (err) => {
            if (err) { reject(new DCERPCException(`Send error: ${err.message}`)); return; }
            writeChunk(offset + toSend.length);
          });
        };
        writeChunk(0);
      } else {
        this.socket!.write(sendBuf, (err) => {
          if (err) reject(new DCERPCException(`Send error: ${err.message}`));
          else resolve();
        });
      }
    });
  }

  async recv(_forceRecv = 0, count = 0): Promise<Buffer> {
    if (!this.socket) throw new DCERPCException('Socket not connected');
    if (count) {
      while (this.recvBuffer.length < count) {
        const chunk = await this.recvFromSocket();
        if (chunk.length === 0) throw new DCERPCException('Connection closed by remote host');
        this.recvBuffer = this.recvBuffer.length > 0 ? Buffer.concat([this.recvBuffer, chunk]) : chunk;
      }
      const result = this.recvBuffer.subarray(0, count);
      this.recvBuffer = this.recvBuffer.subarray(count);
      return result;
    }
    if (this.recvBuffer.length > 0) {
      const result = this.recvBuffer;
      this.recvBuffer = Buffer.alloc(0);
      return result;
    }
    return this.recvFromSocket();
  }

  private recvFromSocket(): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      if (!this.socket) { reject(new DCERPCException('Socket not connected')); return; }
      const onData = (data: Buffer) => {
        this.socket!.removeListener('data', onData);
        this.socket!.removeListener('error', onError);
        this.socket!.removeListener('close', onClose);
        resolve(Buffer.from(data));
      };
      const onError = (err: Error) => {
        this.socket!.removeListener('data', onData);
        this.socket!.removeListener('error', onError);
        this.socket!.removeListener('close', onClose);
        reject(new DCERPCException(`Recv error: ${err.message}`));
      };
      const onClose = () => {
        this.socket!.removeListener('data', onData);
        this.socket!.removeListener('error', onError);
        this.socket!.removeListener('close', onClose);
        resolve(Buffer.alloc(0));
      };
      this.socket.once('data', onData);
      this.socket.once('error', onError);
      this.socket.once('close', onClose);
    });
  }

  getSocket(): net.Socket | null { return this.socket; }
}

export class SMBTransport extends DCERPCTransport {
  private tid = 0;
  private filename: string;
  private handle: number | Buffer = 0;
  private pendingRecv = 0;
  private existingSmb: boolean;
  private smbConnection: SMBConnection | null = null;

  constructor(
    remoteName: string,
    dstport = 445,
    filename = '',
    username = '',
    password = '',
    domain = '',
    lmhash = '',
    nthash = '',
    aesKey: string | null = null,
    TGT: unknown = null,
    TGS: unknown = null,
    remoteHost = '',
    smbConnection: SMBConnection | null = null,
    doKerberos = false,
    kdcHost: string | null = null,
  ) {
    super(remoteName, dstport);
    this.filename = filename;
    this.setCredentials(username, password, domain, lmhash, nthash, aesKey, TGT, TGS);
    this.doKerberos = doKerberos;
    this.kdcHost = kdcHost;
    if (remoteHost) this.remoteHost = remoteHost;
    this.existingSmb = smbConnection !== null;
    this.smbConnection = smbConnection;
    this.setConnectTimeout(30);
  }

  async connect(): Promise<void> {
    if (!this.smbConnection) {
      const conn = new SMBConnection(this.remoteName, this.remoteHost, { sessPort: this.dstport, timeout: this.connectTimeout ?? 60 });
      await conn.negotiateSession();
      if (!this.doKerberos) {
        await conn.login(this.username, this.password, this.domain, this.lmhash, this.nthash);
      } else {
        await conn.kerberosLogin(
          this.username,
          this.password,
          this.domain,
          this.lmhash,
          this.nthash,
          this.aesKey ?? '',
          this.kdcHost,
        );
      }
      this.smbConnection = conn;
    }
    const conn = this.smbConnection!;
    this.tid = await conn.connectTree('IPC$');
    this.handle = await conn.openFile(this.tid, this.filename);
  }

  async disconnect(): Promise<void> {
    const conn = this.smbConnection!;
    await conn.disconnectTree(this.tid);
    if (!this.existingSmb) {
      await conn.logoff();
      await conn.close();
      this.smbConnection = null;
    }
  }

  async send(data: Buffer, _forceWriteAndx = 0, forceRecv = 0): Promise<void> {
    const conn = this.smbConnection!;
    if (this.maxSendFrag && this.maxSendFrag > 0) {
      let offset = 0;
      while (true) {
        const toSend = data.subarray(offset, offset + this.maxSendFrag);
        if (toSend.length === 0) break;
        await conn.writeFile(this.tid, this.handle, toSend, offset);
        offset += toSend.length;
      }
    } else {
      await conn.writeFile(this.tid, this.handle, data);
    }
    if (forceRecv) this.pendingRecv++;
  }

  async recv(_forceRecv = 0, _count = 0): Promise<Buffer> {
    const conn = this.smbConnection!;
    if (this.maxSendFrag || this.pendingRecv) {
      if (this.pendingRecv) this.pendingRecv--;
      return conn.readFile(this.tid, this.handle, 0, this.maxRecvFrag ?? null);
    }
    return conn.readFile(this.tid, this.handle);
  }

  getSmbConnection(): SMBConnection | null { return this.smbConnection; }
  setSmbConnection(smbConnection: SMBConnection): void {
    this.smbConnection = smbConnection;
    const creds = smbConnection.getCredentials();
    this.setCredentials(
      creds.user ?? '', creds.password ?? '', creds.domain ?? '',
      creds.lmhash ? Buffer.isBuffer(creds.lmhash) ? creds.lmhash.toString('hex') : '' : '',
      creds.nthash ? Buffer.isBuffer(creds.nthash) ? creds.nthash.toString('hex') : '' : '',
    );
    this.existingSmb = true;
  }

  doesSupportNTLMv2(): boolean {
    if (!this.smbConnection) return ntlm.USE_NTLMv2;
    return this.smbConnection.doesSupportNTLMv2();
  }
}

export class RPCHTTPTransport extends DCERPCTransport {
  private rpcProxy: RPCProxyClient;
  private rpcProxyHost: string | null;

  constructor(remoteName: string, dstport = 593, rpcProxyHost: string | null = null) {
    super(remoteName, dstport);
    this.rpcProxyHost = rpcProxyHost;
    this.rpcProxy = new RPCProxyClient(remoteName, dstport);
  }

  override setCredentials(
    username: string, password: string, domain = '',
    lmhash = '', nthash = '',
    aesKey: string | null = null,
    TGT: unknown = null, TGS: unknown = null,
  ): void {
    super.setCredentials(username, password, domain, lmhash, nthash, aesKey, TGT, TGS);
    this.rpcProxy.setCredentials(username, password, domain, lmhash, nthash);
  }

  setAuthType(authType: AuthType): void {
    this.rpcProxy.setAuthType(authType);
  }

  getRpcProxyClient(): RPCProxyClient { return this.rpcProxy; }

  override setStringBinding(sb: DCERPCStringBinding): void {
    super.setStringBinding(sb);
    this.rpcProxy._stringbinding = sb;
  }

  async connect(): Promise<void> {
    const proxyTarget = this.rpcProxyHost ?? this.remoteName;
    const [host, portStr] = proxyTarget.includes(':')
      ? proxyTarget.split(':')
      : [proxyTarget, '443'];

    const url: RpcProxyUrl = {
      scheme: 'https',
      netloc: `${host}:${portStr}`,
      path: '/rpc/rpcproxy.dll',
      query: '',
    };
    this.rpcProxy._rpcProxyUrl = url;

    if (this.stringbinding) {
      this.rpcProxy._stringbinding = this.stringbinding;
    }

    await this.rpcProxy.connectProxy();
  }

  async send(data: Buffer, forceWriteAndx = 0, forceRecv = 0): Promise<void> {
    await this.rpcProxy.send(data, forceWriteAndx, forceRecv);
  }

  async recv(forceRecv = 0, count = 0): Promise<Buffer> {
    return this.rpcProxy.recv(forceRecv, count);
  }

  async disconnect(): Promise<void> {
    this.rpcProxy.disconnectProxy();
  }
}
