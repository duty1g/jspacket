// Impacket-js - TypeScript port of Impacket
//
// [MS-RPCH] RPC over HTTP v2 implementation
//
// Ported from impacket/dcerpc/v5/rpch.py
// Original author: Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies

import { Buffer } from 'node:buffer';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import * as uuidMod from '@impacket/uuid';
import { EMPTY_UUID } from '@impacket/uuid';
import {
  NTLMSSP_AV_HOSTNAME,
  getNTLMSSPType1,
  getNTLMSSPType3,
  NTLMAuthChallenge,
  AV_PAIRS,
} from '@impacket/ntlm';
import type { NTLMAuthNegotiate } from '@impacket/ntlm';
import { ERROR_MESSAGES as SYSTEM_ERROR_MESSAGES } from '@impacket/system-errors';
import { ERROR_MESSAGES as NT_ERROR_MESSAGES } from '@impacket/nt-errors';
import { HTTPClientSecurityProvider, AUTH_BASIC, AUTH_NTLM } from '@impacket/http';
import {
  DCERPCException,
  MSRPCHeader,
  MSRPC_RTS,
  PFC_FIRST_FRAG,
  PFC_LAST_FRAG,
} from './rpcrt.js';
import { type DCERPCStringBinding } from './transport.js';

// =============================================================================
// RPCProxyClientException
// =============================================================================

const RPC_ERROR_PARSER = /RPC Error: ([a-fA-F0-9]{1,8})/;

export class RPCProxyClientException extends DCERPCException {
  error_string: string;

  constructor(errorString?: string | null, proxyError?: string | null) {
    let rpcErrorCode: number | null = null;
    let finalErrorString = errorString ?? '';

    if (proxyError != null) {
      const search = RPC_ERROR_PARSER.exec(proxyError);
      if (search?.[1]) {
        rpcErrorCode = parseInt(search[1], 16);
      } else {
        finalErrorString += ': ' + proxyError;
      }
    }

    super(finalErrorString, rpcErrorCode);
    this.error_string = finalErrorString;
  }

  override toString(): string {
    if (this.error_code != null) {
      const key = this.error_code;
      const sysMsg = SYSTEM_ERROR_MESSAGES[key];
      if (sysMsg) {
        return `${this.error_string}, code: 0x${this.error_code.toString(16)} - ${sysMsg[0]}`;
      }
      const ntMsg = NT_ERROR_MESSAGES[key];
      if (ntMsg) {
        return `${this.error_string}, code: 0x${this.error_code.toString(16)} - ${ntMsg[0]}`;
      }
      return `${this.error_string}: unknown code: 0x${this.error_code.toString(16)}`;
    }
    return this.error_string;
  }
}

// =============================================================================
// CONSTANTS
// =============================================================================

export const RPC_OVER_HTTP_v1 = 1;
export const RPC_OVER_HTTP_v2 = 2;

// RPCProxyClient internal errors
export const RPC_PROXY_REMOTE_NAME_NEEDED_ERR =
  "Basic authentication in RPC proxy is used, so couldn't obtain a target NetBIOS name from NTLMSSP to connect.";

// Errors containing parts of server responses
export const RPC_PROXY_INVALID_RPC_PORT_ERR = 'Invalid RPC Port';
export const RPC_PROXY_CONN_A1_0X6BA_ERR = 'RPC Proxy CONN/A1 request failed, code: 0x6ba';
export const RPC_PROXY_CONN_A1_404_ERR = 'CONN/A1 request failed: HTTP/1.1 404 Not Found';
export const RPC_PROXY_RPC_OUT_DATA_404_ERR = 'RPC_OUT_DATA channel: HTTP/1.1 404 Not Found';
export const RPC_PROXY_CONN_A1_401_ERR = 'CONN/A1 request failed: HTTP/1.1 401 Unauthorized';
export const RPC_PROXY_HTTP_IN_DATA_401_ERR = 'RPC_IN_DATA channel: HTTP/1.1 401 Unauthorized';

// 2.2.3.3 Forward Destinations
export const FD_CLIENT = 0x00000000;
export const FD_IN_PROXY = 0x00000001;
export const FD_SERVER = 0x00000002;
export const FD_OUT_PROXY = 0x00000003;

export const RTS_FLAG_NONE = 0x0000;
export const RTS_FLAG_PING = 0x0001;
export const RTS_FLAG_OTHER_CMD = 0x0002;
export const RTS_FLAG_RECYCLE_CHANNEL = 0x0004;
export const RTS_FLAG_IN_CHANNEL = 0x0008;
export const RTS_FLAG_OUT_CHANNEL = 0x0010;
export const RTS_FLAG_EOF = 0x0020;
export const RTS_FLAG_ECHO = 0x0040;

// 2.2.3.5 RTS Commands
export const RTS_CMD_RECEIVE_WINDOW_SIZE = 0x00000000;
export const RTS_CMD_FLOW_CONTROL_ACK = 0x00000001;
export const RTS_CMD_CONNECTION_TIMEOUT = 0x00000002;
export const RTS_CMD_COOKIE = 0x00000003;
export const RTS_CMD_CHANNEL_LIFETIME = 0x00000004;
export const RTS_CMD_CLIENT_KEEPALIVE = 0x00000005;
export const RTS_CMD_VERSION = 0x00000006;
export const RTS_CMD_EMPTY = 0x00000007;
export const RTS_CMD_PADDING = 0x00000008;
export const RTS_CMD_NEGATIVE_ANCE = 0x00000009;
export const RTS_CMD_ANCE = 0x0000000a;
export const RTS_CMD_CLIENT_ADDRESS = 0x0000000b;
export const RTS_CMD_ASSOCIATION_GROUP_ID = 0x0000000c;
export const RTS_CMD_DESTINATION = 0x0000000d;
export const RTS_CMD_PING_TRAFFIC_SENT_NOTIFY = 0x0000000e;

// =============================================================================
// STRUCTURES
// =============================================================================

// 2.2.3.1 RTS Cookie
export class RTSCookie extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Cookie', '16s=b"\\x00"*16'],
  ];
}

// 2.2.3.2 Client Address
export class EncodedClientAddress extends Structure {
  static override structure: FieldDescriptor[] = [
    ['AddressType', '<L=(0 if len(ClientAddress) == 4 else 1)'],
    ['_ClientAddress', '_-ClientAddress', '4 if AddressType == 0 else 16'],
    ['ClientAddress', ':'],
    ['Padding', '12s=b"\\x00"*12'],
  ];
}

// 2.2.3.4 Flow Control Acknowledgment
export class Ack extends Structure {
  static override structure: FieldDescriptor[] = [
    ['BytesReceived', '<L=0'],
    ['AvailableWindow', '<L=0'],
    ['ChannelCookie', ':', RTSCookie],
  ];
}

// 2.2.3.5.1 ReceiveWindowSize
export class ReceiveWindowSize extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=0'],
    ['ReceiveWindowSize', '<L=262144'],
  ];
}

// 2.2.3.5.2 FlowControlAck
export class FlowControlAck extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=1'],
    ['Ack', ':', Ack],
  ];
}

// 2.2.3.5.3 ConnectionTimeout
export class ConnectionTimeout extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=2'],
    ['ConnectionTimeout', '<L=120000'],
  ];
}

// 2.2.3.5.4 Cookie
export class Cookie extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=3'],
    ['Cookie', ':', RTSCookie],
  ];
}

// 2.2.3.5.5 ChannelLifetime
export class ChannelLifetime extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=4'],
    ['ChannelLifetime', '<L=1073741824'],
  ];
}

// 2.2.3.5.6 ClientKeepalive
//
// By the spec, ClientKeepalive value can be 0 or in the inclusive
// range of 60,000 through 4,294,967,295.
// If it is 0, it MUST be interpreted as 300,000.
//
// But do not set it to 0, it will cause 0x6c0 rpc error.
export class ClientKeepalive extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=5'],
    ['ClientKeepalive', '<L=300000'],
  ];
}

// 2.2.3.5.7 Version
export class Version extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=6'],
    ['Version', '<L=1'],
  ];
}

// 2.2.3.5.8 Empty
export class Empty extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=7'],
  ];
}

// 2.2.3.5.9 Padding
export class Padding extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=8'],
    ['ConformanceCount', '<L=len(Padding)'],
    ['Padding', '*ConformanceCount'],
  ];
}

// 2.2.3.5.10 NegativeANCE
export class NegativeANCE extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=9'],
  ];
}

// 2.2.3.5.11 ANCE
export class ANCE extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=0xA'],
  ];
}

// 2.2.3.5.12 ClientAddress
export class ClientAddress extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=0xB'],
    ['ClientAddress', ':', EncodedClientAddress],
  ];
}

// 2.2.3.5.13 AssociationGroupId
export class AssociationGroupId extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=0xC'],
    ['AssociationGroupId', ':', RTSCookie],
  ];
}

// 2.2.3.5.14 Destination
export class Destination extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=0xD'],
    ['Destination', '<L'],
  ];
}

// 2.2.3.5.15 PingTrafficSentNotify
export class PingTrafficSentNotify extends Structure {
  static override structure: FieldDescriptor[] = [
    ['CommandType', '<L=0xE'],
    ['PingTrafficSent', '<L'],
  ];
}

export const COMMANDS: Record<number, typeof Structure> = {
  0x0: ReceiveWindowSize,
  0x1: FlowControlAck,
  0x2: ConnectionTimeout,
  0x3: Cookie,
  0x4: ChannelLifetime,
  0x5: ClientKeepalive,
  0x6: Version,
  0x7: Empty,
  0x8: Padding,
  0x9: NegativeANCE,
  0xa: ANCE,
  0xb: ClientAddress,
  0xc: AssociationGroupId,
  0xd: Destination,
  0xe: PingTrafficSentNotify,
};

// =============================================================================
// 2.2.3.6.1 RTS PDU Header
// =============================================================================

// The RTS PDU Header has the same layout as the common header of the
// connection-oriented RPC PDU as specified in [C706] section 12.6.1,
// with a few additional requirements around the contents of the header fields.
export class RTSHeader extends MSRPCHeader {
  static override _SIZE = 20;
  static override commonHdr: FieldDescriptor[] = [
    ...MSRPCHeader.commonHdr,
    ['Flags', '<H=0'],
    ['NumberOfCommands', '<H=0'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('type', MSRPC_RTS);
      this.set('flags', PFC_FIRST_FRAG | PFC_LAST_FRAG);
      this.set('auth_len', 0);
      this.set('call_id', 0);
    }
  }
}

// =============================================================================
// RTS PDU structures
// =============================================================================

// 2.2.4.2 CONN/A1 RTS PDU
export class CONN_A1_RTS_PDU extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', ':', Version],
    ['VirtualConnectionCookie', ':', Cookie],
    ['OutChannelCookie', ':', Cookie],
    ['ReceiveWindowSize', ':', ReceiveWindowSize],
  ];
}

// 2.2.4.5 CONN/B1 RTS PDU
export class CONN_B1_RTS_PDU extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', ':', Version],
    ['VirtualConnectionCookie', ':', Cookie],
    ['INChannelCookie', ':', Cookie],
    ['ChannelLifetime', ':', ChannelLifetime],
    ['ClientKeepalive', ':', ClientKeepalive],
    ['AssociationGroupId', ':', AssociationGroupId],
  ];
}

// 2.2.4.4 CONN/A3 RTS PDU
export class CONN_A3_RTS_PDU extends Structure {
  static override structure: FieldDescriptor[] = [
    ['ConnectionTimeout', ':', ConnectionTimeout],
  ];
}

// 2.2.4.9 CONN/C2 RTS PDU
export class CONN_C2_RTS_PDU extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', ':', Version],
    ['ReceiveWindowSize', ':', ReceiveWindowSize],
    ['ConnectionTimeout', ':', ConnectionTimeout],
  ];
}

// 2.2.4.51 FlowControlAckWithDestination RTS PDU
export class FlowControlAckWithDestination_RTS_PDU extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Destination', ':', Destination],
    ['FlowControlAck', ':', FlowControlAck],
  ];
}

// =============================================================================
// HELPERS
// =============================================================================

export function hCONN_A1(
  virtualConnectionCookie: Buffer = EMPTY_UUID,
  outChannelCookie: Buffer = EMPTY_UUID,
  receiveWindowSize = 262144,
): Buffer {
  const connA1 = new CONN_A1_RTS_PDU();
  connA1.set('Version', new Version());
  const vcc = new Cookie();
  vcc.set('Cookie', virtualConnectionCookie);
  connA1.set('VirtualConnectionCookie', vcc);
  const occ = new Cookie();
  occ.set('Cookie', outChannelCookie);
  connA1.set('OutChannelCookie', occ);
  const rws = new ReceiveWindowSize();
  rws.set('ReceiveWindowSize', receiveWindowSize);
  connA1.set('ReceiveWindowSize', rws);

  const packet = new RTSHeader();
  packet.set('Flags', RTS_FLAG_NONE);
  packet.set('NumberOfCommands', connA1.structure.length);
  packet.set('pduData', connA1.getData());

  return packet.getData();
}

export function hCONN_B1(
  virtualConnectionCookie: Buffer = EMPTY_UUID,
  inChannelCookie: Buffer = EMPTY_UUID,
  associationGroupId: Buffer = EMPTY_UUID,
): Buffer {
  const connB1 = new CONN_B1_RTS_PDU();
  connB1.set('Version', new Version());
  const vcc = new Cookie();
  vcc.set('Cookie', virtualConnectionCookie);
  connB1.set('VirtualConnectionCookie', vcc);
  const icc = new Cookie();
  icc.set('Cookie', inChannelCookie);
  connB1.set('INChannelCookie', icc);
  connB1.set('ChannelLifetime', new ChannelLifetime());
  connB1.set('ClientKeepalive', new ClientKeepalive());
  const agid = new AssociationGroupId();
  const agidCookie = new RTSCookie();
  agidCookie.set('Cookie', associationGroupId);
  agid.set('AssociationGroupId', agidCookie);
  connB1.set('AssociationGroupId', agid);

  const packet = new RTSHeader();
  packet.set('Flags', RTS_FLAG_NONE);
  packet.set('NumberOfCommands', connB1.structure.length);
  packet.set('pduData', connB1.getData());

  return packet.getData();
}

export function hFlowControlAckWithDestination(
  destination: number,
  bytesReceived: number,
  availableWindow: number,
  channelCookie: Buffer,
): Buffer {
  const rtsPdu = new FlowControlAckWithDestination_RTS_PDU();
  const dest = new Destination();
  dest.set('Destination', destination);
  rtsPdu.set('Destination', dest);
  const fca = new FlowControlAck();
  const ack = new Ack();
  ack.set('BytesReceived', bytesReceived);
  ack.set('AvailableWindow', availableWindow);
  const cookie = new RTSCookie();
  cookie.set('Cookie', channelCookie);
  ack.set('ChannelCookie', cookie);
  fca.set('Ack', ack);
  rtsPdu.set('FlowControlAck', fca);

  const packet = new RTSHeader();
  packet.set('Flags', RTS_FLAG_OTHER_CMD);
  packet.set('NumberOfCommands', rtsPdu.structure.length);
  packet.set('pduData', rtsPdu.getData());

  return packet.getData();
}

export function hPing(): Buffer {
  const packet = new RTSHeader();
  packet.set('Flags', RTS_FLAG_PING);

  return packet.getData();
}

// =============================================================================
// RPC Proxy URL representation
// =============================================================================

export interface RpcProxyUrl {
  scheme: string;
  netloc: string;
  path: string;
  query: string;
}

// =============================================================================
// RPCProxyClient
// =============================================================================

/**
 * Helper to read data from a socket into a Promise.
 */
function socketRecv(socket: net.Socket, _size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const onData = (data: Buffer) => {
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      resolve(Buffer.from(data));
    };
    const onError = (err: Error) => {
      socket.removeListener('data', onData);
      socket.removeListener('close', onClose);
      reject(new RPCProxyClientException(`Socket error: ${err.message}`));
    };
    const onClose = () => {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      resolve(Buffer.alloc(0));
    };
    socket.once('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
  });
}

/**
 * Helper to send data over a socket, returned as a Promise.
 */
function socketSend(socket: net.Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => {
      if (err) reject(new RPCProxyClientException(`Socket send error: ${err.message}`));
      else resolve();
    });
  });
}

export class RPCProxyClient extends HTTPClientSecurityProvider {
  static RECV_SIZE = 8192;

  static defaultHeaders: Record<string, string> = {
    'User-Agent': 'MSRPC',
    'Cache-Control': 'no-cache',
    'Connection': 'Keep-Alive',
    'Expect': '100-continue',
    'Accept': 'application/rpc',
    'Pragma': 'No-cache',
  };

  private remoteName: string | null;
  private dstport: number;
  private authType: string | null = null;

  // Channel sockets
  private channels: Record<string, net.Socket> = {};

  // Connection cookies
  private inChannelCookie: Buffer = Buffer.alloc(0);
  private outChannelCookie: Buffer = Buffer.alloc(0);
  private associationGroupId: Buffer = Buffer.alloc(0);
  private virtualConnectionCookie: Buffer = Buffer.alloc(0);

  // Flow control state
  private serverConnectionTimeout: number | null = null;
  private serverReceiveWindowSize: number | null = null;
  private availableWindowAdvertised = 262144; // 256k
  private receiverAvailableWindow = 262144;
  private bytesReceivedCount = 0;

  // Chunked encoding state
  private serverChunked = false;
  private readBuffer: Buffer = Buffer.alloc(0);
  private chunkLeft = 0;

  rtsPingReceived = false;

  // These are set by the transport layer
  _rpcProxyUrl: RpcProxyUrl | null = null;
  _stringbinding: DCERPCStringBinding | null = null;

  constructor(remoteName: string | null = null, dstport = 593) {
    super();
    this.remoteName = remoteName;
    this.dstport = dstport;
    this.initState();
  }

  initState(): void {
    this.channels = {};

    this.inChannelCookie = uuidMod.generate();
    this.outChannelCookie = uuidMod.generate();
    this.associationGroupId = uuidMod.generate();
    this.virtualConnectionCookie = uuidMod.generate();

    this.serverConnectionTimeout = null;
    this.serverReceiveWindowSize = null;
    this.availableWindowAdvertised = 262144;
    this.receiverAvailableWindow = this.availableWindowAdvertised;
    this.bytesReceivedCount = 0;

    this.serverChunked = false;
    this.readBuffer = Buffer.alloc(0);
    this.chunkLeft = 0;

    this.rtsPingReceived = false;
  }

  setProxyCredentials(
    username: string,
    password: string,
    domain = '',
    lmhash = '',
    nthash = '',
  ): void {
    console.error(
      'DeprecationWarning: Call to deprecated method setProxyCredentials (use setCredentials).',
    );
    this.setCredentials(username, password, domain, lmhash, nthash);
  }

  private _ntlmUsername = '';
  private _ntlmPassword = '';
  private _ntlmDomain = '';
  private _ntlmLmhash: Buffer | string = '';
  private _ntlmNthash: Buffer | string = '';

  override setCredentials(
    username: string,
    password: string,
    domain = '',
    lmhash = '',
    nthash = '',
    aesKey = '',
    TGT: unknown = null,
    TGS: unknown = null,
  ): void {
    super.setCredentials(username, password, domain, lmhash, nthash, aesKey, TGT, TGS);
    this._ntlmUsername = username;
    this._ntlmPassword = password;
    this._ntlmDomain = domain;
    if (lmhash !== '' || nthash !== '') {
      let lm = lmhash; let nt = nthash;
      if (lm.length % 2) lm = '0' + lm;
      if (nt.length % 2) nt = '0' + nt;
      try { this._ntlmLmhash = Buffer.from(lm, 'hex'); } catch { this._ntlmLmhash = lm; }
      try { this._ntlmNthash = Buffer.from(nt, 'hex'); } catch { this._ntlmNthash = nt; }
    } else {
      this._ntlmLmhash = '';
      this._ntlmNthash = '';
    }
  }

  async createRpcInChannel(): Promise<void> {
    const headers = { ...RPCProxyClient.defaultHeaders };
    headers['Content-Length'] = '1073741824';
    await this.createChannel('RPC_IN_DATA', headers);
  }

  async createRpcOutChannel(): Promise<void> {
    const headers = { ...RPCProxyClient.defaultHeaders };
    headers['Content-Length'] = '76';
    await this.createChannel('RPC_OUT_DATA', headers);
  }

  private async readHttpResponse(socket: net.Socket): Promise<{ statusCode: number; headers: Record<string, string>; raw: Buffer }> {
    let buf = Buffer.alloc(0);
    while (!buf.includes(Buffer.from('\r\n\r\n'))) {
      const chunk = await socketRecv(socket, RPCProxyClient.RECV_SIZE);
      if (chunk.length === 0) throw new RPCProxyClientException('Connection closed during HTTP response');
      buf = Buffer.concat([buf, chunk]);
    }
    const headerEnd = buf.indexOf(Buffer.from('\r\n\r\n'));
    const headerSection = buf.subarray(0, headerEnd).toString('ascii');
    const lines = headerSection.split('\r\n');
    const statusLine = lines[0]!;
    const statusMatch = /HTTP\/\d\.\d (\d+)/.exec(statusLine);
    const statusCode = statusMatch ? parseInt(statusMatch[1]!, 10) : 0;
    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const idx = lines[i]!.indexOf(': ');
      if (idx >= 0) {
        const key = lines[i]!.substring(0, idx).toLowerCase();
        const val = lines[i]!.substring(idx + 2);
        if (key in headers) {
          headers[key] += ', ' + val;
        } else {
          headers[key] = val;
        }
      }
    }
    return { statusCode, headers, raw: buf };
  }

  private buildHttpRequest(method: string, path: string, headers: Record<string, string>): Buffer {
    const requestLine = `${method} ${path} HTTP/1.1\r\n`;
    const headerLines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n');
    return Buffer.from(requestLine + headerLines + '\r\n\r\n', 'ascii');
  }

  private ntlmType1: NTLMAuthNegotiate | null = null;

  private async createChannel(method: string, headers: Record<string, string>): Promise<void> {
    if (!this._rpcProxyUrl) {
      throw new RPCProxyClientException('RPC Proxy URL not set');
    }

    const url = this._rpcProxyUrl;
    const authType = this.getAuthType();
    this.authType = authType;

    if (!this.remoteName && authType === AUTH_BASIC) {
      throw new RPCProxyClientException(RPC_PROXY_REMOTE_NAME_NEEDED_ERR);
    }

    if (!url.query) {
      url.query = `${this.remoteName}:${this.dstport}`;
    }
    const path = url.path + '?' + url.query;

    let socket = await this.connectSocket(url.scheme, url.netloc);

    if (authType === AUTH_BASIC) {
      this.channels[method] = socket;
      const [basicHeaders] = this.getAuthHeadersBasic();
      const finalHeaders = { ...headers, ...basicHeaders };
      finalHeaders['Host'] = url.netloc;
      await socketSend(socket, this.buildHttpRequest(method, path, finalHeaders));
      await this.read100Continue(method);
      return;
    }

    // NTLM authentication over raw socket (3-step handshake)
    // Step 1: Send Type1 (Negotiate) message
    const type1 = getNTLMSSPType1('', '', false, true);
    this.ntlmType1 = type1;
    const type1Data = type1.getData();

    const authHeaders1: Record<string, string> = {
      'User-Agent': 'MSRPC',
      'Host': url.netloc,
      'Connection': 'Keep-Alive',
      'Content-Length': '0',
      'Authorization': `NTLM ${type1Data.toString('base64')}`,
    };

    await socketSend(socket, this.buildHttpRequest(method, path, authHeaders1));
    const resp1 = await this.readHttpResponse(socket);

    if (resp1.statusCode !== 401) {
      throw new RPCProxyClientException(
        `NTLM Type1: expected 401, got ${resp1.statusCode}`,
      );
    }

    // Extract Type2 (Challenge) from WWW-Authenticate header
    const wwwAuth = resp1.headers['www-authenticate'] ?? '';
    const type2Match = /NTLM ([a-zA-Z0-9+/]+=*)/.exec(wwwAuth);
    if (!type2Match) {
      throw new RPCProxyClientException('No NTLM challenge in 401 response');
    }
    const type2Data = Buffer.from(type2Match[1]!, 'base64');

    // Extract server hostname from NTLMSSP challenge for remoteName
    if (!this.remoteName) {
      try {
        const challenge = new NTLMAuthChallenge(type2Data);
        const tiRaw = challenge.get('TargetInfoFields') as Buffer;
        if (tiRaw && tiRaw.length > 0) {
          const avPairs = new AV_PAIRS(tiRaw);
          const hostnameEntry = avPairs.fields.get(NTLMSSP_AV_HOSTNAME);
          if (hostnameEntry) {
            this.remoteName = hostnameEntry[1].toString('utf16le');
            if (this._stringbinding) {
              this._stringbinding.setNetworkAddress(this.remoteName);
            }
            url.query = `${this.remoteName}:${this.dstport}`;
          }
        }
      } catch { /* ignore */ }
    }

    // Step 2: Build Type3 (Authenticate) and send on same connection
    const [type3] = getNTLMSSPType3(
      type1, type2Data,
      this._ntlmUsername, this._ntlmPassword, this._ntlmDomain,
      this._ntlmLmhash, this._ntlmNthash, true,
    );
    const type3Data = type3.getData();

    // Read and drain any remaining body from the 401 response
    const contentLenStr = resp1.headers['content-length'];
    if (contentLenStr) {
      const bodyLen = parseInt(contentLenStr, 10);
      const headerEnd = resp1.raw.indexOf(Buffer.from('\r\n\r\n'));
      const bodyReceived = resp1.raw.length - (headerEnd + 4);
      let remaining = bodyLen - bodyReceived;
      while (remaining > 0) {
        const chunk = await socketRecv(socket, Math.min(remaining, RPCProxyClient.RECV_SIZE));
        remaining -= chunk.length;
      }
    }

    // Final authenticated request with the real channel headers
    const finalPath = url.path + '?' + url.query;
    const finalHeaders: Record<string, string> = {
      ...headers,
      'Host': url.netloc,
      'Authorization': `NTLM ${type3Data.toString('base64')}`,
    };

    this.channels[method] = socket;
    await socketSend(socket, this.buildHttpRequest(method, finalPath, finalHeaders));
    await this.read100Continue(method);
  }

  private async connectSocket(scheme: string, netloc: string): Promise<net.Socket> {
    const [host, portStr] = netloc.split(':');
    const defaultPort = scheme === 'https' ? 443 : 80;
    const port = portStr ? parseInt(portStr, 10) : defaultPort;

    return new Promise((resolve, reject) => {
      let socket: net.Socket;
      if (scheme === 'https') {
        socket = tls.connect(
          { host: host ?? netloc, port, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] },
          () => resolve(socket),
        );
      } else {
        socket = net.createConnection({ host: host ?? netloc, port }, () => resolve(socket));
      }
      socket.setNoDelay(true);
      socket.on('error', (err) => {
        reject(new RPCProxyClientException(`Connection failed: ${err.message}`));
      });
    });
  }


  private async read100Continue(method: string): Promise<void> {
    const socket = this.channels[method];
    if (!socket) {
      throw new RPCProxyClientException(`Channel ${method} not found`);
    }

    let resp = await socketRecv(socket, RPCProxyClient.RECV_SIZE);

    while (!resp.includes(Buffer.from('\r\n\r\n'))) {
      const more = await socketRecv(socket, RPCProxyClient.RECV_SIZE);
      resp = Buffer.concat([resp, more]);
    }

    // Continue responses can have multiple lines, for example:
    //
    // HTTP/1.1 100 Continue
    // Via: 1.1 FIREWALL1
    //
    // Don't expect the response to contain "100 Continue\r\n\r\n"
    const statusSlice = resp.subarray(9, 23);
    if (!statusSlice.equals(Buffer.from('100 Continue\r\n'))) {
      try {
        const crlfIdx = resp.indexOf(Buffer.from('\r\n'));
        const firstLine = crlfIdx >= 0
          ? resp.subarray(0, crlfIdx).toString('utf-8')
          : resp.toString('utf-8');

        throw new RPCProxyClientException(
          `RPC Proxy Client: ${this.authType ?? 'unknown'} authentication failed in ${method} channel`,
          firstLine,
        );
      } catch (e) {
        if (e instanceof RPCProxyClientException) throw e;
        throw new RPCProxyClientException(
          `RPC Proxy Client: ${this.authType ?? 'unknown'} authentication failed in ${method} channel`,
        );
      }
    }
  }

  async createTunnel(): Promise<void> {
    // 3.2.1.5.3.1 Connection Establishment
    const packetA1 = hCONN_A1(
      this.virtualConnectionCookie,
      this.outChannelCookie,
      this.availableWindowAdvertised,
    );
    await socketSend(this.getSocketOut(), packetA1);

    const packetB1 = hCONN_B1(
      this.virtualConnectionCookie,
      this.inChannelCookie,
      this.associationGroupId,
    );
    await socketSend(this.getSocketIn(), packetB1);

    let resp = await socketRecv(this.getSocketOut(), RPCProxyClient.RECV_SIZE);

    while (!resp.includes(Buffer.from('\r\n\r\n'))) {
      const more = await socketRecv(this.getSocketOut(), RPCProxyClient.RECV_SIZE);
      resp = Buffer.concat([resp, more]);
    }

    if (!resp.subarray(9, 12).equals(Buffer.from('200'))) {
      try {
        const crlfIdx = resp.indexOf(Buffer.from('\r\n'));
        const firstLine = crlfIdx >= 0
          ? resp.subarray(0, crlfIdx).toString('utf-8')
          : resp.toString('utf-8');

        throw new RPCProxyClientException(
          'RPC Proxy CONN/A1 request failed',
          firstLine,
        );
      } catch (e) {
        if (e instanceof RPCProxyClientException) throw e;
        throw new RPCProxyClientException('RPC Proxy CONN/A1 request failed');
      }
    }

    const respAscii = resp.toString('ascii');
    if (respAscii.toLowerCase().includes('transfer-encoding: chunked')) {
      this.serverChunked = true;
    }

    // If the body is here, send it to rpcOutRecv1()
    const bodyStart = resp.indexOf(Buffer.from('\r\n\r\n'));
    this.readBuffer = resp.subarray(bodyStart + 4);

    // Receiving and parsing CONN/A3
    const connA3Rpc = await this.rpcOutReadPkt();
    const connA3Pdu = new RTSHeader(connA3Rpc).get('pduData') as Buffer;
    const connA3 = new CONN_A3_RTS_PDU(connA3Pdu);
    const connA3Timeout = connA3.get('ConnectionTimeout') as Structure;
    this.serverConnectionTimeout = connA3Timeout.get('ConnectionTimeout') as number;

    // Receiving and parsing CONN/C2
    const connC2Rpc = await this.rpcOutReadPkt();
    const connC2Pdu = new RTSHeader(connC2Rpc).get('pduData') as Buffer;
    const connC2 = new CONN_C2_RTS_PDU(connC2Pdu);
    const connC2Rws = connC2.get('ReceiveWindowSize') as Structure;
    this.serverReceiveWindowSize = connC2Rws.get('ReceiveWindowSize') as number;
  }

  getSocketIn(): net.Socket {
    const sock = this.channels['RPC_IN_DATA'];
    if (!sock) throw new RPCProxyClientException('RPC_IN_DATA channel not connected');
    return sock;
  }

  getSocketOut(): net.Socket {
    const sock = this.channels['RPC_OUT_DATA'];
    if (!sock) throw new RPCProxyClientException('RPC_OUT_DATA channel not connected');
    return sock;
  }

  closeRpcInChannel(): void {
    const sock = this.channels['RPC_IN_DATA'];
    if (sock) {
      sock.destroy();
      delete this.channels['RPC_IN_DATA'];
    }
  }

  closeRpcOutChannel(): void {
    const sock = this.channels['RPC_OUT_DATA'];
    if (sock) {
      sock.destroy();
      delete this.channels['RPC_OUT_DATA'];
    }
  }

  checkHttpError(buffer: Buffer): void {
    if (buffer.subarray(0, 22).equals(Buffer.from('HTTP/1.0 503 RPC Error'))) {
      throw new RPCProxyClientException(
        'RPC Proxy request failed',
        buffer.toString('utf-8'),
      );
    }
  }

  async rpcOutRecv1(amt?: number): Promise<Buffer> {
    // Read with at most one underlying system call.
    // The function MUST return the maximum amt bytes.
    const effectiveAmt = amt ?? RPCProxyClient.RECV_SIZE;
    const sock = this.getSocketOut();

    if (!this.serverChunked) {
      let buffer: Buffer;

      if (this.readBuffer.length > 0) {
        buffer = this.readBuffer;
        this.readBuffer = Buffer.alloc(0);
      } else {
        // Read RECV_SIZE bytes and not amt bytes.
        // Check the answer for HTTP errors.
        buffer = await socketRecv(sock, RPCProxyClient.RECV_SIZE);
      }

      this.checkHttpError(buffer);

      if (buffer.length <= effectiveAmt) {
        return buffer;
      }

      // We received more than we need
      this.readBuffer = buffer.subarray(effectiveAmt);
      return buffer.subarray(0, effectiveAmt);
    }

    // Chunked encoding handling

    // Check if the previous chunk is still there
    if (this.chunkLeft > 0) {
      if (effectiveAmt >= this.chunkLeft) {
        const buffer = this.readBuffer.subarray(0, this.chunkLeft);
        // We may have received a part of a new chunk
        this.readBuffer = this.readBuffer.subarray(this.chunkLeft + 2);
        this.chunkLeft = 0;
        return buffer;
      } else {
        const buffer = this.readBuffer.subarray(0, effectiveAmt);
        this.readBuffer = this.readBuffer.subarray(effectiveAmt);
        this.chunkLeft -= effectiveAmt;
        return buffer;
      }
    }

    // Start processing a new chunk
    let buffer = this.readBuffer;
    this.readBuffer = Buffer.alloc(0);

    this.checkHttpError(buffer);

    // Receive chunk size field which ends with CRLF
    const CRLF = Buffer.from('\r\n');
    while (!buffer.includes(CRLF)) {
      const more = await socketRecv(sock, RPCProxyClient.RECV_SIZE);
      buffer = Buffer.concat([buffer, more]);
      this.checkHttpError(buffer);
    }

    const crlfPos = buffer.indexOf(CRLF);
    const chunksize = parseInt(buffer.subarray(0, crlfPos).toString('ascii'), 16);
    buffer = buffer.subarray(crlfPos + 2);

    // Read at least our chunk including final CRLF
    while (buffer.length - 2 < chunksize) {
      const more = await socketRecv(sock, chunksize - buffer.length + 2);
      buffer = Buffer.concat([buffer, more]);
    }

    // We should not be using any information from
    // the TCP level to determine HTTP boundaries.
    if (buffer.length - 2 > chunksize) {
      this.readBuffer = buffer.subarray(chunksize + 2);
      buffer = buffer.subarray(0, chunksize + 2);
    }

    // Checking the amt
    if (buffer.length - 2 > effectiveAmt) {
      this.chunkLeft = chunksize - effectiveAmt;
      // We may have received a part of a new chunk before,
      // so the concatenation is crucial
      this.readBuffer = Buffer.concat([buffer.subarray(effectiveAmt), this.readBuffer]);
      return buffer.subarray(0, effectiveAmt);
    } else {
      // Removing CRLF
      return buffer.subarray(0, buffer.length - 2);
    }
  }

  async send(data: Buffer, _forceWriteAndx = 0, _forceRecv = 0): Promise<void> {
    // We don't use chunked encoding for IN channel as
    // Microsoft software is developed this way.
    // If you do this, it may fail.
    await socketSend(this.getSocketIn(), data);
  }

  async rpcOutReadPkt(handleRts = false): Promise<Buffer> {
    while (true) {
      let responseData = Buffer.alloc(0);

      // Receive common RPC header and no more
      //
      // C706 12.4 Common Fields
      // This MUST recv MSRPCHeader._SIZE bytes, and not MSRPCRespHeader._SIZE bytes!
      while (responseData.length < MSRPCHeader._SIZE) {
        const chunk = await this.rpcOutRecv1(MSRPCHeader._SIZE - responseData.length);
        responseData = Buffer.concat([responseData, chunk]);
      }

      const responseHeader = new MSRPCHeader(responseData);

      // frag_len contains the full length of the packet for both MSRPC and RTS
      const fragLen = responseHeader.get('frag_len') as number;

      // Receiving the full pkt and no more
      while (responseData.length < fragLen) {
        const chunk = await this.rpcOutRecv1(fragLen - responseData.length);
        responseData = Buffer.concat([responseData, chunk]);
      }

      // Flow Control procedures
      //
      // 3.2.1.1.4
      // Only RPC PDUs are subject to flow control.
      // RTS PDUs and HTTP request/response headers are not subject to flow control.
      if ((responseHeader.get('type') as number) !== MSRPC_RTS) {
        this.flowControl(fragLen);
      }

      if (handleRts && (responseHeader.get('type') as number) === MSRPC_RTS) {
        await this.handleOutOfSequenceRts(responseData);
      } else {
        return responseData;
      }
    }
  }

  async recv(_forceRecv = 0, _count = 0): Promise<Buffer> {
    return this.rpcOutReadPkt(true);
  }

  async handleOutOfSequenceRts(responseData: Buffer): Promise<void> {
    const packet = new RTSHeader(responseData);

    // 2.2.4.49 Ping RTS PDU
    if ((packet.get('Flags') as number) === RTS_FLAG_PING) {
      // 3.2.1.2.1 PingTimer
      //
      // As we do not do long-term connections with no data transfer,
      // it means something on the server-side is going wrong.
      this.rtsPingReceived = true;
      console.error('Ping RTS PDU packet received. Is the RPC Server alive?');

      // Send PING PDU to IN Channel like in xfreerdp
      const pingPacket = hPing();
      await this.send(pingPacket);
      await this.send(pingPacket);
    }
    // 2.2.4.24 OUT_R1/A2 RTS PDU
    else if ((packet.get('Flags') as number) === RTS_FLAG_RECYCLE_CHANNEL) {
      throw new RPCProxyClientException(
        'The server requested recycling of a virtual OUT channel, ' +
        'but this function is not supported!',
      );
    }
    // Ignore all other messages, most probably flow control acknowledgments
  }

  flowControl(fragLen: number): void {
    this.bytesReceivedCount += fragLen;
    this.receiverAvailableWindow -= fragLen;

    if (this.receiverAvailableWindow < Math.floor(this.availableWindowAdvertised / 2)) {
      this.receiverAvailableWindow = this.availableWindowAdvertised;
      const packet = hFlowControlAckWithDestination(
        FD_OUT_PROXY,
        this.bytesReceivedCount,
        this.availableWindowAdvertised,
        this.outChannelCookie,
      );
      // Fire-and-forget send for flow control ack
      socketSend(this.getSocketIn(), packet).catch(() => {
        // Ignore send errors during flow control
      });
    }
  }

  async connectProxy(): Promise<void> {
    await this.createRpcInChannel();
    await this.createRpcOutChannel();
    await this.createTunnel();
  }

  disconnectProxy(): void {
    this.closeRpcInChannel();
    this.closeRpcOutChannel();
    this.initState();
  }
}
