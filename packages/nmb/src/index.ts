import { Buffer } from 'node:buffer';
import dgram from 'node:dgram';
import { Socket } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

import { Structure, type FieldDescriptor } from '@impacket/structure';

export const INADDR_ANY = '0.0.0.0';
export const BROADCAST_ADDR = '<broadcast>';

export const NETBIOS_NS_PORT = 137;
export const NETBIOS_SESSION_PORT = 139;
export const SMB_SESSION_PORT = 445;

export const NODE_B = 0x0000;
export const NODE_P = 0x2000;
export const NODE_M = 0x4000;
export const NODE_RESERVED = 0x6000;
export const NODE_GROUP = 0x8000;
export const NODE_UNIQUE = 0x0;

export const TYPE_UNKNOWN = 0x01;
export const TYPE_WORKSTATION = 0x00;
export const TYPE_CLIENT = 0x03;
export const TYPE_SERVER = 0x20;
export const TYPE_DOMAIN_MASTER = 0x1b;
export const TYPE_DOMAIN_CONTROLLER = 0x1c;
export const TYPE_MASTER_BROWSER = 0x1d;
export const TYPE_BROWSER = 0x1e;
export const TYPE_NETDDE = 0x1f;
export const TYPE_STATUS = 0x21;

export const OPCODE_QUERY = 0;
export const OPCODE_REGISTRATION = 0x5 << 11;
export const OPCODE_RELEASE = 0x6 << 11;
export const OPCODE_WACK = 0x7 << 11;
export const OPCODE_REFRESH = 0x8 << 11;
export const OPCODE_REQUEST = 0 << 11;
export const OPCODE_RESPONSE = 0x10 << 11;

export const NM_FLAGS_BROADCAST = 0x1 << 4;
export const NM_FLAGS_UNICAST = 0 << 4;
export const NM_FLAGS_RA = 0x8 << 4;
export const NM_FLAGS_RD = 0x10 << 4;
export const NM_FLAGS_TC = 0x20 << 4;
export const NM_FLAGS_AA = 0x40 << 4;

export const QUESTION_TYPE_NB = 0x20;
export const QUESTION_TYPE_NBSTAT = 0x21;
export const QUESTION_CLASS_IN = 0x1;

export const RR_TYPE_A = 0x1;
export const RR_TYPE_NS = 0x2;
export const RR_TYPE_NULL = 0xa;
export const RR_TYPE_NB = 0x20;
export const RR_TYPE_NBSTAT = 0x21;
export const RR_CLASS_IN = 1;

export const RCODE_FMT_ERR = 0x1;
export const RCODE_SRV_ERR = 0x2;
export const RCODE_IMP_ERR = 0x4;
export const RCODE_RFS_ERR = 0x5;
export const RCODE_ACT_ERR = 0x6;
export const RCODE_CFT_ERR = 0x7;

export const NAME_FLAGS_PRM = 0x0200;
export const NAME_FLAGS_ACT = 0x0400;
export const NAME_FLAG_CNF = 0x0800;
export const NAME_FLAG_DRG = 0x1000;

export const NB_FLAGS_ONT_B = 0;
export const NB_FLAGS_ONT_P = 1 << 13;
export const NB_FLAGS_ONT_M = 2 << 13;
export const NB_FLAGS_G = 1 << 15;

export const NAME_TYPES: Record<number, string> = {
  [TYPE_UNKNOWN]: 'Unknown',
  [TYPE_WORKSTATION]: 'Workstation',
  [TYPE_CLIENT]: 'Client',
  [TYPE_SERVER]: 'Server',
  [TYPE_DOMAIN_MASTER]: 'Domain Master',
  [TYPE_DOMAIN_CONTROLLER]: 'Domain Controller',
  [TYPE_MASTER_BROWSER]: 'Master Browser',
  [TYPE_BROWSER]: 'Browser Server',
  [TYPE_NETDDE]: 'NetDDE Server',
  [TYPE_STATUS]: 'Status',
};

export const NETBIOS_SESSION_MESSAGE = 0x0;
export const NETBIOS_SESSION_REQUEST = 0x81;
export const NETBIOS_SESSION_POSITIVE_RESPONSE = 0x82;
export const NETBIOS_SESSION_NEGATIVE_RESPONSE = 0x83;
export const NETBIOS_SESSION_RETARGET_RESPONSE = 0x84;
export const NETBIOS_SESSION_KEEP_ALIVE = 0x85;

export const ERRCLASS_QUERY = 0x00;
export const ERRCLASS_SESSION = 0xf0;
export const ERRCLASS_OS = 0xff;

export const QUERY_ERRORS: Record<number, string> = {
  1: 'Format Error. Request was invalidly formatted',
  2: 'Server failure. Problem with NBNS, cannot process name.',
  3: 'Name does not exist',
  4: 'Unsupported request error.  Allowable only for challenging NBNS when gets an Update type registration request.',
  5: 'Refused error.  For policy reasons server will not register this name from this host.',
  6: 'Active error.  Name is owned by another node.',
  7: 'Name in conflict error.  A UNIQUE name is owned by more than one node.',
};

export const SESSION_ERRORS: Record<number, string> = {
  128: 'Not listening on called name',
  129: 'Not listening for calling name',
  130: 'Called name not present',
  131: 'Sufficient resources',
  143: 'Unspecified error',
};

export class NetBIOSError extends Error {
  error_class: number | null;
  error_code: number | null;
  error_msg: string;

  constructor(
    error_message = '',
    error_class: number | null = null,
    error_code: number | null = null,
  ) {
    super(error_message);
    this.error_class = error_class;
    this.error_code = error_code;
    this.error_msg = error_message;
  }

  get_error_code(): number | null {
    return this.error_code;
  }

  get_error_class(): number | null {
    return this.error_class;
  }

  toString(): string {
    return `NetBIOSError: ${this.error_msg}`;
  }
}

export class NetBIOSTimeout extends Error {
  constructor(message = 'Timeout') {
    super(message);
  }
}

const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

export function encode_name(name: string, nametype: number, scope: string): Buffer {
  if (name === '*') {
    name = name + '\0'.repeat(15);
  } else if (name.length > 15) {
    name = name.slice(0, 15) + String.fromCharCode(nametype);
  } else {
    name = name.padEnd(15, ' ') + String.fromCharCode(nametype);
  }

  const encoded = Buffer.alloc(name.length * 2);
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    encoded[i * 2] = ALPHA.charCodeAt(c >> 4);
    encoded[i * 2 + 1] = ALPHA.charCodeAt(c & 0x0f);
  }

  const parts: Buffer[] = [Buffer.from([name.length * 2]), encoded];

  if (scope) {
    for (const s of scope.split('.')) {
      parts.push(Buffer.from([s.length]));
      parts.push(Buffer.from(s, 'utf8'));
    }
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function doFirstLevelDecoding(c1: number, c2: number): number {
  return ((c1 - ALPHA.charCodeAt(0)) << 4) | (c2 - ALPHA.charCodeAt(0));
}

export function decode_name(name: Buffer): [number, string, string] {
  const name_length = name[0]!;
  if (name_length !== 32) throw new NetBIOSError(`Invalid name length ${name_length}`);

  const encoded = name.subarray(1, 33);
  const decodedChars: number[] = [];
  for (let i = 0; i < 16; i++) {
    decodedChars.push(doFirstLevelDecoding(encoded[i * 2]!, encoded[i * 2 + 1]!));
  }
  const decoded_name = Buffer.from(decodedChars).toString('latin1');

  if (name[33] === 0) {
    return [34, decoded_name, ''];
  }

  let decoded_domain = '';
  let offset = 33;
  while (offset < name.length) {
    const domain_length = name[offset]!;
    if (domain_length === 0) break;
    offset += 1;
    decoded_domain += '.' + name.subarray(offset, offset + domain_length).toString('utf8');
    offset += domain_length;
  }
  return [offset + 1, decoded_name, decoded_domain];
}

export class NetBIOSSessionPacket {
  type = 0x0;
  flags = 0x0;
  length = 0x0;
  private _trailer: Buffer = Buffer.alloc(0);

  constructor(data?: Buffer) {
    if (data !== undefined && data !== null) {
      try {
        this.type = data[0]!;
        if (this.type === NETBIOS_SESSION_MESSAGE) {
          this.length = (data[1]! << 16) | data.readUInt16BE(2);
        } else {
          this.flags = data[1]!;
          this.length = data.readUInt16BE(2);
        }
        this._trailer = data.subarray(4);
      } catch {
        throw new NetBIOSError('Wrong packet format');
      }
    }
  }

  set_type(type: number): void {
    this.type = type;
  }

  get_type(): number {
    return this.type;
  }

  rawData(): Buffer {
    const hdr = Buffer.alloc(4);
    if (this.type === NETBIOS_SESSION_MESSAGE) {
      hdr.writeUInt8(this.type, 0);
      hdr.writeUInt8((this.length >> 16) & 0xff, 1);
      hdr.writeUInt16BE(this.length & 0xffff, 2);
    } else {
      hdr.writeUInt8(this.type, 0);
      hdr.writeUInt8(this.flags, 1);
      hdr.writeUInt16BE(this.length, 2);
    }
    return Buffer.concat([hdr, this._trailer]);
  }

  set_trailer(data: Buffer): void {
    this._trailer = data;
    this.length = data.length;
  }

  get_length(): number {
    return this.length;
  }

  get_trailer(): Buffer {
    return this._trailer;
  }
}

export class NetBIOSSession {
  protected myname: string;
  protected local_type: number;
  protected remote_name: string;
  protected remote_type: number;
  protected remote_host: string;
  protected _sock: Socket | null;

  constructor(
    myname: string,
    remote_name: string,
    remote_host: string,
    remote_type = TYPE_SERVER,
    sess_port = NETBIOS_SESSION_PORT,
    timeout: number | null = null,
    local_type = TYPE_WORKSTATION,
    sock: Socket | null = null,
  ) {
    this.myname = myname.length > 15 ? myname.slice(0, 15).toUpperCase() : myname.toUpperCase();
    this.local_type = local_type;

    let rn = remote_name;
    if (rn === '*SMBSERVER' && sess_port === SMB_SESSION_PORT) {
      rn = remote_host;
    }

    this.remote_name = rn.length > 15 ? rn.slice(0, 15).toUpperCase() : rn.toUpperCase();
    this.remote_type = remote_type;
    this.remote_host = remote_host;

    if (sock !== null) {
      this._sock = sock;
    } else {
      this._sock = this.setupConnection(remote_host, sess_port, timeout);
    }

    if (sess_port === NETBIOS_SESSION_PORT) {
      this.requestSession(remote_type, local_type, timeout);
    }
  }

  protected setupConnection(_host: string, _port: number, _timeout: number | null): Socket {
    throw new Error('Not Implemented!');
  }

  protected requestSession(
    _remote_type: number,
    _local_type: number,
    _timeout: number | null,
  ): void {
    throw new Error('Not Implemented!');
  }

  get_myname(): string {
    return this.myname;
  }

  get_mytype(): number {
    return this.local_type;
  }

  get_remote_host(): string {
    return this.remote_host;
  }

  get_remote_name(): string {
    return this.remote_name;
  }

  get_remote_type(): number {
    return this.remote_type;
  }

  close(): void {
    this._sock?.destroy();
  }

  get_socket(): Socket | null {
    return this._sock;
  }
}

export class NetBIOSTCPSession extends NetBIOSSession {
  private select_poll: boolean;
  private read_function: (read_length: number, timeout: number | null) => Promise<Buffer>;
  private _recvBuffer: Buffer = Buffer.alloc(0);
  private _recvWaiters: Array<{ length: number; resolve: (data: Buffer) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }> = [];

  constructor(
    myname: string,
    remote_name: string,
    remote_host: string,
    remote_type = TYPE_SERVER,
    sess_port = NETBIOS_SESSION_PORT,
    timeout: number | null = null,
    local_type = TYPE_WORKSTATION,
    sock: Socket | null = null,
    select_poll = false,
  ) {
    super(myname, remote_name, remote_host, remote_type, sess_port, timeout, local_type, sock);
    this.select_poll = select_poll;
    this.read_function = select_poll ? this.pollingRead : this.bufferedRead;

    if (this._sock) {
      this._sock.on('data', (chunk: Buffer) => {
        this._recvBuffer = Buffer.concat([this._recvBuffer, chunk]);
        this._drainBuffer();
      });
      this._sock.on('error', (err: Error) => {
        const waiters = this._recvWaiters.splice(0);
        for (const w of waiters) {
          clearTimeout(w.timer);
          w.reject(new NetBIOSError(`Error while reading: ${err.message}`, ERRCLASS_OS, null));
        }
      });
      this._sock.on('close', () => {
        const waiters = this._recvWaiters.splice(0);
        for (const w of waiters) {
          clearTimeout(w.timer);
          w.reject(new NetBIOSError('Connection closed while reading', ERRCLASS_OS, null));
        }
      });
    }
  }

  private _drainBuffer(): void {
    while (this._recvWaiters.length > 0 && this._recvBuffer.length >= this._recvWaiters[0]!.length) {
      const waiter = this._recvWaiters.shift()!;
      clearTimeout(waiter.timer);
      const data = this._recvBuffer.subarray(0, waiter.length);
      this._recvBuffer = this._recvBuffer.subarray(waiter.length);
      waiter.resolve(data);
    }
  }

  private async bufferedRead(read_length: number, timeout: number | null): Promise<Buffer> {
    if (this._recvBuffer.length >= read_length) {
      const data = this._recvBuffer.subarray(0, read_length);
      this._recvBuffer = this._recvBuffer.subarray(read_length);
      return data;
    }

    const actualTimeout = timeout ?? 3600;
    return new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this._recvWaiters.findIndex((w) => w.resolve === resolve);
        if (idx >= 0) this._recvWaiters.splice(idx, 1);
        reject(new NetBIOSTimeout());
      }, actualTimeout * 1000);

      this._recvWaiters.push({ length: read_length, resolve, reject, timer });
      this._drainBuffer();
    });
  }

  protected setupConnection(host: string, port: number, timeout: number | null): Socket {
    const sock = new Socket();
    sock.setNoDelay(true);
    if (timeout !== null) {
      sock.setTimeout(timeout * 1000);
    }
    sock.on('error', () => {});
    sock.connect(port, host);
    return sock;
  }

  static async withProxy(
    myname: string,
    remote_name: string,
    remote_host: string,
    remote_type = TYPE_SERVER,
    sess_port = NETBIOS_SESSION_PORT,
    timeout: number | null = null,
    local_type = TYPE_WORKSTATION,
  ): Promise<NetBIOSTCPSession> {
    const { getGlobalProxy, socks5Connect } = await import('@impacket/socks');
    const proxy = getGlobalProxy();
    let sock: Socket | null = null;
    if (proxy) {
      sock = await socks5Connect(remote_host, sess_port, proxy);
      if (timeout !== null) sock.setTimeout(timeout * 1000);
    }
    return new NetBIOSTCPSession(myname, remote_name, remote_host, remote_type, sess_port, timeout, local_type, sock);
  }

  protected async waitForConnection(): Promise<void> {
    if (!this._sock) return;
    if (this._sock.readyState === 'open') return;
    return new Promise((resolve, reject) => {
      if (!this._sock) return resolve();
      const onConnect = () => {
        this._sock?.removeListener('error', onError);
        resolve();
      };
      const onError = (err: Error) => {
        this._sock?.removeListener('connect', onConnect);
        reject(new NetBIOSError(`Connection error: ${err.message}`));
      };
      this._sock.once('connect', onConnect);
      this._sock.once('error', onError);
    });
  }

  async sendPacket(data: Buffer): Promise<void> {
    await this.waitForConnection();
    const p = new NetBIOSSessionPacket();
    p.set_type(NETBIOS_SESSION_MESSAGE);
    p.set_trailer(data);
    const raw = p.rawData();
    return new Promise((resolve, reject) => {
      if (!this._sock || this._sock.destroyed) {
        reject(new NetBIOSError('Socket not connected'));
        return;
      }
      this._sock.write(raw, (err) => {
        if (err) reject(new NetBIOSError(`Write error: ${err.message}`));
        else resolve();
      });
    });
  }

  async recvPacket(timeout: number | null = null): Promise<NetBIOSSessionPacket> {
    const data = await this.read(timeout);
    const NBSPacket = new NetBIOSSessionPacket(data);
    if (NBSPacket.get_type() === NETBIOS_SESSION_KEEP_ALIVE) {
      return this.recvPacket(timeout);
    }
    return NBSPacket;
  }

  protected async requestSession(
    remote_type: number,
    local_type: number,
    timeout: number | null,
  ): Promise<void> {
    await this.waitForConnection();
    const p = new NetBIOSSessionPacket();
    const remote_name = encode_name(this.remote_name, remote_type, '');
    const myname = encode_name(this.myname, local_type, '');
    p.set_type(NETBIOS_SESSION_REQUEST);
    p.set_trailer(Buffer.concat([remote_name, myname]));

    const raw = p.rawData();
    await new Promise<void>((resolve, reject) => {
      if (!this._sock || this._sock.destroyed) {
        reject(new NetBIOSError('Socket not connected'));
        return;
      }
      this._sock.write(raw, (err) => {
        if (err) reject(new NetBIOSError(`Write error: ${err.message}`));
        else resolve();
      });
    });

    while (true) {
      const resp = await this.recvPacket(timeout);
      if (resp.get_type() === NETBIOS_SESSION_NEGATIVE_RESPONSE) {
        throw new NetBIOSError(`Cannot request session (Called Name:${this.remote_name})`);
      }
      if (resp.get_type() === NETBIOS_SESSION_POSITIVE_RESPONSE) {
        break;
      }
    }
  }

  private async pollingRead(read_length: number, timeout: number | null): Promise<Buffer> {
    const actualTimeout = timeout ?? 3600;
    let timeLeft = actualTimeout;
    const CHUNK_TIME = 0.025;
    let data = Buffer.alloc(0);
    let bytesLeft = read_length;

    while (bytesLeft > 0) {
      if (timeLeft <= 0) throw new NetBIOSTimeout();
      await sleep(CHUNK_TIME * 1000);
      timeLeft -= CHUNK_TIME;

      if (!this._sock) throw new NetBIOSError('Socket not connected');
      const chunk = this._sock.read(bytesLeft);
      if (chunk) {
        data = Buffer.concat([data, chunk]);
        bytesLeft = read_length - data.length;
      }
    }
    return data;
  }

  private async read(timeout: number | null = null): Promise<Buffer> {
    const header = await this.read_function(4, timeout);
    const type = header[0]!;
    const flags = header[1]!;
    let bodyLength = header.readUInt16BE(2);
    if (type === NETBIOS_SESSION_MESSAGE) {
      bodyLength |= flags << 16;
    } else {
      if (flags & 0x01) bodyLength |= 0x10000;
    }
    const body = await this.read_function(bodyLength, timeout);
    return Buffer.concat([header, body]);
  }
}

////////////////////////////////////////////////////////////////////////////////
// 4.2 NAME SERVER PACKETS
////////////////////////////////////////////////////////////////////////////////

// 4.2.18. NODE STATUS RESPONSE - Node name entry
export class NODE_NAME_ENTRY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['NAME', '15s=b""'],
    ['TYPE', 'B=0'],
    ['NAME_FLAGS', '>H'],
  ];
}

// 4.2.18. NODE STATUS RESPONSE - Statistics
export class STATISTICS extends Structure {
  static override structure: FieldDescriptor[] = [
    ['UNIT_ID', '6s=b""'],
    ['JUMPERS', 'B'],
    ['TEST_RESULT', 'B'],
    ['VERSION_NUMBER', '>H'],
    ['PERIOD_OF_STATISTICS', '>H'],
    ['NUMBER_OF_CRCs', '>H'],
    ['NUMBER_ALIGNMENT_ERRORS', '>H'],
    ['NUMBER_OF_COLLISIONS', '>H'],
    ['NUMBER_SEND_ABORTS', '>H'],
    ['NUMBER_GOOD_SENDS', '>L'],
    ['NUMBER_GOOD_RECEIVES', '>L'],
    ['NUMBER_RETRANSMITS', '>H'],
    ['NUMBER_NO_RESOURCE_CONDITIONS', '>H'],
    ['NUMBER_FREE_COMMAND_BLOCKS', '>H'],
    ['TOTAL_NUMBER_COMMAND_BLOCKS', '>H'],
    ['MAX_TOTAL_NUMBER_COMMAND_BLOCKS', '>H'],
    ['NUMBER_PENDING_SESSIONS', '>H'],
    ['MAX_NUMBER_PENDING_SESSIONS', '>H'],
    ['MAX_TOTAL_SESSIONS_POSSIBLE', '>H'],
    ['SESSION_DATA_PACKET_SIZE', '>H'],
  ];
}

// 4.2.13. POSITIVE NAME QUERY RESPONSE - Address entry
export class ADDR_ENTRY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['NB_FLAGS', '>H=0'],
    ['NB_ADDRESS', '4s=b""'],
  ];
}

// NBNS Resource Record (base)
export class NBNSResourceRecord extends Structure {
  static override structure: FieldDescriptor[] = [
    ['RR_NAME', 'z=\x00'],
    ['RR_TYPE', '>H=0'],
    ['RR_CLASS', '>H=0'],
    ['TTL', '>L=0'],
    ['RDLENGTH', '>H-RDATA'],
    ['RDATA', ':=""'],
  ];
}

// 4.2.18. NODE STATUS RESPONSE
export class NBNodeStatusResponse extends NBNSResourceRecord {
  mac = '00-00-00-00-00-00';
  num_names = 0;
  entries: NODE_NAME_ENTRY[] = [];
  statistics: STATISTICS | null = null;

  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (data) {
      const rdata = this.get('RDATA') as Buffer;
      this.num_names = rdata[0]!;
      this.entries = [];
      let remaining = rdata.subarray(1);
      for (let i = 0; i < this.num_names; i++) {
        const entry = new NODE_NAME_ENTRY(remaining);
        remaining = remaining.subarray(entry.length);
        this.entries.push(entry);
      }
      this.statistics = new STATISTICS(remaining);
      this._setMacInHexa(this.statistics.get('UNIT_ID') as Buffer);
    }
  }

  private _setMacInHexa(data: Buffer): void {
    const parts: string[] = [];
    for (const byte of data) {
      parts.push(byte.toString(16).padStart(2, '0').toUpperCase());
    }
    this.mac = parts.join('-');
  }

  get_mac(): string {
    return this.mac;
  }
}

// 4.2.13. POSITIVE NAME QUERY RESPONSE
export class NBPositiveNameQueryResponse extends NBNSResourceRecord {
  entries: string[] = [];

  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (data) {
      this.entries = [];
      let rdata = this.get('RDATA') as Buffer;
      while (rdata.length > 0) {
        const entry = new ADDR_ENTRY(rdata);
        rdata = rdata.subarray(entry.length);
        const ip = entry.get('NB_ADDRESS') as Buffer;
        this.entries.push(`${ip[0]!}.${ip[1]!}.${ip[2]!}.${ip[3]!}`);
      }
    }
  }
}

// 4.2.1. GENERAL FORMAT OF NAME SERVICE PACKETS
export class NAME_SERVICE_PACKET extends Structure {
  static override commonHdr: FieldDescriptor[] = [
    ['NAME_TRN_ID', '>H=0'],
    ['FLAGS', '>H=0'],
    ['QDCOUNT', '>H=0'],
    ['ANCOUNT', '>H=0'],
    ['NSCOUNT', '>H=0'],
    ['ARCOUNT', '>H=0'],
  ];

  static override structure: FieldDescriptor[] = [
    ['ANSWERS', ':'],
  ];
}

// 4.2.1.2. QUESTION SECTION
export class QUESTION_ENTRY extends Structure {
  static override commonHdr: FieldDescriptor[] = [
    ['QUESTION_NAME', 'z'],
    ['QUESTION_TYPE', '>H=0'],
    ['QUESTION_CLASS', '>H=0'],
  ];
}

// 4.2.1.3. RESOURCE RECORD
export class RESOURCE_RECORD extends Structure {
  static override structure: FieldDescriptor[] = [
    ['RR_NAME', 'z=\x00'],
    ['RR_TYPE', '>H=0'],
    ['RR_CLASS', '>H=0'],
    ['TTL', '>L=0'],
    ['RDLENGTH', '>H-RDATA'],
    ['RDATA', ':=""'],
  ];
}

// 4.2.2. NAME REGISTRATION REQUEST
export class NAME_REGISTRATION_REQUEST extends NAME_SERVICE_PACKET {
  static override structure: FieldDescriptor[] = [
    ['QUESTION_NAME', ':'],
    ['QUESTION_TYPE', '>H=0'],
    ['QUESTION_CLASS', '>H=0'],
    ['RR_NAME', ':'],
    ['RR_TYPE', '>H=0'],
    ['RR_CLASS', '>H=0'],
    ['TTL', '>L=0'],
    ['RDLENGTH', '>H=6'],
    ['NB_FLAGS', '>H=0'],
    ['NB_ADDRESS', '4s=b""'],
  ];

  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (!data) {
      this.set('FLAGS', OPCODE_REQUEST | NM_FLAGS_RD | OPCODE_REGISTRATION);
      this.set('QDCOUNT', 1);
      this.set('ANCOUNT', 0);
      this.set('NSCOUNT', 0);
      this.set('ARCOUNT', 1);
      this.set('QUESTION_TYPE', QUESTION_TYPE_NB);
      this.set('QUESTION_CLASS', QUESTION_CLASS_IN);
      this.set('RR_TYPE', RR_TYPE_NB);
      this.set('RR_CLASS', RR_CLASS_IN);
    }
  }
}

// 4.2.3. NAME OVERWRITE REQUEST & DEMAND
export class NAME_OVERWRITE_REQUEST extends NAME_REGISTRATION_REQUEST {
  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (!data) {
      this.set('FLAGS', OPCODE_REQUEST | OPCODE_REGISTRATION);
      this.set('QDCOUNT', 1);
      this.set('ANCOUNT', 0);
      this.set('NSCOUNT', 0);
      this.set('ARCOUNT', 1);
    }
  }
}

// 4.2.4. NAME REFRESH REQUEST
export class NAME_REFRESH_REQUEST extends NAME_REGISTRATION_REQUEST {
  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (!data) {
      this.set('FLAGS', OPCODE_REFRESH | 0x1);
      this.set('QDCOUNT', 1);
      this.set('ANCOUNT', 0);
      this.set('NSCOUNT', 0);
      this.set('ARCOUNT', 1);
    }
  }
}

// 4.2.5/6/7. NAME REGISTRATION RESPONSE
export class NAME_REGISTRATION_RESPONSE extends NAME_REGISTRATION_REQUEST {}

// 4.2.8. NAME CONFLICT DEMAND
export class NAME_CONFLICT_DEMAND extends NAME_REGISTRATION_REQUEST {}

// 4.2.12. NAME QUERY REQUEST
export class NAME_QUERY_REQUEST extends NAME_SERVICE_PACKET {
  static override structure: FieldDescriptor[] = [
    ['QUESTION_NAME', ':'],
    ['QUESTION_TYPE', '>H=0'],
    ['QUESTION_CLASS', '>H=0'],
  ];

  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (!data) {
      this.set('FLAGS', OPCODE_REQUEST | OPCODE_REGISTRATION | NM_FLAGS_RD);
      this.set('QDCOUNT', 1);
      this.set('ANCOUNT', 0);
      this.set('NSCOUNT', 0);
      this.set('ARCOUNT', 0);
      this.set('QUESTION_TYPE', QUESTION_TYPE_NB);
      this.set('QUESTION_CLASS', QUESTION_CLASS_IN);
    }
  }
}

// 4.2.17. NODE STATUS REQUEST
export class NODE_STATUS_REQUEST extends NAME_QUERY_REQUEST {
  constructor(data?: Buffer | null) {
    super(data ?? null);
    if (!data) {
      this.set('FLAGS', 0);
      this.set('QUESTION_TYPE', QUESTION_TYPE_NBSTAT);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// NetBIOS (NBNS) - UDP Name Service
////////////////////////////////////////////////////////////////////////////////

export class NetBIOS {
  private _servport: number;
  private _nameserver: string | null = null;
  private _broadcastaddr = BROADCAST_ADDR;
  mac = '00-00-00-00-00-00';

  constructor(servport = NETBIOS_NS_PORT) {
    this._servport = servport;
  }

  private async _setupConnection(_dstaddr: string): Promise<dgram.Socket> {
    for (let attempt = 0; attempt < 10; attempt++) {
      const sock = dgram.createSocket('udp4');
      const port = Math.floor(Math.random() * 50000) + 10000;
      try {
        await new Promise<void>((resolve, reject) => {
          sock.once('error', reject);
          sock.bind(port, INADDR_ANY, () => {
            sock.removeAllListeners('error');
            resolve();
          });
        });
        sock.setBroadcast(true);
        return sock;
      } catch {
        try { sock.close(); } catch { /* ignore */ }
      }
    }
    throw new NetBIOSError('Cannot bind to a good UDP port', ERRCLASS_OS, 11);
  }

  async send(
    request: NAME_SERVICE_PACKET,
    destaddr: string,
    timeout: number,
  ): Promise<NAME_SERVICE_PACKET> {
    const sock = await this._setupConnection(destaddr);
    const requestData = request.getData();
    const requestId = request.get('NAME_TRN_ID') as number;
    let tries = 3;

    try {
      while (true) {
        await new Promise<void>((resolve, reject) => {
          sock.send(requestData, 0, requestData.length, this._servport, destaddr, (err) => {
            if (err) reject(new NetBIOSError(`Connection error: ${err.message}`));
            else resolve();
          });
        });

        const data = await new Promise<Buffer | null>((resolve) => {
          const timer = setTimeout(() => {
            sock.removeAllListeners('message');
            resolve(null);
          }, timeout * 1000);

          sock.once('message', (msg: Buffer) => {
            clearTimeout(timer);
            resolve(msg);
          });
        });

        if (data === null) {
          if (tries > 0) {
            tries--;
            continue;
          }
          throw new NetBIOSTimeout();
        }

        const res = new NAME_SERVICE_PACKET(data);
        if ((res.get('NAME_TRN_ID') as number) === requestId) {
          if (((res.get('FLAGS') as number) & 0xf) > 0) {
            throw new NetBIOSError(
              'Negative response',
              ERRCLASS_QUERY,
              (res.get('FLAGS') as number) & 0xf,
            );
          }
          return res;
        }
        // Transaction ID mismatch - retry
      }
    } finally {
      try { sock.close(); } catch { /* ignore */ }
    }
  }

  set_nameserver(nameserver: string): void {
    this._nameserver = nameserver;
  }

  get_nameserver(): string | null {
    return this._nameserver;
  }

  set_broadcastaddr(broadcastaddr: string): void {
    this._broadcastaddr = broadcastaddr;
  }

  get_broadcastaddr(): string {
    return this._broadcastaddr;
  }

  async gethostbyname(
    nbname: string,
    qtype = TYPE_WORKSTATION,
    scope: string | null = null,
    timeout = 1,
  ): Promise<NBPositiveNameQueryResponse> {
    return this.name_query_request(nbname, this._nameserver, qtype, scope, timeout);
  }

  async getnodestatus(
    nbname: string,
    destaddr: string | null = null,
    type = TYPE_WORKSTATION,
    scope: string | null = null,
    timeout = 1,
  ): Promise<NODE_NAME_ENTRY[]> {
    const dest = destaddr ?? this._nameserver;
    return this.node_status_request(nbname, dest, type, scope, timeout);
  }

  async getnetbiosname(ip: string): Promise<string> {
    const entries = await this.getnodestatus('*', ip);
    const serverEntries = entries.filter((x) => (x.get('TYPE') as number) === TYPE_SERVER);
    const name = serverEntries[0]!.get('NAME') as Buffer;
    return name.toString('latin1').trim();
  }

  getmacaddress(): string {
    return this.mac;
  }

  async name_registration_request(
    nbname: string,
    destaddr: string | null,
    qtype: number,
    scope: string | null,
    nb_flags = 0,
    nb_address = '0.0.0.0',
  ): Promise<NAME_SERVICE_PACKET> {
    const netbios_name = nbname.toUpperCase();
    const qn_label = encode_name(netbios_name, qtype, scope ?? '');

    const p = new NAME_REGISTRATION_REQUEST();
    p.set('NAME_TRN_ID', Math.floor(Math.random() * 32000) + 1);
    p.set('QUESTION_NAME', Buffer.concat([qn_label.subarray(0, -1), Buffer.from([0])]));
    p.set('RR_NAME', Buffer.concat([qn_label.subarray(0, -1), Buffer.from([0])]));
    p.set('TTL', 0xffff);
    p.set('NB_FLAGS', nb_flags);
    p.set('NB_ADDRESS', Buffer.from(nb_address.split('.').map(Number)));

    let dest = destaddr;
    if (!dest) {
      p.set('FLAGS', (p.get('FLAGS') as number) | NM_FLAGS_BROADCAST);
      dest = this._broadcastaddr;
    }

    return this.send(p, dest, 1);
  }

  async name_query_request(
    nbname: string,
    destaddr: string | null = null,
    qtype = TYPE_SERVER,
    scope: string | null = null,
    timeout = 1,
  ): Promise<NBPositiveNameQueryResponse> {
    const netbios_name = nbname.toUpperCase();
    const qn_label = encode_name(netbios_name, qtype, scope ?? '');

    const p = new NAME_QUERY_REQUEST();
    p.set('NAME_TRN_ID', Math.floor(Math.random() * 32000) + 1);
    p.set('QUESTION_NAME', Buffer.concat([qn_label.subarray(0, -1), Buffer.from([0])]));
    p.set('FLAGS', NM_FLAGS_RD);

    let dest = destaddr;
    if (!dest) {
      p.set('FLAGS', (p.get('FLAGS') as number) | NM_FLAGS_BROADCAST);
      dest = this._broadcastaddr;
    }

    const res = await this.send(p, dest, timeout);
    return new NBPositiveNameQueryResponse(res.get('ANSWERS') as Buffer);
  }

  async node_status_request(
    nbname: string,
    destaddr: string | null,
    type: number,
    scope: string | null,
    timeout: number,
  ): Promise<NODE_NAME_ENTRY[]> {
    const netbios_name = nbname.toUpperCase();
    const qn_label = encode_name(netbios_name, type, scope ?? '');

    const p = new NODE_STATUS_REQUEST();
    p.set('NAME_TRN_ID', Math.floor(Math.random() * 32000) + 1);
    p.set('QUESTION_NAME', Buffer.concat([qn_label.subarray(0, -1), Buffer.from([0])]));

    let dest = destaddr;
    if (!dest) {
      p.set('FLAGS', NM_FLAGS_BROADCAST);
      dest = this._broadcastaddr;
    }

    const res = await this.send(p, dest, timeout);
    const answ = new NBNodeStatusResponse(res.get('ANSWERS') as Buffer);
    this.mac = answ.get_mac();
    return answ.entries;
  }
}

////////////////////////////////////////////////////////////////////////////////
// NetBIOS UDP Session Packet & Session
////////////////////////////////////////////////////////////////////////////////

export class NetBIOSUDPSessionPacket extends Structure {
  static readonly TYPE_DIRECT_UNIQUE = 16;
  static readonly TYPE_DIRECT_GROUP = 17;

  static readonly FLAGS_MORE_FRAGMENTS = 1;
  static readonly FLAGS_FIRST_FRAGMENT = 2;
  static readonly FLAGS_B_NODE = 0;

  static override structure: FieldDescriptor[] = [
    ['Type', 'B=16'],
    ['Flags', 'B=2'],
    ['ID', '<H'],
    ['_SourceIP', '>L'],
    ['SourceIP', '"'],
    ['SourcePort', '>H=138'],
    ['DataLegth', '>H-Data'],
    ['Offset', '>H=0'],
    ['SourceName', 'z'],
    ['DestinationName', 'z'],
    ['Data', ':'],
  ];

  override getData(): Buffer {
    const sourceIP = this.get('SourceIP') as string;
    if (sourceIP) {
      const parts = sourceIP.split('.');
      const addr =
        (((((Number(parts[0]!) << 8) + Number(parts[1]!)) << 8) + Number(parts[2]!)) << 8) +
        Number(parts[3]!);
      this.set('_SourceIP', addr >>> 0);
    }
    return super.getData();
  }

  get_trailer(): Buffer {
    return this.get('Data') as Buffer;
  }
}

export class NetBIOSUDPSession extends NetBIOSSession {
  private _udpSock: dgram.Socket | null = null;
  private _peer: [string, number] = ['', 0];
  private _dgramId = 0;

  protected override setupConnection(host: string, port: number, _timeout: number | null): Socket {
    this._peer = [host, port];
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    sock.bind(138, INADDR_ANY);
    this._udpSock = sock;
    // Return null: base class expects TCP Socket but UDP uses dgram.Socket stored separately
    return null as unknown as Socket;
  }

  protected override requestSession(
    _remote_type: number,
    _local_type: number,
    _timeout: number | null,
  ): void {
    // No session request needed for UDP
  }

  private nextId(): number {
    if (this._dgramId === 0) {
      this._dgramId = Math.floor(Math.random() * 65535) + 1;
    }
    return this._dgramId++;
  }

  async sendPacket(data: Buffer): Promise<void> {
    if (!this._udpSock) throw new NetBIOSError('UDP socket not connected');

    const p = new NetBIOSUDPSessionPacket();
    p.set('ID', this.nextId());
    const addrInfo = this._udpSock.address();
    p.set('SourceIP', addrInfo.address);
    p.set('SourceName', encode_name(this.get_myname(), this.get_mytype(), '').subarray(0, -1));
    p.set(
      'DestinationName',
      encode_name(this.get_remote_name(), this.get_remote_type(), '').subarray(0, -1),
    );
    p.set('Data', data);

    const packetData = p.getData();

    await new Promise<void>((resolve, reject) => {
      this._udpSock!.send(packetData, this._peer[1], this._peer[0], (err) => {
        if (err) reject(new NetBIOSError(`Send error: ${err.message}`));
        else resolve();
      });
    });

    this._udpSock.close();
    this._udpSock = null;
    this.setupConnection(this._peer[0], this._peer[1], null);
  }

  async recvPacket(_timeout: number | null = null): Promise<NetBIOSUDPSessionPacket> {
    if (!this._udpSock) throw new NetBIOSError('UDP socket not connected');

    return new Promise<NetBIOSUDPSessionPacket>((resolve) => {
      const onMessage = (msg: Buffer, rinfo: dgram.RemoteInfo) => {
        if (rinfo.address === this._peer[0]) {
          this._udpSock!.removeListener('message', onMessage);
          resolve(new NetBIOSUDPSessionPacket(msg));
        }
      };
      this._udpSock!.on('message', onMessage);
    });
  }

  override close(): void {
    if (this._udpSock) {
      try { this._udpSock.close(); } catch { /* ignore */ }
      this._udpSock = null;
    }
  }
}
