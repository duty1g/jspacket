import { Structure, type FieldDescriptor } from '@impacket/structure';
import * as net from 'node:net';
import * as tls from 'node:tls';
import * as dgram from 'node:dgram';
import * as crypto from 'node:crypto';
import { Duplex, type DuplexOptions } from 'node:stream';

// MC-SQLR Constants
export const SQLR_PORT = 1434;
export const SQLR_CLNT_BCAST_EX = 0x02;
export const SQLR_CLNT_UCAST_EX = 0x03;
export const SQLR_CLNT_UCAST_INST = 0x04;
export const SQLR_CLNT_UCAST_DAC = 0x0f;

// MC-SQLR Structures
export class SQLR extends Structure {
  static override commonHdr: FieldDescriptor[] = [
    ['OpCode', 'B'],
  ];
}

export class SQLRUcastInst extends SQLR {
  static override structure: FieldDescriptor[] = [
    ['Instance', ':'],
  ];

  constructor(data: Buffer | null = null) {
    super(data);
    if (data !== null) {
      this.set('OpCode', SQLR_CLNT_UCAST_INST);
    }
  }
}

export class SQLRUcastDac extends SQLR {
  static override structure: FieldDescriptor[] = [
    ['Protocol', 'B=1'],
    ['Instance', ':'],
  ];

  constructor(data: Buffer | null = null) {
    super(data);
    if (data !== null) {
      this.set('OpCode', SQLR_CLNT_UCAST_DAC);
    }
  }
}

export class SQLRResponse extends SQLR {
  static override structure: FieldDescriptor[] = [
    ['Size', '<H'],
    ['_Data', '_-Data', 'self["Size"]'],
    ['Data', ':'],
  ];
}

// Error class
export class SQLErrorException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SQLErrorException';
  }
}

// TDS TYPE constants
export const TDS_SQL_BATCH = 1;
export const TDS_PRE_TDS_LOGIN = 2;
export const TDS_RPC = 3;
export const TDS_TABULAR = 4;
export const TDS_ATTENTION = 6;
export const TDS_BULK_LOAD_DATA = 7;
export const TDS_TRANSACTION = 14;
export const TDS_LOGIN7 = 16;
export const TDS_SSPI = 17;
export const TDS_PRE_LOGIN = 18;

// TDS Status constants
export const TDS_STATUS_NORMAL = 0;
export const TDS_STATUS_EOM = 1;
export const TDS_STATUS_RESET_CONNECTION = 8;
export const TDS_STATUS_RESET_SKIPTRANS = 16;

// TDS Encryption constants
export const TDS_ENCRYPT_OFF = 0;
export const TDS_ENCRYPT_ON = 1;
export const TDS_ENCRYPT_NOT_SUP = 2;
export const TDS_ENCRYPT_REQ = 3;

// Option 2 Flags
export const TDS_INTEGRATED_SECURITY_ON = 0x80;
export const TDS_INIT_LANG_FATAL = 0x01;
export const TDS_ODBC_ON = 0x02;

// Token Types
export const TDS_ALTMETADATA_TOKEN = 0x88;
export const TDS_ALTROW_TOKEN = 0xd3;
export const TDS_COLMETADATA_TOKEN = 0x81;
export const TDS_COLINFO_TOKEN = 0xa5;
export const TDS_DONE_TOKEN = 0xfd;
export const TDS_DONEPROC_TOKEN = 0xfe;
export const TDS_DONEINPROC_TOKEN = 0xff;
export const TDS_ENVCHANGE_TOKEN = 0xe3;
export const TDS_ERROR_TOKEN = 0xaa;
export const TDS_INFO_TOKEN = 0xab;
export const TDS_LOGINACK_TOKEN = 0xad;
export const TDS_NBCROW_TOKEN = 0xd2;
export const TDS_OFFSET_TOKEN = 0x78;
export const TDS_ORDER_TOKEN = 0xa9;
export const TDS_RETURNSTATUS_TOKEN = 0x79;
export const TDS_RETURNVALUE_TOKEN = 0xac;
export const TDS_ROW_TOKEN = 0xd1;
export const TDS_SSPI_TOKEN = 0xed;
export const TDS_TABNAME_TOKEN = 0xa4;

// ENVCHANGE Types
export const TDS_ENVCHANGE_DATABASE = 1;
export const TDS_ENVCHANGE_LANGUAGE = 2;
export const TDS_ENVCHANGE_CHARSET = 3;
export const TDS_ENVCHANGE_PACKETSIZE = 4;
export const TDS_ENVCHANGE_UNICODE = 5;
export const TDS_ENVCHANGE_UNICODE_DS = 6;
export const TDS_ENVCHANGE_COLLATION = 7;
export const TDS_ENVCHANGE_TRANS_START = 8;
export const TDS_ENVCHANGE_TRANS_COMMIT = 9;
export const TDS_ENVCHANGE_ROLLBACK = 10;
export const TDS_ENVCHANGE_DTC = 11;

// Column types - FIXED-LEN Data Types
export const TDS_NULL_TYPE = 0x1f;
export const TDS_INT1TYPE = 0x30;
export const TDS_BITTYPE = 0x32;
export const TDS_INT2TYPE = 0x34;
export const TDS_INT4TYPE = 0x38;
export const TDS_DATETIM4TYPE = 0x3a;
export const TDS_FLT4TYPE = 0x3b;
export const TDS_MONEYTYPE = 0x3c;
export const TDS_DATETIMETYPE = 0x3d;
export const TDS_FLT8TYPE = 0x3e;
export const TDS_MONEY4TYPE = 0x7a;
export const TDS_INT8TYPE = 0x7f;

// Column types - VARIABLE-Len Data Types
export const TDS_GUIDTYPE = 0x24;
export const TDS_INTNTYPE = 0x26;
export const TDS_DECIMALTYPE = 0x37;
export const TDS_NUMERICTYPE = 0x3f;
export const TDS_BITNTYPE = 0x68;
export const TDS_DECIMALNTYPE = 0x6a;
export const TDS_NUMERICNTYPE = 0x6c;
export const TDS_FLTNTYPE = 0x6d;
export const TDS_MONEYNTYPE = 0x6e;
export const TDS_DATETIMNTYPE = 0x6f;
export const TDS_DATENTYPE = 0x28;
export const TDS_TIMENTYPE = 0x29;
export const TDS_DATETIME2NTYPE = 0x2a;
export const TDS_DATETIMEOFFSETNTYPE = 0x2b;
export const TDS_CHARTYPE = 0x2f;
export const TDS_VARCHARTYPE = 0x27;
export const TDS_BINARYTYPE = 0x2d;
export const TDS_VARBINARYTYPE = 0x25;
export const TDS_BIGVARBINTYPE = 0xa5;
export const TDS_BIGVARCHRTYPE = 0xa7;
export const TDS_BIGBINARYTYPE = 0xad;
export const TDS_BIGCHARTYPE = 0xaf;
export const TDS_NVARCHARTYPE = 0xe7;
export const TDS_NCHARTYPE = 0xef;
export const TDS_XMLTYPE = 0xf1;
export const TDS_UDTTYPE = 0xf0;
export const TDS_TEXTTYPE = 0x23;
export const TDS_IMAGETYPE = 0x22;
export const TDS_NTEXTTYPE = 0x63;
export const TDS_SSVARIANTTYPE = 0x62;

// TDS Structures
export class TDSPacket extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Type', '<B'],
    ['Status', '<B=1'],
    ['Length', '>H=8+len(Data)'],
    ['SPID', '>H=0'],
    ['PacketID', '<B=0'],
    ['Window', '<B=0'],
    ['Data', ':'],
  ];
}

export class TDS_PRELOGIN extends Structure {
  static override structure: FieldDescriptor[] = [
    ['VersionToken', '>B=0'],
    ['VersionOffset', '>H'],
    ['VersionLength', '>H=len(self["Version"])'],
    ['EncryptionToken', '>B=0x1'],
    ['EncryptionOffset', '>H'],
    ['EncryptionLength', '>H=1'],
    ['InstanceToken', '>B=2'],
    ['InstanceOffset', '>H'],
    ['InstanceLength', '>H=len(self["Instance"])'],
    ['ThreadIDToken', '>B=3'],
    ['ThreadIDOffset', '>H'],
    ['ThreadIDLength', '>H=4'],
    ['EndToken', '>B=0xff'],
    ['_Version', '_-Version', 'self["VersionLength"]'],
    ['Version', ':'],
    ['Encryption', 'B'],
    ['_Instance', '_-Instance', 'self["InstanceLength"]-1'],
    ['Instance', ':'],
    ['ThreadID', ':'],
  ];

  override getData(): Buffer {
    const version = this.get('Version');
    const instance = this.get('Instance');
    const vLen = Buffer.isBuffer(version) ? version.length : 0;
    const iLen = Buffer.isBuffer(instance) ? instance.length : 0;
    this.set('VersionOffset', 21);
    this.set('EncryptionOffset', 21 + vLen);
    this.set('InstanceOffset', 21 + vLen + 1);
    this.set('ThreadIDOffset', 21 + vLen + 1 + iLen);
    return super.getData();
  }
}

export class TDS_LOGIN extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Length', '<L=0'],
    ['TDSVersion', '>L=0x71'],
    ['PacketSize', '<L=32764'],
    ['ClientProgVer', '>L=7'],
    ['ClientPID', '<L=0'],
    ['ConnectionID', '<L=0'],
    ['OptionFlags1', '<B=0xe0'],
    ['OptionFlags2', '<B'],
    ['TypeFlags', '<B=0'],
    ['OptionFlags3', '<B=0'],
    ['ClientTimeZone', '<L=0'],
    ['ClientLCID', '<L=0'],
    ['HostNameOffset', '<H'],
    ['HostNameLength', '<H=len(self["HostName"])//2'],
    ['UserNameOffset', '<H=0'],
    ['UserNameLength', '<H=len(self["UserName"])//2'],
    ['PasswordOffset', '<H=0'],
    ['PasswordLength', '<H=len(self["Password"])//2'],
    ['AppNameOffset', '<H'],
    ['AppNameLength', '<H=len(self["AppName"])//2'],
    ['ServerNameOffset', '<H'],
    ['ServerNameLength', '<H=len(self["ServerName"])//2'],
    ['UnusedOffset', '<H=0'],
    ['UnusedLength', '<H=0'],
    ['CltIntNameOffset', '<H'],
    ['CltIntNameLength', '<H=len(self["CltIntName"])//2'],
    ['LanguageOffset', '<H=0'],
    ['LanguageLength', '<H=0'],
    ['DatabaseOffset', '<H=0'],
    ['DatabaseLength', '<H=len(self["Database"])//2'],
    ['ClientID', '6s=b"\\x01\\x02\\x03\\x04\\x05\\x06"'],
    ['SSPIOffset', '<H'],
    ['SSPILength', '<H=len(self["SSPI"])'],
    ['AtchDBFileOffset', '<H'],
    ['AtchDBFileLength', '<H=len(self["AtchDBFile"])//2'],
    ['HostName', ':'],
    ['UserName', ':'],
    ['Password', ':'],
    ['AppName', ':'],
    ['ServerName', ':'],
    ['CltIntName', ':'],
    ['Database', ':'],
    ['SSPI', ':'],
    ['AtchDBFile', ':'],
  ];

  constructor(data: Buffer | null = null) {
    super(data);
    if (data === null) {
      this.set('UserName', '');
      this.set('Password', '');
      this.set('Database', '');
      this.set('AtchDBFile', '');
    }
  }

  override fromString(data: Buffer): this {
    super.fromString(data);
    const hostNameLength = this.get('HostNameLength') as number;
    if (hostNameLength > 0) {
      const offset = this.get('HostNameOffset') as number;
      this.set('HostName', data.subarray(offset, offset + hostNameLength * 2));
    }
    const userNameLength = this.get('UserNameLength') as number;
    if (userNameLength > 0) {
      const offset = this.get('UserNameOffset') as number;
      this.set('UserName', data.subarray(offset, offset + userNameLength * 2));
    }
    const passwordLength = this.get('PasswordLength') as number;
    if (passwordLength > 0) {
      const offset = this.get('PasswordOffset') as number;
      this.set('Password', data.subarray(offset, offset + passwordLength * 2));
    }
    const appNameLength = this.get('AppNameLength') as number;
    if (appNameLength > 0) {
      const offset = this.get('AppNameOffset') as number;
      this.set('AppName', data.subarray(offset, offset + appNameLength * 2));
    }
    const serverNameLength = this.get('ServerNameLength') as number;
    if (serverNameLength > 0) {
      const offset = this.get('ServerNameOffset') as number;
      this.set('ServerName', data.subarray(offset, offset + serverNameLength * 2));
    }
    const cltIntNameLength = this.get('CltIntNameLength') as number;
    if (cltIntNameLength > 0) {
      const offset = this.get('CltIntNameOffset') as number;
      this.set('CltIntName', data.subarray(offset, offset + cltIntNameLength * 2));
    }
    const databaseLength = this.get('DatabaseLength') as number;
    if (databaseLength > 0) {
      const offset = this.get('DatabaseOffset') as number;
      this.set('Database', data.subarray(offset, offset + databaseLength * 2));
    }
    const sspiLength = this.get('SSPILength') as number;
    if (sspiLength > 0) {
      const offset = this.get('SSPIOffset') as number;
      this.set('SSPI', data.subarray(offset, offset + sspiLength * 2));
    }
    const atchDbFileLength = this.get('AtchDBFileLength') as number;
    if (atchDbFileLength > 0) {
      const offset = this.get('AtchDBFileOffset') as number;
      this.set('AtchDBFile', data.subarray(offset, offset + atchDbFileLength * 2));
    }
    return this;
  }

  override getData(): Buffer {
    let index = 86;
    this.set('HostNameOffset', index);

    const hostName = this.get('HostName');
    index += bufLen(hostName);

    const userName = this.get('UserName');
    if (userName !== '') {
      this.set('UserNameOffset', index);
    } else {
      this.set('UserNameOffset', 0);
    }
    index += bufLen(userName);

    const password = this.get('Password');
    if (password !== '') {
      this.set('PasswordOffset', index);
    } else {
      this.set('PasswordOffset', 0);
    }
    index += bufLen(password);

    this.set('AppNameOffset', index);
    const appName = this.get('AppName');
    this.set('ServerNameOffset', index + bufLen(appName));
    const serverName = this.get('ServerName');
    this.set('CltIntNameOffset', index + bufLen(appName) + bufLen(serverName));
    const cltIntName = this.get('CltIntName');
    this.set('LanguageOffset', index + bufLen(appName) + bufLen(serverName) + bufLen(cltIntName));
    this.set('DatabaseOffset', index + bufLen(appName) + bufLen(serverName) + bufLen(cltIntName));
    const database = this.get('Database');
    this.set('SSPIOffset', index + bufLen(appName) + bufLen(serverName) + bufLen(cltIntName) + bufLen(database));
    const sspi = this.get('SSPI');
    this.set('AtchDBFileOffset', index + bufLen(appName) + bufLen(serverName) + bufLen(cltIntName) + bufLen(database) + bufLen(sspi));

    return super.getData();
  }
}

export class TDS_LOGIN_ACK extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Length', '<H'],
    ['Interface', '<B'],
    ['TDSVersion', '<L'],
    ['ProgNameLen', '<B'],
    ['_ProgNameLen', '_-ProgName', 'self["ProgNameLen"]*2'],
    ['ProgName', ':'],
    ['MajorVer', '<B'],
    ['MinorVer', '<B'],
    ['BuildNumHi', '<B'],
    ['BuildNumLow', '<B'],
  ];
}

export class TDS_RETURNSTATUS extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Value', '<L'],
  ];
}

export class TDS_INFO_ERROR extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Length', '<H'],
    ['Number', '<L'],
    ['State', '<B'],
    ['Class', '<B'],
    ['MsgTextLen', '<H'],
    ['_MsgTextLen', '_-MsgText', 'self["MsgTextLen"]*2'],
    ['MsgText', ':'],
    ['ServerNameLen', '<B'],
    ['_ServerNameLen', '_-ServerName', 'self["ServerNameLen"]*2'],
    ['ServerName', ':'],
    ['ProcNameLen', '<B'],
    ['_ProcNameLen', '_-ProcName', 'self["ProcNameLen"]*2'],
    ['ProcName', ':'],
    ['LineNumber', '<H'],
  ];
}

export class TDS_ENVCHANGE extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Length', '<H=4+len(Data)'],
    ['Type', '<B'],
    ['_Data', '_-Data', 'self["Length"]-1'],
    ['Data', ':'],
  ];
}

export class TDS_DONEINPROC extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Status', '<H'],
    ['CurCmd', '<H'],
    ['DoneRowCount', '<L'],
  ];
}

export class TDS_ORDER extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Length', '<H'],
    ['_Data', '_-Data', 'self["Length"]'],
    ['Data', ':'],
  ];
}

export class TDS_ENVCHANGE_VARCHAR extends Structure {
  static override structure: FieldDescriptor[] = [
    ['NewValueLen', '<B=len(NewValue)'],
    ['_NewValue', '_-NewValue', 'self["NewValueLen"]*2'],
    ['NewValue', ':'],
    ['OldValueLen', '<B=len(OldValue)'],
    ['_OldValue', '_-OldValue', 'self["OldValueLen"]*2'],
    ['OldValue', ':'],
  ];
}

export class TDS_ROW extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Data', ':'],
  ];
}

export class TDS_DONE extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Status', '<H'],
    ['CurCmd', '<H'],
    ['DoneRowCount', '<L'],
  ];
}

export class TDS_COLMETADATA extends Structure {
  static override structure: FieldDescriptor[] = [
    ['TokenType', '<B'],
    ['Count', '<H'],
    ['Data', ':'],
  ];
}

// Rows printer interface
export interface RowsPrinter {
  logMessage(message: string): void;
}

export class DummyPrint implements RowsPrinter {
  logMessage(message: string): void {
    if (message === '\n') {
      console.log(message);
    } else if (message === '\r') {
      console.log();
    } else {
      process.stdout.write(message + ' ');
    }
  }
}

// Column metadata type
export interface ColumnMeta {
  Name: string;
  Type: number;
  TypeData: number | Buffer;
  Flags: number;
  Length: number;
  minLenght: number;
  Format: string;
}

export type RowDict = Record<string, unknown>;
export type RowTuple = unknown[];
export type Row = RowDict | RowTuple;
export type TDSReplies = Record<number, Structure[]>;

// Utility: compute buffer length from a PackValue
function bufLen(v: unknown): number {
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return v.length;
  if (typeof v === 'string') return Buffer.byteLength(v, 'latin1');
  return 0;
}

// Utility: convert a 16-byte buffer to UUID string (mixed-endian, Windows format)
function uuidBinToString(buf: Buffer): string {
  const p1 = Buffer.from(buf.subarray(0, 4)).reverse().toString('hex');
  const p2 = Buffer.from(buf.subarray(4, 6)).reverse().toString('hex');
  const p3 = Buffer.from(buf.subarray(6, 8)).reverse().toString('hex');
  const p4 = buf.subarray(8, 10).toString('hex');
  const p5 = buf.subarray(10, 16).toString('hex');
  return `${p1}-${p2}-${p3}-${p4}-${p5}`;
}

// Utility: format MSSQL version bytes as string
function mssqlVersionString(data: Buffer): string {
  if (data.length >= 6) {
    const major = data.readUInt8(0);
    const minor = data.readUInt8(1);
    const build = data.readUInt16BE(2);
    return `${major}.${minor}.${build}`;
  }
  return 'unknown';
}

// Utility: Python-style sprintf for %-Ns and %Ns format strings
function sprintfStr(fmt: string, value: unknown): string {
  const str = String(value);
  const match = fmt.match(/^%(-)?\s*(\d+)s$/);
  if (!match) return str;
  const leftAlign = match[1] === '-';
  const width = parseInt(match[2]!, 10);
  return leftAlign ? str.padEnd(width) : str.padStart(width);
}

// Async reader for buffering socket data
class AsyncReader {
  private chunks: Buffer[] = [];
  private waiting: ((value: Buffer) => void) | null = null;
  private errorWaiting: ((err: Error) => void) | null = null;

  feed(data: Buffer): void {
    if (data.length === 0) return;
    if (this.waiting) {
      const resolve = this.waiting;
      this.waiting = null;
      this.errorWaiting = null;
      resolve(data);
    } else {
      this.chunks.push(data);
    }
  }

  error(err: Error): void {
    if (this.errorWaiting) {
      const reject = this.errorWaiting;
      this.waiting = null;
      this.errorWaiting = null;
      reject(err);
    }
  }

  async read(): Promise<Buffer> {
    if (this.chunks.length > 0) {
      return this.chunks.shift()!;
    }
    return new Promise<Buffer>((resolve, reject) => {
      this.waiting = resolve;
      this.errorWaiting = reject;
    });
  }
}

export class MSSQL {
  packetSize: number;
  server: string;
  remoteName: string;
  port: number;
  replies: TDSReplies;
  colMeta: ColumnMeta[];
  rows: Row[];
  currentDB: string;
  COL_SEPARATOR: string;
  MAX_COL_LEN: number;
  lastError: SQLErrorException | false;
  mssqlVersion: string;

  private _socket: net.Socket | null;
  private _tlsSocket: tls.TLSSocket | null;
  private _tlsTransport: Duplex | null;
  private _tlsUnique: Buffer;
  private _useTls: boolean;
  private _reader: AsyncReader;
  private _dataHandler: ((chunk: Buffer) => void) | null;
  private _rowsPrinter: RowsPrinter;
  private _workstationId: string;
  private _applicationName: string;
  private _clientInterfaceName: string;

  constructor(
    address: string,
    port = 1433,
    remoteName = '',
    workstationId = '',
    applicationName = '',
    rowsPrinter: RowsPrinter = new DummyPrint(),
    clientInterfaceName = '',
  ) {
    this.packetSize = 32763;
    this.server = address;
    this.remoteName = remoteName;
    this.port = port;
    this._socket = null;
    this.replies = {};
    this.colMeta = [];
    this.rows = [];
    this.currentDB = '';
    this.COL_SEPARATOR = '  ';
    this.MAX_COL_LEN = 255;
    this.lastError = false;
    this._tlsSocket = null;
    this._tlsTransport = null;
    this._tlsUnique = Buffer.alloc(0);
    this._useTls = false;
    this._reader = new AsyncReader();
    this._dataHandler = null;
    this._rowsPrinter = rowsPrinter;
    this.mssqlVersion = '';

    this._workstationId = workstationId || `DESKTOP-${crypto.randomUUID().replace(/-/g, '').substring(0, 8).toUpperCase()}`;
    this._applicationName = applicationName || 'Microsoft SQL Server Management Studio - Query';
    this._clientInterfaceName = clientInterfaceName || this._applicationName;
  }

  get workstationId(): string {
    return this._workstationId;
  }

  get applicationName(): string {
    return this._applicationName;
  }

  async getInstances(timeout = 5): Promise<Record<string, string>[]> {
    const packet = new SQLR();
    packet.set('OpCode', SQLR_CLNT_UCAST_EX);

    return new Promise<Record<string, string>[]>((resolve) => {
      const sock = dgram.createSocket('udp4');

      const timer = setTimeout(() => {
        sock.close();
        resolve([]);
      }, timeout * 1000);

      sock.on('message', (msg: Buffer) => {
        clearTimeout(timer);
        sock.close();

        const resp = new SQLRResponse(msg);
        const data = resp.get('Data') as Buffer;
        const entries = data.toString('utf-8').split(';;');
        entries.pop();

        const result: Record<string, string>[] = [];
        for (const entry of entries) {
          const fields = entry.split(';');
          const ret: Record<string, string> = {};
          for (let j = 0; j < fields.length - 1; j += 2) {
            ret[fields[j]!] = fields[j + 1]!;
          }
          result.push(ret);
        }
        resolve(result);
      });

      const pktData = packet.getData();
      sock.send(pktData, 0, pktData.length, SQLR_PORT, this.server);
    });
  }

  async preLogin(): Promise<TDS_PRELOGIN> {
    const prelogin = new TDS_PRELOGIN();
    prelogin.set('Version', Buffer.from([0x08, 0x00, 0x01, 0x55, 0x00, 0x00]));
    prelogin.set('Encryption', TDS_ENCRYPT_OFF);
    const threadId = Buffer.alloc(4);
    threadId.writeUInt32LE(Math.floor(Math.random() * 65536));
    prelogin.set('ThreadID', threadId);
    prelogin.set('Instance', Buffer.from('MSSQLServer\x00'));

    await this.sendTDS(TDS_PRE_LOGIN, prelogin.getData(), 0);
    const tds = await this.recvTDS();
    const response = new TDS_PRELOGIN(tds.get('Data') as Buffer);
    this.mssqlVersion = mssqlVersionString(response.get('Version') as Buffer);
    return response;
  }

  encryptPassword(password: Buffer): Buffer {
    const result = Buffer.alloc(password.length);
    for (let i = 0; i < password.length; i++) {
      result[i] = (((password[i]! & 0x0f) << 4) | ((password[i]! & 0xf0) >> 4)) ^ 0xa5;
    }
    return result;
  }

  async connect(timeout = 30): Promise<net.Socket> {
    return new Promise<net.Socket>((resolve, reject) => {
      const sock = net.createConnection({ host: this.server, port: this.port, timeout: timeout * 1000 });

      sock.once('connect', () => {
        sock.setNoDelay(true);
        this._socket = sock;
        this._reader = new AsyncReader();
        this._dataHandler = (chunk: Buffer) => {
          this._reader.feed(chunk);
        };
        sock.on('data', (chunk: Buffer) => {
          if (this._dataHandler) {
            this._dataHandler(chunk);
          }
        });
        sock.on('error', (err: Error) => {
          this._reader.error(err);
        });
        resolve(sock);
      });

      sock.once('error', (err: Error) => {
        reject(err);
      });

      sock.once('timeout', () => {
        sock.destroy();
        reject(new Error('Connection timed out'));
      });
    });
  }

  disconnect(): void {
    if (this._tlsSocket) {
      this._tlsSocket.destroy();
      this._tlsSocket = null;
    }
    if (this._tlsTransport) {
      this._tlsTransport.destroy();
      this._tlsTransport = null;
    }
    if (this._socket) {
      this._socket.destroy();
      this._socket = null;
    }
    this._useTls = false;
  }

  setPacketSize(size: number): void {
    this.packetSize = size;
  }

  getPacketSize(): number {
    return this.packetSize;
  }

  // ---- SEND DATA ----

  async sendTDS(packetType: number, data: Buffer, packetID = 1): Promise<void> {
    if ((data.length - 8) > this.packetSize) {
      let remaining = data.subarray(this.packetSize - 8);
      const tds = new TDSPacket();
      tds.set('Type', packetType);
      tds.set('Status', TDS_STATUS_NORMAL);
      tds.set('PacketID', packetID);
      tds.set('Data', data.subarray(0, this.packetSize - 8));
      await this.socketSendall(tds.getData());

      while (remaining.length > (this.packetSize - 8)) {
        packetID += 1;
        tds.set('PacketID', packetID);
        tds.set('Data', remaining.subarray(0, this.packetSize - 8));
        await this.socketSendall(tds.getData());
        remaining = remaining.subarray(this.packetSize - 8);
      }
      data = remaining;
      packetID += 1;
    }

    const tds = new TDSPacket();
    tds.set('Type', packetType);
    tds.set('Status', TDS_STATUS_EOM);
    tds.set('PacketID', packetID);
    tds.set('Data', data);
    await this.socketSendall(tds.getData());
  }

  private async socketSendall(data: Buffer): Promise<void> {
    if (this._useTls && this._tlsSocket) {
      return this.tlsSend(data);
    }
    return new Promise<void>((resolve, reject) => {
      this._socket!.write(data, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  private async tlsSend(data: Buffer): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this._tlsSocket!.write(data, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  // ---- READ DATA ----

  async recvTDS(recvSize?: number): Promise<TDSPacket> {
    void recvSize;

    let data: Buffer = Buffer.alloc(0);
    while (data.length === 0) {
      data = await this.socketRecv();
    }

    const packet = new TDSPacket(data);

    let status = packet.get('Status') as number;
    let packetLen = (packet.get('Length') as number) - 8;
    while (packetLen > (packet.get('Data') as Buffer).length) {
      const chunk = await this.socketRecv();
      packet.set('Data', Buffer.concat([packet.get('Data') as Buffer, chunk]));
    }

    let remaining: Buffer | null = null;
    const pktData = packet.get('Data') as Buffer;
    if (packetLen < pktData.length) {
      remaining = pktData.subarray(packetLen);
      packet.set('Data', pktData.subarray(0, packetLen));
    }

    while (status !== TDS_STATUS_EOM) {
      let tmpPacket: TDSPacket;
      if (remaining !== null) {
        tmpPacket = new TDSPacket(remaining);
      } else {
        tmpPacket = new TDSPacket(await this.socketRecv());
      }

      packetLen = (tmpPacket.get('Length') as number) - 8;
      while (packetLen > (tmpPacket.get('Data') as Buffer).length) {
        const moreData = await this.socketRecv();
        tmpPacket.set('Data', Buffer.concat([tmpPacket.get('Data') as Buffer, moreData]));
      }

      remaining = null;
      const tmpData = tmpPacket.get('Data') as Buffer;
      if (packetLen < tmpData.length) {
        remaining = tmpData.subarray(packetLen);
        tmpPacket.set('Data', tmpData.subarray(0, packetLen));
      }

      status = tmpPacket.get('Status') as number;
      packet.set('Data', Buffer.concat([packet.get('Data') as Buffer, tmpPacket.get('Data') as Buffer]));
      packet.set('Length', (packet.get('Length') as number) + (tmpPacket.get('Length') as number) - 8);
    }

    return packet;
  }

  private async socketRecv(): Promise<Buffer> {
    return this._reader.read();
  }

  // ---- TLS CONTEXT ----

  generateCbtFromTlsUnique(): Buffer {
    const initiatorAddress = Buffer.alloc(8);
    const acceptorAddress = Buffer.alloc(8);
    const applicationDataRaw = Buffer.concat([Buffer.from('tls-unique:'), this._tlsUnique]);
    const lenApplicationData = Buffer.alloc(4);
    lenApplicationData.writeUInt32LE(applicationDataRaw.length);
    const applicationData = Buffer.concat([lenApplicationData, applicationDataRaw]);
    const channelBindingStruct = Buffer.concat([initiatorAddress, acceptorAddress, applicationData]);
    const cbtToken = crypto.createHash('md5').update(channelBindingStruct).digest();
    console.debug(`Computed tls-unique CBT token: ${cbtToken.toString('hex')}`);
    return cbtToken;
  }

  async setTlsContext(): Promise<void> {
    console.info('Encryption required, switching to TLS');

    const encryptedOutputChunks: Buffer[] = [];
    let onEncryptedOutput: (() => void) | null = null;
    let handshakeDone = false;

    const duplexOpts: DuplexOptions = {
      read() { /* TLS reads are driven by push() */ },
      write(chunk: unknown, _enc: BufferEncoding, cb: (error?: Error | null) => void) {
        encryptedOutputChunks.push(chunk as Buffer);
        if (onEncryptedOutput) {
          const r = onEncryptedOutput;
          onEncryptedOutput = null;
          r();
        }
        cb();
      },
    };
    const transport = new Duplex(duplexOpts);
    let tlsSock!: tls.TLSSocket;

    const securePromise = new Promise<void>((resolve, reject) => {
      tlsSock = tls.connect({ socket: transport as any, rejectUnauthorized: false }, () => {
        handshakeDone = true;
        if (onEncryptedOutput) {
          const r = onEncryptedOutput;
          onEncryptedOutput = null;
          r();
        }
        resolve();
      });
      tlsSock.once('error', (err: Error) => {
        handshakeDone = true;
        if (onEncryptedOutput) {
          const r = onEncryptedOutput;
          onEncryptedOutput = null;
          r();
        }
        reject(err);
      });
    });

    const pumpHandshake = async (): Promise<void> => {
      while (!handshakeDone) {
        if (encryptedOutputChunks.length === 0) {
          await new Promise<void>((r) => { onEncryptedOutput = r; });
        }
        if (handshakeDone && encryptedOutputChunks.length === 0) break;

        const outData = Buffer.concat(encryptedOutputChunks.splice(0));
        if (outData.length === 0) continue;

        await this.sendTDS(TDS_PRE_LOGIN, outData, 0);
        const tdsResp = await this.recvTDS(4096);
        const tlsData = tdsResp.get('Data') as Buffer;
        transport.push(tlsData);
      }
    };

    await Promise.all([securePromise, pumpHandshake()]);

    this._dataHandler = (chunk: Buffer) => {
      transport.push(chunk);
    };

    transport._write = (chunk: unknown, _: BufferEncoding, cb: (error?: Error | null) => void) => {
      this._socket!.write(chunk as Buffer, cb);
    };

    this.packetSize = 16 * 1024 - 1;
    this._tlsSocket = tlsSock;
    this._tlsTransport = transport;
    this._tlsUnique = tlsSock.getFinished() || Buffer.alloc(0);
    this._useTls = true;

    tlsSock.on('data', (chunk: Buffer) => {
      this._reader.feed(chunk);
    });
  }

  // ---- LOGIN ----

  async login(
    database: string | null,
    username: string,
    password = '',
    domain = '',
    hashes: string | null = null,
    useWindowsAuth = false,
  ): Promise<boolean> {
    void domain;
    void hashes;

    const resp = await this.preLogin();
    const encLevel = resp.get('Encryption') as number;

    if (encLevel === TDS_ENCRYPT_REQ || encLevel === TDS_ENCRYPT_OFF) {
      await this.setTlsContext();
    }

    const login = new TDS_LOGIN();
    login.set('HostName', Buffer.from(this._workstationId, 'utf16le'));
    login.set('AppName', Buffer.from(this._applicationName, 'utf16le'));
    login.set('ServerName', Buffer.from(this.remoteName, 'utf16le'));
    login.set('CltIntName', Buffer.from(this._clientInterfaceName, 'utf16le'));
    login.set('ClientPID', Math.floor(Math.random() * 1025));
    login.set('PacketSize', this.packetSize);
    if (database !== null) {
      login.set('Database', Buffer.from(database, 'utf16le'));
    }

    login.set('OptionFlags2', TDS_INIT_LANG_FATAL | TDS_ODBC_ON);

    if (useWindowsAuth) {
      throw new Error('Windows authentication (NTLM) requires @impacket/ntlm which is not imported in this package');
    }

    login.set('UserName', Buffer.from(username, 'utf16le'));
    login.set('Password', this.encryptPassword(Buffer.from(password, 'utf16le')));
    login.set('SSPI', '');

    login.set('Length', login.getData().length);
    await this.sendTDS(TDS_LOGIN7, login.getData());

    if (encLevel === TDS_ENCRYPT_OFF) {
      this._tlsSocket = null;
      this._useTls = false;
      this._dataHandler = (chunk: Buffer) => {
        this._reader.feed(chunk);
      };
    }

    const tds = await this.recvTDS();

    this.replies = this.parseReply(tds.get('Data') as Buffer);
    return TDS_LOGINACK_TOKEN in this.replies;
  }

  // ---- RESULT PROCESSING ----

  processColMeta(): void {
    for (const col of this.colMeta) {
      let fmt: string;

      if (col.Type === TDS_NVARCHARTYPE || col.Type === TDS_NCHARTYPE || col.Type === TDS_NTEXTTYPE) {
        col.Length = (col.TypeData as number) / 2;
        fmt = '%%-%ds';
      } else if (col.Type === TDS_GUIDTYPE) {
        col.Length = 36;
        fmt = '%%%ds';
      } else if (col.Type === TDS_DECIMALNTYPE || col.Type === TDS_NUMERICNTYPE) {
        col.Length = (col.TypeData as Buffer).readUInt8(0);
        fmt = '%%%ds';
      } else if (col.Type === TDS_DATETIMNTYPE) {
        col.Length = 19;
        fmt = '%%-%ds';
      } else if (col.Type === TDS_INT4TYPE || col.Type === TDS_INTNTYPE) {
        col.Length = 11;
        fmt = '%%%ds';
      } else if (col.Type === TDS_FLTNTYPE || col.Type === TDS_MONEYNTYPE) {
        col.Length = 25;
        fmt = '%%%ds';
      } else if (col.Type === TDS_BITNTYPE || col.Type === TDS_BIGCHARTYPE) {
        col.Length = col.TypeData as number;
        fmt = '%%%ds';
      } else if (col.Type === TDS_BIGBINARYTYPE || col.Type === TDS_BIGVARBINTYPE) {
        col.Length = (col.TypeData as number) * 2;
        fmt = '%%%ds';
      } else if (col.Type === TDS_TEXTTYPE || col.Type === TDS_BIGVARCHRTYPE) {
        col.Length = col.TypeData as number;
        fmt = '%%-%ds';
      } else {
        col.Length = 10;
        fmt = '%%%ds';
      }

      col.minLenght = 0;
      for (const row of this.rows) {
        if (Array.isArray(row)) continue;
        const val = (row as RowDict)[col.Name];
        if (String(val).length > col.minLenght) {
          col.minLenght = String(val).length;
        }
      }
      if (col.minLenght < col.Length) {
        col.Length = col.minLenght;
      }
      if (col.Name.length > col.Length) {
        col.Length = col.Name.length;
      } else if (col.Length > this.MAX_COL_LEN) {
        col.Length = this.MAX_COL_LEN;
      }

      col.Format = fmt.replace('%%', '%').replace('%d', String(col.Length));
    }
  }

  printColumnsHeader(): void {
    if (this.colMeta.length === 0) return;
    for (const col of this.colMeta) {
      this._rowsPrinter.logMessage(sprintfStr(col.Format, col.Name) + this.COL_SEPARATOR);
    }
    this._rowsPrinter.logMessage('\r');
    for (const col of this.colMeta) {
      this._rowsPrinter.logMessage('-'.repeat(col.Length) + this.COL_SEPARATOR);
    }
    this._rowsPrinter.logMessage('\r');
  }

  printRows(): void {
    if (this.lastError !== false) return;
    this.processColMeta();
    this.printColumnsHeader();
    for (const row of this.rows) {
      if (Array.isArray(row)) continue;
      for (const col of this.colMeta) {
        this._rowsPrinter.logMessage(sprintfStr(col.Format, (row as RowDict)[col.Name]) + this.COL_SEPARATOR);
      }
      this._rowsPrinter.logMessage('\r');
    }
  }

  printReplies(
    errorLogger: (...args: unknown[]) => void = console.error,
    infoLogger: (...args: unknown[]) => void = console.info,
  ): void {
    for (const keys of Object.keys(this.replies)) {
      const tokenList = this.replies[Number(keys)];
      if (!tokenList) continue;
      for (const key of tokenList) {
        const tokenType = key.get('TokenType') as number;
        if (tokenType === TDS_ERROR_TOKEN) {
          const serverName = (key.get('ServerName') as Buffer).toString('utf16le');
          const lineNumber = key.get('LineNumber') as number;
          const msgText = (key.get('MsgText') as Buffer).toString('utf16le');
          this.lastError = new SQLErrorException(`ERROR(${serverName}): Line ${lineNumber}: ${msgText}`);
          errorLogger(this.lastError);
        } else if (tokenType === TDS_INFO_TOKEN) {
          const serverName = (key.get('ServerName') as Buffer).toString('utf16le');
          const lineNumber = key.get('LineNumber') as number;
          const msgText = (key.get('MsgText') as Buffer).toString('utf16le');
          infoLogger(`INFO(${serverName}): Line ${lineNumber}: ${msgText}`);
        } else if (tokenType === TDS_LOGINACK_TOKEN) {
          const iface = key.get('Interface') as number;
          infoLogger(`ACK: Result: ${iface} - ${this.mssqlVersion}`);
        } else if (tokenType === TDS_ENVCHANGE_TOKEN) {
          const envType = key.get('Type') as number;
          if (envType === TDS_ENVCHANGE_DATABASE || envType === TDS_ENVCHANGE_LANGUAGE ||
              envType === TDS_ENVCHANGE_CHARSET || envType === TDS_ENVCHANGE_PACKETSIZE) {
            const record = new TDS_ENVCHANGE_VARCHAR(key.get('Data') as Buffer);
            let oldValue = record.get('OldValue') as Buffer | string;
            let newValue = record.get('NewValue') as Buffer | string;
            if (oldValue === '') oldValue = Buffer.from('None', 'utf16le');
            else if (newValue === '') newValue = Buffer.from('None', 'utf16le');
            let typeName: string;
            if (envType === TDS_ENVCHANGE_DATABASE) typeName = 'DATABASE';
            else if (envType === TDS_ENVCHANGE_LANGUAGE) typeName = 'LANGUAGE';
            else if (envType === TDS_ENVCHANGE_CHARSET) typeName = 'CHARSET';
            else if (envType === TDS_ENVCHANGE_PACKETSIZE) typeName = 'PACKETSIZE';
            else typeName = String(envType);
            const oldStr = Buffer.isBuffer(oldValue) ? oldValue.toString('utf16le') : oldValue;
            const newStr = Buffer.isBuffer(newValue) ? newValue.toString('utf16le') : newValue;
            infoLogger(`ENVCHANGE(${typeName}): Old Value: ${oldStr}, New Value: ${newStr}`);
          }
        }
      }
    }
  }

  // ---- ROW PARSING ----

  parseRow(token: TDS_ROW, tuplemode = false): number {
    const tokenData = token.get('Data') as Buffer;
    if (tokenData.length <= 1) return 0;

    const row: RowDict | RowTuple = tuplemode ? [] : {};
    const origDataLen = tokenData.length;
    let data = tokenData;

    for (const col of this.colMeta) {
      const _type = col.Type;
      let value: unknown;

      if (_type === TDS_NVARCHARTYPE || _type === TDS_NCHARTYPE) {
        const charLen = data.readUInt16LE(0);
        data = data.subarray(2);
        if (charLen !== 0xffff) {
          value = data.subarray(0, charLen).toString('utf16le');
          data = data.subarray(charLen);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_BIGVARCHRTYPE) {
        const charLen = data.readUInt16LE(0);
        data = data.subarray(2);
        if (charLen !== 0xffff) {
          value = data.subarray(0, charLen);
          data = data.subarray(charLen);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_GUIDTYPE) {
        const uuidLen = data.readUInt8(0);
        data = data.subarray(1);
        if (uuidLen > 0) {
          value = uuidBinToString(data.subarray(0, uuidLen));
          data = data.subarray(uuidLen);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_NTEXTTYPE || _type === TDS_IMAGETYPE) {
        const charLen = data.readUInt8(0);
        if (charLen === 0) {
          value = 'NULL';
          data = data.subarray(1);
        } else {
          data = data.subarray(1 + charLen + 8);
          const dataLen = data.readUInt32LE(0);
          data = data.subarray(4);
          if (dataLen !== 0xffff) {
            if (_type === TDS_NTEXTTYPE) {
              value = data.subarray(0, dataLen).toString('utf16le');
            } else {
              value = data.subarray(0, dataLen).toString('hex');
            }
            data = data.subarray(dataLen);
          } else {
            value = 'NULL';
          }
        }
      } else if (_type === TDS_TEXTTYPE) {
        const charLen = data.readUInt8(0);
        if (charLen === 0) {
          value = 'NULL';
          data = data.subarray(1);
        } else {
          data = data.subarray(1 + charLen + 8);
          const dataLen = data.readUInt32LE(0);
          data = data.subarray(4);
          if (dataLen !== 0xffff) {
            value = data.subarray(0, dataLen);
            data = data.subarray(dataLen);
          } else {
            value = 'NULL';
          }
        }
      } else if (_type === TDS_BIGVARBINTYPE || _type === TDS_BIGBINARYTYPE) {
        const charLen = data.readUInt16LE(0);
        data = data.subarray(2);
        if (charLen !== 0xffff) {
          value = data.subarray(0, charLen).toString('hex');
          data = data.subarray(charLen);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_DATETIM4TYPE || _type === TDS_DATETIMNTYPE || _type === TDS_DATETIMETYPE) {
        value = '';
        let effectiveType = _type;
        if (_type === TDS_DATETIMNTYPE) {
          const dtLen = data.readUInt8(0);
          if (dtLen === 4) {
            effectiveType = TDS_DATETIM4TYPE;
          } else if (dtLen === 8) {
            effectiveType = TDS_DATETIMETYPE;
          } else {
            value = 'NULL';
          }
          data = data.subarray(1);
        }
        if (value !== 'NULL') {
          let dateValue: number;
          let timeValue: number;
          let baseDateMs: number;

          if (effectiveType === TDS_DATETIMETYPE) {
            dateValue = data.readInt32LE(0);
            data = data.subarray(4);
            baseDateMs = dateValue < 0 ? Date.UTC(1753, 0, 1) : Date.UTC(1900, 0, 1);
            timeValue = data.readUInt32LE(0);
            data = data.subarray(4);
          } else {
            dateValue = data.readUInt16LE(0);
            data = data.subarray(2);
            timeValue = data.readUInt16LE(0);
            data = data.subarray(2);
            baseDateMs = Date.UTC(1900, 0, 1);
          }

          const dateMs = baseDateMs + dateValue * 86400000;
          const dt = new Date(dateMs);
          const totalSeconds = Math.floor(timeValue / 300);
          const hours = Math.floor(totalSeconds / 3600);
          const mod = totalSeconds % 3600;
          const minutes = Math.floor(mod / 60);
          const seconds = mod % 60;
          value = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), dt.getUTCDate(), hours, minutes, seconds));
        }
      } else if (_type === TDS_INT4TYPE || _type === TDS_MONEY4TYPE || _type === TDS_FLT4TYPE) {
        value = data.readInt32LE(0);
        data = data.subarray(4);
      } else if (_type === TDS_FLTNTYPE) {
        const valueSize = data.readUInt8(0);
        data = data.subarray(1);
        if (valueSize > 0) {
          if (valueSize === 4) {
            value = data.readFloatLE(0);
          } else {
            value = data.readDoubleLE(0);
          }
          data = data.subarray(valueSize);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_MONEYNTYPE) {
        const valueSize = data.readUInt8(0);
        data = data.subarray(1);
        if (valueSize > 0) {
          if (valueSize === 4) {
            const raw = data.readInt32LE(0);
            value = Math.floor(raw / Math.pow(10, 4));
          } else {
            const raw = Number(data.readBigInt64LE(0));
            value = Math.floor((raw >>> 0) / Math.pow(10, 4));
          }
          data = data.subarray(valueSize);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_BIGCHARTYPE) {
        const charLen = data.readUInt16LE(0);
        data = data.subarray(2);
        value = data.subarray(0, charLen);
        data = data.subarray(charLen);
      } else if (_type === TDS_INT8TYPE || _type === TDS_FLT8TYPE || _type === TDS_MONEYTYPE) {
        value = Number(data.readBigInt64LE(0));
        data = data.subarray(8);
      } else if (_type === TDS_INT2TYPE) {
        value = data.readUInt16LE(0);
        data = data.subarray(2);
      } else if (_type === TDS_DATENTYPE) {
        const valueSize = data.readUInt8(0);
        data = data.subarray(1);
        if (valueSize > 0) {
          const dateBytes = data.subarray(0, valueSize);
          const padded = Buffer.alloc(4);
          padded[0] = 0;
          dateBytes.copy(padded, 1);
          const dateValue = padded.readUInt32LE(0);
          value = new Date(dateValue * 1000);
          data = data.subarray(valueSize);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_BITTYPE || _type === TDS_INT1TYPE) {
        value = data.readUInt8(0);
        data = data.subarray(1);
      } else if (_type === TDS_NUMERICNTYPE || _type === TDS_DECIMALNTYPE) {
        const valueLen = data.readUInt8(0);
        data = data.subarray(1);
        const valueBytes = data.subarray(0, valueLen);
        data = data.subarray(valueLen);
        const precision = (col.TypeData as Buffer).readUInt8(1);
        const scale = (col.TypeData as Buffer).readUInt8(2);
        if (valueLen > 0) {
          const isPositiveSign = valueBytes.readUInt8(0);
          const numBytes = valueBytes.subarray(1);
          let number: number;
          if (numBytes.length === 2) {
            number = numBytes.readUInt16LE(0);
          } else if (numBytes.length === 4) {
            number = numBytes.readUInt32LE(0);
          } else if (numBytes.length === 8) {
            number = Number(numBytes.readBigUInt64LE(0));
          } else {
            number = 0;
          }
          number = Math.floor(number / Math.pow(precision, scale));
          if (isPositiveSign === 0) {
            number *= -1;
          }
          value = number;
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_BITNTYPE) {
        const valueSize = data.readUInt8(0);
        data = data.subarray(1);
        if (valueSize > 0) {
          if (valueSize === 1) {
            value = data.readUInt8(0);
          } else {
            value = data.subarray(0, valueSize);
          }
        } else {
          value = 'NULL';
        }
        data = data.subarray(valueSize);
      } else if (_type === TDS_INTNTYPE) {
        const valueSize = data.readUInt8(0);
        data = data.subarray(1);
        if (valueSize > 0) {
          if (valueSize === 1) {
            value = data.readUInt8(0);
          } else if (valueSize === 2) {
            value = data.readInt16LE(0);
          } else if (valueSize === 4) {
            value = data.readInt32LE(0);
          } else if (valueSize === 8) {
            value = Number(data.readBigInt64LE(0));
          }
          data = data.subarray(valueSize);
        } else {
          value = 'NULL';
        }
      } else if (_type === TDS_SSVARIANTTYPE) {
        throw new Error('ParseRow: SQL Variant type not yet supported');
      } else {
        throw new Error(`ParseRow: Unsupported data type: 0x${_type.toString(16)}`);
      }

      if (tuplemode) {
        (row as RowTuple).push(value);
      } else {
        (row as RowDict)[col.Name] = value;
      }
    }

    this.rows.push(row);
    return origDataLen - data.length;
  }

  parseColMetaData(token: TDS_COLMETADATA): number {
    const count = token.get('Count') as number;
    if (count === 0xffff) return 0;

    this.colMeta = [];
    const tokenData = token.get('Data') as Buffer;
    const origDataLen = tokenData.length;
    let data = tokenData;

    for (let i = 0; i < count; i++) {
      const _userType = data.readUInt16LE(0);
      void _userType;
      data = data.subarray(2);
      const flags = data.readUInt16LE(0);
      data = data.subarray(2);
      const colType = data.readUInt8(0);
      data = data.subarray(1);

      let typeData: number | Buffer;

      if (colType === TDS_BITTYPE || colType === TDS_INT1TYPE || colType === TDS_INT2TYPE ||
          colType === TDS_INT8TYPE || colType === TDS_DATETIMETYPE || colType === TDS_DATETIM4TYPE ||
          colType === TDS_FLT4TYPE || colType === TDS_FLT8TYPE || colType === TDS_MONEYTYPE ||
          colType === TDS_MONEY4TYPE || colType === TDS_DATENTYPE || colType === TDS_INT4TYPE) {
        typeData = 0;
      } else if (colType === TDS_INTNTYPE || colType === TDS_TIMENTYPE ||
                 colType === TDS_DATETIME2NTYPE || colType === TDS_DATETIMEOFFSETNTYPE ||
                 colType === TDS_FLTNTYPE || colType === TDS_MONEYNTYPE ||
                 colType === TDS_GUIDTYPE || colType === TDS_BITNTYPE) {
        typeData = data.readUInt8(0);
        data = data.subarray(1);
      } else if (colType === TDS_DATETIMNTYPE) {
        typeData = data.readUInt8(0);
        data = data.subarray(1);
      } else if (colType === TDS_BIGVARBINTYPE || colType === TDS_BIGBINARYTYPE ||
                 colType === TDS_NCHARTYPE || colType === TDS_NVARCHARTYPE ||
                 colType === TDS_BIGVARCHRTYPE || colType === TDS_BIGCHARTYPE) {
        typeData = data.readUInt16LE(0);
        data = data.subarray(2);
      } else if (colType === TDS_DECIMALNTYPE || colType === TDS_NUMERICNTYPE ||
                 colType === TDS_DECIMALTYPE) {
        typeData = Buffer.from(data.subarray(0, 3));
        data = data.subarray(3);
      } else if (colType === TDS_IMAGETYPE || colType === TDS_TEXTTYPE ||
                 colType === TDS_XMLTYPE || colType === TDS_SSVARIANTTYPE ||
                 colType === TDS_NTEXTTYPE) {
        typeData = data.readUInt32LE(0);
        data = data.subarray(4);
      } else {
        throw new Error(`Unsupported data type: 0x${colType.toString(16)}`);
      }

      if (colType === TDS_NTEXTTYPE || colType === TDS_BIGCHARTYPE ||
          colType === TDS_BIGVARCHRTYPE || colType === TDS_NCHARTYPE ||
          colType === TDS_NVARCHARTYPE || colType === TDS_TEXTTYPE) {
        data = data.subarray(5);
      }

      if (colType === TDS_IMAGETYPE || colType === TDS_TEXTTYPE || colType === TDS_NTEXTTYPE) {
        const dataLen = data.readUInt16LE(0);
        data = data.subarray(2);
        data = data.subarray(dataLen * 2);
      }

      const colNameLength = data.readUInt8(0);
      data = data.subarray(1);
      const colName = data.subarray(0, colNameLength * 2).toString('utf16le');
      data = data.subarray(colNameLength * 2);

      this.colMeta.push({
        Name: colName,
        Type: colType,
        TypeData: typeData,
        Flags: flags,
        Length: 0,
        minLenght: 0,
        Format: '',
      });
    }

    return origDataLen - data.length;
  }

  parseReply(tokens: Buffer, tuplemode = false): TDSReplies {
    if (tokens.length === 0) return {};

    const replies: TDSReplies = {};

    while (tokens.length > 0) {
      const tokenID = tokens.readUInt8(0);
      let token: Structure;

      if (tokenID === TDS_ERROR_TOKEN) {
        token = new TDS_INFO_ERROR(tokens);
        const serverName = (token.get('ServerName') as Buffer).toString('utf16le');
        const lineNumber = token.get('LineNumber') as number;
        const msgText = (token.get('MsgText') as Buffer).toString('utf16le');
        this.lastError = new SQLErrorException(`ERROR(${serverName}): Line ${lineNumber}: ${msgText}`);
      } else if (tokenID === TDS_RETURNSTATUS_TOKEN) {
        token = new TDS_RETURNSTATUS(tokens);
      } else if (tokenID === TDS_INFO_TOKEN) {
        token = new TDS_INFO_ERROR(tokens);
      } else if (tokenID === TDS_LOGINACK_TOKEN) {
        token = new TDS_LOGIN_ACK(tokens);
      } else if (tokenID === TDS_ENVCHANGE_TOKEN) {
        token = new TDS_ENVCHANGE(tokens);
        const envType = token.get('Type') as number;
        if (envType === TDS_ENVCHANGE_PACKETSIZE) {
          const record = new TDS_ENVCHANGE_VARCHAR(token.get('Data') as Buffer);
          const newVal = record.get('NewValue');
          this.packetSize = parseInt(Buffer.isBuffer(newVal) ? newVal.toString('utf16le') : String(newVal), 10);
        } else if (envType === TDS_ENVCHANGE_DATABASE) {
          const record = new TDS_ENVCHANGE_VARCHAR(token.get('Data') as Buffer);
          const newVal = record.get('NewValue');
          this.currentDB = Buffer.isBuffer(newVal) ? newVal.toString('utf16le') : String(newVal);
        }
      } else if (tokenID === TDS_DONEINPROC_TOKEN || tokenID === TDS_DONEPROC_TOKEN) {
        token = new TDS_DONEINPROC(tokens);
      } else if (tokenID === TDS_ORDER_TOKEN) {
        token = new TDS_ORDER(tokens);
      } else if (tokenID === TDS_ROW_TOKEN) {
        token = new TDS_ROW(tokens);
        const tokenLen = this.parseRow(token as TDS_ROW, tuplemode);
        token.set('Data', (token.get('Data') as Buffer).subarray(0, tokenLen));
      } else if (tokenID === TDS_COLMETADATA_TOKEN) {
        token = new TDS_COLMETADATA(tokens);
        const tokenLen = this.parseColMetaData(token as TDS_COLMETADATA);
        token.set('Data', (token.get('Data') as Buffer).subarray(0, tokenLen));
      } else if (tokenID === TDS_DONE_TOKEN) {
        token = new TDS_DONE(tokens);
      } else {
        console.error(`Unknown Token 0x${tokenID.toString(16)}`);
        return replies;
      }

      if (!(tokenID in replies)) {
        replies[tokenID] = [];
      }
      replies[tokenID]!.push(token);
      tokens = tokens.subarray(token.length);
    }

    return replies;
  }

  // ---- SQL OPERATIONS ----

  async batch(cmd: string, tuplemode = false, wait = true): Promise<Row[] | true> {
    this.rows = [];
    this.colMeta = [];
    this.lastError = false;
    await this.sendTDS(TDS_SQL_BATCH, Buffer.from(cmd + '\r\n', 'utf16le'));
    if (wait) {
      const tds = await this.recvTDS();
      this.replies = this.parseReply(tds.get('Data') as Buffer, tuplemode);
      return this.rows;
    }
    return true;
  }

  async batchStatement(cmd: string): Promise<void> {
    this.rows = [];
    this.colMeta = [];
    this.lastError = false;
    await this.sendTDS(TDS_SQL_BATCH, Buffer.from(cmd + '\r\n', 'utf16le'));
  }

  async sqlQuery(cmd: string, tuplemode = false, wait = true): Promise<Row[] | true> {
    return this.batch(cmd, tuplemode, wait);
  }

  async changeDB(db: string): Promise<void> {
    if (db !== this.currentDB) {
      const chdb = `use ${db}`;
      await this.batch(chdb);
      this.printReplies();
    }
  }

  async runSQLQuery(
    db: string | null,
    sqlQueryStr: string,
    tuplemode = false,
    wait = true,
  ): Promise<Row[] | true> {
    const targetDb = db || 'master';
    await this.changeDB(targetDb);
    this.printReplies();
    const ret = await this.batch(sqlQueryStr, tuplemode, wait);
    if (wait) {
      this.printReplies();
    }
    if (this.lastError) {
      throw this.lastError;
    }
    return ret;
  }

  async runSQLStatement(
    db: string | null,
    sqlQueryStr: string,
    wait = true,
  ): Promise<true> {
    await this.runSQLQuery(db, sqlQueryStr, false, wait);
    if (this.lastError) {
      throw this.lastError;
    }
    return true;
  }
}
