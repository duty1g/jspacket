import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import os from 'node:os';
import { parseTLV, parseTLVs, TagClass } from '@impacket/asn1';
import {
  Constants as KrbConstants,
  Types as KrbTypes,
  Asn1 as KrbAsn1,
  Crypto as KrbCrypto,
  KerberosV5,
  GSSAPI as KrbGSSAPI,
} from '@impacket/krb5';
import * as nmb from '@impacket/nmb';
import * as ntlm from '@impacket/ntlm';
import {
  ASN1_AID,
  ASN1_OID,
  SPNEGO_NegTokenInit,
  SPNEGO_NegTokenResp,
  TypesMech,
  asn1encode,
} from '@impacket/spnego';
import type { Structure } from '@impacket/structure';
import * as constants from './constants.js';
import {
  AsciiOrUnicodeStructure,
  NewSMBPacket,
  SMBCheckDirectory_Data,
  SMBClose_Parameters,
  SMBCommand,
  SMBCommand_Parameters,
  SMBCreateDirectory_Data,
  SMBDeleteDirectory_Data,
  SMBDelete_Data,
  SMBDelete_Parameters,
  SMBEcho_Data,
  SMBEcho_Parameters,
  SMBExtended_Security_Data,
  SMBExtended_Security_Parameters,
  SMBFlush_Parameters,
  SMBLogOffAndX,
  SMBNTLMDialect_Data,
  SMBNTLMDialect_Data_ExtSec,
  SMBNTLMDialect_Parameters,
  SMBNTTransactionResponse_Parameters,
  SMBNTTransaction_Data,
  SMBNTTransaction_Parameters,
  SMBNtCreateAndXResponse_Parameters,
  SMBNtCreateAndX_Data,
  SMBNtCreateAndX_Parameters,
  SMBOpenAndXResponse_Parameters,
  SMBOpenAndX_Data,
  SMBOpenAndX_Parameters,
  SMBOpenResponse_Parameters,
  SMBOpen_Data,
  SMBOpen_Parameters,
  SMBQueryFileStandardInfo,
  SMBReadAndXResponse_Parameters,
  SMBReadAndX_Parameters,
  SMBReadRaw_Parameters,
  SMBReadResponse_Data,
  SMBRead_Parameters,
  SMBRename_Data,
  SMBRename_Parameters,
  SMBSessionSetupAndXResponse_Data,
  SMBSessionSetupAndXResponse_Parameters,
  SMBSessionSetupAndX_Data,
  SMBSessionSetupAndX_Extended_Data,
  SMBSessionSetupAndX_Extended_Parameters,
  SMBSessionSetupAndX_Extended_Response_Data,
  SMBSessionSetupAndX_Extended_Response_Parameters,
  SMBSessionSetupAndX_Parameters,
  SMBTransaction2Response_Parameters,
  SMBTransaction2_Data,
  SMBTransaction2_Parameters,
  SMBTransactionResponse_Parameters,
  SMBTransaction_Data,
  SMBTransaction_Parameters,
  SMBTransaction_SData,
  SMBTreeConnectAndX_Data,
  SMBTreeConnectAndX_Parameters,
  SMBTreeConnect_Data,
  SMBTreeConnect_Parameters,
  SMBWriteAndXResponse_Parameters,
  SMBWriteAndX_Data,
  SMBWriteAndX_Parameters,
  SMBWriteRaw_Parameters,
  SMBWriteResponse_Parameters,
  SMBWrite_Data,
  SMBWrite_Parameters,
} from './structures.js';

const F = constants.FLAGS2_UNICODE;

/** Extract the raw DER-encoded ticket bytes from a KDC-REP (AS-REP or TGS-REP). */
function extractRawTicketFromKdcRep(kdcRepBytes: Buffer): Buffer {
  let tlv = parseTLV(kdcRepBytes);
  // Unwrap APPLICATION tag (AS-REP=11, TGS-REP=13)
  if (tlv.cls === TagClass.APPLICATION) tlv = parseTLV(tlv.value);
  // Inside the SEQUENCE, find context tag [5] which holds the ticket
  const inner = parseTLVs(tlv.value);
  for (const t of inner) {
    if (t.cls === TagClass.CONTEXT && t.tag === 5) {
      return t.value;
    }
  }
  throw new Error('Ticket not found in KDC-REP');
}

export interface SMBOptions {
  myName?: string;
  hostType?: number;
  sessPort?: number;
  timeout?: number | null;
  udp?: boolean;
  session?: nmb.NetBIOSTCPSession | null;
  negPacket?: Buffer | null;
}

export interface Credentials {
  user: string;
  password: string;
  domain: string;
  lmhash: Buffer | string;
  nthash: Buffer | string;
  aesKey: Buffer | string;
  tgt: unknown;
  tgs: unknown;
}

export class SMB {
  static HostnameValidationException = class extends Error {};

  _uid = 0;
  private _serverName = '';
  private _clientName = '';
  private _serverOS = '';
  private _serverOSMajor: number | null = null;
  private _serverOSMinor: number | null = null;
  private _serverOSBuild: number | null = null;
  private _serverLanman = '';
  private _serverDomain = '';
  private _serverDnsDomainName = '';
  private _serverDnsHostName = '';
  private _remoteName: string;
  private _remoteHost: string;
  private _isNTLMv2 = true;
  _dialectsParameters: SMBNTLMDialect_Parameters | SMBExtended_Security_Parameters | null = null;
  _dialectsData: SMBNTLMDialect_Data | SMBExtended_Security_Data | null = null;
  private _doKerberos = false;

  private _userName = '';
  private _password = '';
  private _domain = '';
  private _lmhash: Buffer | string = '';
  private _nthash: Buffer | string = '';
  private _aesKey: Buffer | string = '';
  private _kdc = '';
  private _TGT: unknown = null;
  private _TGS: unknown = null;

  private _dialectData: number | Structure = 0;
  private _dialectParameters: number | Structure = 0;
  private _action = 0;
  _sess: nmb.NetBIOSTCPSession | null = null;
  encryptPasswords = true;
  tid = 0;
  fid = 0;

  private _strictHostnameValidation = false;
  private _validationAllowAbsent = true;
  private _acceptedHostname = '';

  private _signSequenceNumber = 0;
  private _signingSessionKey: Buffer = Buffer.alloc(0);
  private _signingChallengeResponse: Buffer = Buffer.alloc(0);
  private _signatureEnabled = false;
  private _signatureVerificationEnabled = false;
  private _signatureRequired = false;

  private _flags1 = constants.FLAGS1_PATHCASELESS | constants.FLAGS1_CANONICALIZED_PATHS;
  private _flags2 =
    constants.FLAGS2_EXTENDED_SECURITY | constants.FLAGS2_NT_STATUS | constants.FLAGS2_LONG_NAMES;

  private _timeout: number;

  constructor(remoteName: string, remoteHost: string, options: SMBOptions = {}) {
    const {
      myName = null,
      hostType = nmb.TYPE_SERVER,
      sessPort = 445,
      timeout = null,
      udp = false,
      session = null,
    } = options;

    this._remoteName = remoteName.toUpperCase();
    this._remoteHost = remoteHost;
    this._timeout = timeout ?? 60;

    if (sessPort === 445 && remoteName === '*SMBSERVER') {
      this._remoteName = remoteHost;
    }

    if (myName === null) {
      this._clientName = '';
    } else {
      this._clientName = myName;
    }

    if (session === null) {
      let localName = myName;
      if (!localName) {
        localName = os.hostname();
        const i = localName.indexOf('.');
        if (i > -1) localName = localName.slice(0, i);
      }
      if (udp) {
        throw new Error('UDP mode not yet supported');
      }
      this._sess = new nmb.NetBIOSTCPSession(
        localName,
        this._remoteName,
        remoteHost,
        hostType,
        sessPort,
        this._timeout,
      );
    } else {
      this._sess = session;
    }
  }

  async negotiate(extendedSecurity = true, negPacket?: Buffer | null): Promise<number> {
    return this.negSession(extendedSecurity, negPacket);
  }

  getKerberos(): boolean {
    return this._doKerberos;
  }

  getRemoteName(): string {
    return this._remoteName;
  }

  setRemoteName(name: string): boolean {
    this._remoteName = name;
    return true;
  }

  setHostnameValidation(validate: boolean, acceptEmpty: boolean, hostname: string): void {
    this._strictHostnameValidation = validate;
    this._validationAllowAbsent = acceptEmpty;
    this._acceptedHostname = hostname;
  }

  getRemoteHost(): string {
    return this._remoteHost;
  }

  getFlags(): [number, number] {
    return [this._flags1, this._flags2];
  }

  setFlags(flags1?: number, flags2?: number): void {
    if (flags1 !== undefined) this._flags1 = flags1;
    if (flags2 !== undefined) this._flags2 = flags2;
  }

  setTimeout(timeout: number | null): number {
    const prev = this._timeout;
    this._timeout = timeout ?? 60;
    return prev;
  }

  getTimeout(): number {
    return this._timeout;
  }

  getSession(): nmb.NetBIOSTCPSession | null {
    return this._sess;
  }

  getTid(): number {
    return this.tid;
  }

  getFid(): number {
    return this.fid;
  }

  isGuestSession(): boolean {
    return (this._action & constants.SMB_SETUP_GUEST) !== 0;
  }

  doesSupportNTLMv2(): boolean {
    return this._isNTLMv2;
  }

  closeSession(): void {
    if (this._sess) {
      this._sess.close();
      this._sess = null;
    }
  }

  async recvSMB(): Promise<NewSMBPacket> {
    if (!this._sess) throw new Error('No session');
    const r = await this._sess.recvPacket(this._timeout);
    return new NewSMBPacket(r.get_trailer());
  }

  signSMB(packet: NewSMBPacket, signingSessionKey: Buffer, signingChallengeResponse: Buffer): void {
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeInt32LE(this._signSequenceNumber, 0);
    seqBuf.writeInt32LE(0, 4);
    packet.set('SecurityFeatures', seqBuf);

    const m = createHash('md5');
    m.update(signingSessionKey);
    m.update(signingChallengeResponse);
    m.update(packet.getData());
    const digest = m.digest().subarray(0, 8);
    packet.set('SecurityFeatures', digest);

    if (this._signatureVerificationEnabled) {
      this._signSequenceNumber += 1;
    } else {
      this._signSequenceNumber += 2;
    }
  }

  checkSignSMB(
    packet: NewSMBPacket,
    signingSessionKey: Buffer,
    signingChallengeResponse: Buffer,
  ): boolean {
    const signature = packet.get('SecurityFeatures') as Buffer;
    this.signSMB(packet, signingSessionKey, signingChallengeResponse);
    if (!this._signatureVerificationEnabled) {
      this._signSequenceNumber -= 1;
    }
    const calcSig = packet.get('SecurityFeatures') as Buffer;
    return Buffer.compare(calcSig, signature) === 0;
  }

  async sendSMB(smb: NewSMBPacket): Promise<void> {
    smb.set('Uid', this._uid);
    smb.set('Pid', process.pid & 0xffff);
    let flags1 = smb.get('Flags1') as number;
    let flags2 = smb.get('Flags2') as number;
    flags1 |= this._flags1;
    flags2 |= this._flags2;
    smb.set('Flags1', flags1);
    smb.set('Flags2', flags2);
    if (this._signatureEnabled) {
      flags2 |= constants.FLAGS2_SMB_SECURITY_SIGNATURE;
      smb.set('Flags2', flags2);
      this.signSMB(smb, this._signingSessionKey, this._signingChallengeResponse);
    }
    if (!this._sess) throw new Error('No session');
    await this._sess.sendPacket(smb.getData());
  }

  async negSession(extendedSecurity = true, negPacket?: Buffer | null): Promise<number> {
    const parsePacket = (smb: NewSMBPacket): number => {
      if ((smb.get('Flags2') as number) & constants.FLAGS2_UNICODE) {
        this._flags2 |= constants.FLAGS2_UNICODE;
      }

      if (smb.isValidAnswer(constants.SMB_COMMAND_NEGOTIATE)) {
        const dataArr = smb.get('Data') as SMBCommand[];
        const sessionResponse = dataArr[0]!;
        this._dialectsParameters = new SMBNTLMDialect_Parameters(
          sessionResponse.get('Parameters') as Buffer,
        );
        this._dialectsData = new SMBNTLMDialect_Data();
        this._dialectsData.set(
          'ChallengeLength',
          this._dialectsParameters.get('ChallengeLength') as number,
        );
        try {
          this._dialectsData.fromString(sessionResponse.get('Data') as Buffer);
        } catch {
          throw new constants.SessionError(
            'Connection failed: invalid or truncated server response',
            0x000d,
            0xc000,
          );
        }

        if (
          (this._dialectsParameters.get('Capabilities') as number) & constants.CAP_EXTENDED_SECURITY
        ) {
          this._dialectsParameters = new SMBExtended_Security_Parameters(
            sessionResponse.get('Parameters') as Buffer,
          );
          try {
            this._dialectsData = new SMBExtended_Security_Data(
              sessionResponse.get('Data') as Buffer,
            );
          } catch {
            throw new constants.SessionError(
              'Connection failed: invalid or truncated server response',
              0x000d,
              0xc000,
            );
          }
          if (
            (this._dialectsParameters.get('SecurityMode') as number) &
            constants.SECURITY_SIGNATURES_REQUIRED
          ) {
            this._signatureRequired = true;
          }
          return 1;
        }
        if ((this._dialectsParameters.get('DialectIndex') as number) === 0xffff) {
          throw new constants.UnsupportedFeature('Remote server does not know NT LM 0.12');
        }
        return 1;
      }
      return 0;
    };

    if (!negPacket) {
      const smb = new NewSMBPacket();
      const negSession = new SMBCommand(constants.SMB_COMMAND_NEGOTIATE);
      const flags2 = this._flags2;
      if (extendedSecurity) {
        this._flags2 = flags2 | constants.FLAGS2_EXTENDED_SECURITY;
      } else {
        this._flags2 = flags2 & ~constants.FLAGS2_EXTENDED_SECURITY;
      }
      negSession.set('Data', Buffer.from('\x02NT LM 0.12\x00', 'latin1'));
      smb.addCommand(negSession);
      await this.sendSMB(smb);
      const resp = await this.recvSMB();
      return parsePacket(resp);
    }
    return parsePacket(new NewSMBPacket(negPacket));
  }

  async treeConnect(
    path: string,
    password: Buffer | string = '',
    service = constants.SERVICE_ANY,
  ): Promise<number> {
    const smb = new NewSMBPacket();
    const treeConnect = new SMBCommand(constants.SMB_COMMAND_TREE_CONNECT);
    treeConnect.set('Parameters', new SMBTreeConnect_Parameters());
    const data = new SMBTreeConnect_Data();
    data.set('Path', path.toUpperCase());
    data.set('Password', password);
    data.set('Service', service);
    treeConnect.set('Data', data.getData());
    smb.addCommand(treeConnect);
    await this.sendSMB(smb);
    const resp = await this.recvSMB();
    return resp.get('Tid') as number;
  }

  async treeConnectAndX(
    path: string,
    password: Buffer | string | null = null,
    service = constants.SERVICE_ANY,
    smbPacket?: NewSMBPacket,
  ): Promise<number> {
    let pwd: Buffer | string;
    if (password) {
      if (
        this._dialectsParameters &&
        (this._dialectsParameters.get('ChallengeLength') as number) > 0
      ) {
        pwd = this.getNtlmv1Response(ntlm.computeLmhash(password as string));
      } else {
        pwd = password;
      }
    } else {
      pwd = '\x00';
    }

    const smb = smbPacket ?? new NewSMBPacket();

    const share = path.split('\\').pop()!;
    const remoteHost = this._remoteHost;
    let pathBuf: Buffer | string = `\\\\${remoteHost}\\${share}`;
    pathBuf =
      this._flags2 & F ? Buffer.from(pathBuf.toUpperCase(), 'utf-16le') : pathBuf.toUpperCase();

    const treeConnect = new SMBCommand(constants.SMB_COMMAND_TREE_CONNECT_ANDX);
    treeConnect.set('Parameters', new SMBTreeConnectAndX_Parameters());
    const data = new SMBTreeConnectAndX_Data(this._flags2);
    treeConnect.set('Parameters', new SMBTreeConnectAndX_Parameters());
    (treeConnect.get('Parameters') as SMBTreeConnectAndX_Parameters).set(
      'PasswordLength',
      typeof pwd === 'string' ? pwd.length : pwd.length,
    );
    data.set('Password', pwd);
    data.set('Path', pathBuf);
    data.set('Service', service);
    if (this._flags2 & F) {
      data.set('Pad', 0x0);
    }
    treeConnect.set('Data', data.getData());

    smb.addCommand(treeConnect);
    await this.sendSMB(smb);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_TREE_CONNECT_ANDX)) {
      this.tid = resp.get('Tid') as number;
      return this.tid;
    }
    this.tid = resp.get('Tid') as number;
    return this.tid;
  }

  connectTree = SMB.prototype.treeConnectAndX;

  static getDialect(): string {
    return constants.SMB_DIALECT;
  }

  getDialect(): string {
    return constants.SMB_DIALECT;
  }

  getServerName(): string {
    return this._serverName;
  }

  getClientName(): string {
    return this._clientName;
  }

  getSessionKey(): Buffer {
    return this._signingSessionKey;
  }

  setSessionKey(key: Buffer): void {
    this._signatureEnabled = true;
    this._signSequenceNumber = 2;
    this._signingSessionKey = key;
  }

  getEncryptionKey(): Buffer | null {
    if (this._dialectsData?.has('Challenge')) {
      return this._dialectsData.get('Challenge') as Buffer;
    }
    return null;
  }

  getServerTime(): string {
    if (!this._dialectsParameters) return '';
    const high = BigInt(this._dialectsParameters.get('HighDateTime') as number);
    const low = BigInt(this._dialectsParameters.get('LowDateTime') as number);
    let ts = (high << 32n) | low;
    ts -= 116444736000000000n;
    ts /= 10000000n;
    return new Date(Number(ts) * 1000).toUTCString();
  }

  async disconnectTree(tid: number): Promise<void> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    smb.addCommand(new SMBCommand(constants.SMB_COMMAND_TREE_DISCONNECT));
    await this.sendSMB(smb);
    await this.recvSMB();
  }

  async open(
    tid: number,
    filename: string,
    openMode: number,
    desiredAccess: number,
  ): Promise<[number, number, number, number, number]> {
    filename = filename.replace('/', '\\');
    const filenameBuf = this._flags2 & F ? Buffer.from(filename, 'utf-16le') : filename;

    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const openFile = new SMBCommand(constants.SMB_COMMAND_OPEN);
    openFile.set('Parameters', new SMBOpen_Parameters());
    (openFile.get('Parameters') as SMBOpen_Parameters).set('DesiredAccess', desiredAccess);
    (openFile.get('Parameters') as SMBOpen_Parameters).set('OpenMode', openMode);
    (openFile.get('Parameters') as SMBOpen_Parameters).set(
      'SearchAttributes',
      constants.ATTR_READONLY | constants.ATTR_HIDDEN | constants.ATTR_ARCHIVE,
    );
    const data = new SMBOpen_Data(this._flags2);
    data.set('FileName', filenameBuf);
    openFile.set('Data', data.getData());
    smb.addCommand(openFile);
    await this.sendSMB(smb);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_OPEN)) {
      const dataArr = resp.get('Data') as SMBCommand[];
      const openFileResponse = dataArr[0]!;
      const params = new SMBOpenResponse_Parameters(openFileResponse.get('Parameters') as Buffer);
      return [
        params.get('Fid') as number,
        params.get('FileAttributes') as number,
        params.get('LastWriten') as number,
        params.get('FileSize') as number,
        params.get('GrantedAccess') as number,
      ];
    }
    throw new Error('Open failed');
  }

  async openAndX(
    tid: number,
    filename: string,
    openMode: number,
    desiredAccess: number,
  ): Promise<[number, number, number, number, number, number, number, number, number]> {
    filename = filename.replace('/', '\\');
    const filenameBuf = this._flags2 & F ? Buffer.from(filename, 'utf-16le') : filename;

    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const openFile = new SMBCommand(constants.SMB_COMMAND_OPEN_ANDX);
    openFile.set('Parameters', new SMBOpenAndX_Parameters());
    const params = openFile.get('Parameters') as SMBOpenAndX_Parameters;
    params.set('DesiredAccess', desiredAccess);
    params.set('OpenMode', openMode);
    params.set(
      'SearchAttributes',
      constants.ATTR_READONLY | constants.ATTR_HIDDEN | constants.ATTR_ARCHIVE,
    );
    const data = new SMBOpenAndX_Data(this._flags2);
    data.set('FileName', filenameBuf);
    if (this._flags2 & F) data.set('Pad', 0x0);
    openFile.set('Data', data.getData());
    smb.addCommand(openFile);
    await this.sendSMB(smb);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_OPEN_ANDX)) {
      const dataArr = resp.get('Data') as SMBCommand[];
      const openFileResponse = dataArr[0]!;
      const p = new SMBOpenAndXResponse_Parameters(openFileResponse.get('Parameters') as Buffer);
      return [
        p.get('Fid') as number,
        p.get('FileAttributes') as number,
        p.get('LastWriten') as number,
        p.get('FileSize') as number,
        p.get('GrantedAccess') as number,
        p.get('FileType') as number,
        p.get('IPCState') as number,
        p.get('Action') as number,
        p.get('ServerFid') as number,
      ];
    }
    throw new Error('OpenAndX failed');
  }

  async close(tid: number, fid: number): Promise<number> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const closeFile = new SMBCommand(constants.SMB_COMMAND_CLOSE);
    const params = new SMBClose_Parameters();
    params.set('FID', fid);
    closeFile.set('Parameters', params);
    smb.addCommand(closeFile);
    await this.sendSMB(smb);
    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_CLOSE)) return 1;
    return 0;
  }

  async sendTrans(
    tid: number,
    setup: Buffer,
    name: string | Buffer,
    param: Buffer,
    data: Buffer,
    noAnswer = 0,
  ): Promise<void> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const transCommand = new SMBCommand(constants.SMB_COMMAND_TRANSACTION);
    transCommand.set('Parameters', new SMBTransaction_Parameters());
    transCommand.set('Data', new SMBTransaction_Data());
    const params = transCommand.get('Parameters') as SMBTransaction_Parameters;
    params.set('Setup', setup);
    params.set('TotalParameterCount', param.length);
    params.set('TotalDataCount', data.length);
    params.set('ParameterCount', param.length);
    params.set('ParameterOffset', 32 + 3 + 28 + setup.length + name.length);
    params.set('DataCount', data.length);
    params.set('DataOffset', 32 + 3 + 28 + setup.length + name.length + param.length);
    const d = transCommand.get('Data') as SMBTransaction_Data;
    d.set('Name', typeof name === 'string' ? Buffer.from(name, 'latin1') : name);
    d.set('Trans_Parameters', param);
    d.set('Trans_Data', data);
    if (noAnswer) {
      params.set('Flags', constants.TRANS_NO_RESPONSE);
    }
    smb.addCommand(transCommand);
    await this.sendSMB(smb);
  }

  async sendTrans2(
    tid: number,
    setup: number,
    name: string | Buffer,
    param: Buffer,
    data: Buffer,
  ): Promise<void> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const command = Buffer.alloc(2);
    command.writeUInt16LE(setup, 0);
    const transCommand = new SMBCommand(constants.SMB_COMMAND_TRANSACTION2);
    transCommand.set('Parameters', new SMBTransaction2_Parameters());
    const params = transCommand.get('Parameters') as SMBTransaction2_Parameters;
    if (this._dialectsParameters) {
      params.set('MaxDataCount', this._dialectsParameters.get('MaxBufferSize') as number);
    }
    transCommand.set('Data', new SMBTransaction2_Data());
    params.set('Setup', command);
    params.set('TotalParameterCount', param.length);
    params.set('TotalDataCount', data.length);

    let padLen = 0;
    if (param.length > 0) {
      padLen = (4 - ((32 + 2 + 28 + command.length) % 4)) % 4;
      (transCommand.get('Data') as SMBTransaction2_Data).set('Pad1', Buffer.alloc(padLen, 0xff));
    } else {
      (transCommand.get('Data') as SMBTransaction2_Data).set('Pad1', Buffer.alloc(0));
    }

    params.set('ParameterCount', param.length);
    params.set('ParameterOffset', 32 + 2 + 28 + command.length + name.length + padLen);

    let pad2Len = 0;
    if (data.length > 0) {
      pad2Len = (4 - ((32 + 2 + 28 + command.length + padLen + param.length) % 4)) % 4;
      (transCommand.get('Data') as SMBTransaction2_Data).set('Pad2', Buffer.alloc(pad2Len, 0xff));
    } else {
      (transCommand.get('Data') as SMBTransaction2_Data).set('Pad2', Buffer.alloc(0));
    }

    params.set('DataCount', data.length);
    params.set('DataOffset', (params.get('ParameterOffset') as number) + param.length + pad2Len);

    const d = transCommand.get('Data') as SMBTransaction2_Data;
    d.set('Trans_Parameters', param);
    d.set('Trans_Data', data);
    smb.addCommand(transCommand);
    await this.sendSMB(smb);
  }

  async queryFileInfo(
    tid: number,
    fid: number,
    fileInfoClass = constants.SMB_QUERY_FILE_STANDARD_INFO,
  ): Promise<Buffer> {
    const param = Buffer.alloc(4);
    param.writeUInt16LE(fid, 0);
    param.writeUInt16LE(fileInfoClass, 2);
    await this.sendTrans2(
      tid,
      constants.TRANS2_QUERY_FILE_INFORMATION,
      '\x00',
      param,
      Buffer.alloc(0),
    );

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_TRANSACTION2)) {
      const dataArr = resp.get('Data') as SMBCommand[];
      const trans2Response = dataArr[0]!;
      const trans2Parameters = new SMBTransaction2Response_Parameters(
        trans2Response.get('Parameters') as Buffer,
      );
      const totalDataCount = trans2Parameters.get('TotalDataCount') as number;
      const d = trans2Response.get('Data') as Buffer;
      return d.subarray(d.length - totalDataCount);
    }
    throw new Error('query_file_info failed');
  }

  async setFileInfo(
    tid: number,
    fid: number,
    fileInfoClass: number,
    fileInfoData: Buffer,
  ): Promise<Buffer> {
    const param = Buffer.alloc(6);
    param.writeUInt16LE(fid, 0);
    param.writeUInt16LE(fileInfoClass, 2);
    await this.sendTrans2(tid, constants.TRANS2_SET_FILE_INFORMATION, '\x00', param, fileInfoData);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_TRANSACTION2)) {
      const dataArr = resp.get('Data') as SMBCommand[];
      const trans2Response = dataArr[0]!;
      const trans2Parameters = new SMBTransaction2Response_Parameters(
        trans2Response.get('Parameters') as Buffer,
      );
      const totalDataCount = trans2Parameters.get('TotalDataCount') as number;
      const d = trans2Response.get('Data') as Buffer;
      return d.subarray(d.length - totalDataCount);
    }
    throw new Error('set_file_info failed');
  }

  async read(tid: number, fid: number, offset = 0, maxSize?: number): Promise<Buffer | null> {
    const max_size = maxSize ?? (this._dialectsParameters?.get('MaxBufferSize') as number) ?? 65535;
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const read = new SMBCommand(constants.SMB_COMMAND_READ);
    read.set('Parameters', new SMBRead_Parameters());
    const params = read.get('Parameters') as SMBRead_Parameters;
    params.set('Fid', fid);
    params.set('Offset', offset);
    params.set('Count', max_size);
    smb.addCommand(read);
    await this.sendSMB(smb);
    const ans = await this.recvSMB();
    if (ans.isValidAnswer(constants.SMB_COMMAND_READ)) {
      const dataArr = ans.get('Data') as SMBCommand[];
      const readResponse = dataArr[0]!;
      const readData = new SMBReadResponse_Data(readResponse.get('Data') as Buffer);
      return readData.get('Data') as Buffer;
    }
    return null;
  }

  async readAndX(
    tid: number,
    fid: number,
    offset = 0,
    maxSize?: number,
    waitAnswer = true,
    smbPacket?: NewSMBPacket,
  ): Promise<Buffer | NewSMBPacket | null> {
    let max_size = maxSize;
    if (!max_size) {
      if (
        this._dialectsParameters &&
        (this._dialectsParameters.get('Capabilities') as number) & constants.CAP_LARGE_READX &&
        !this._signatureEnabled
      ) {
        max_size = 65000;
      } else {
        max_size = (this._dialectsParameters?.get('MaxBufferSize') as number) ?? 65535;
      }
    }

    let smb: NewSMBPacket;
    let readAndX: SMBCommand;
    if (!smbPacket) {
      smb = new NewSMBPacket();
      smb.set('Tid', tid);
      readAndX = new SMBCommand(constants.SMB_COMMAND_READ_ANDX);
      readAndX.set('Parameters', new SMBReadAndX_Parameters());
      const params = readAndX.get('Parameters') as SMBReadAndX_Parameters;
      params.set('Fid', fid);
      params.set('Offset', offset);
      params.set('MaxCount', max_size);
      smb.addCommand(readAndX);
    } else {
      smb = smbPacket;
      readAndX = (smb.get('Data') as SMBCommand[])[0]!;
    }

    if (waitAnswer) {
      let answer = Buffer.alloc(0);
      while (true) {
        await this.sendSMB(smb);
        const ans = await this.recvSMB();
        if (ans.isValidAnswer(constants.SMB_COMMAND_READ_ANDX)) {
          const dataArr = ans.get('Data') as SMBCommand[];
          const readAndXResponse = dataArr[0]!;
          const readAndXParameters = new SMBReadAndXResponse_Parameters(
            readAndXResponse.get('Parameters') as Buffer,
          );
          const dataOffset = readAndXParameters.get('DataOffset') as number;
          const dataCount = readAndXParameters.get('DataCount') as number;
          const dataCountHi = readAndXParameters.get('DataCount_Hi') as number;
          const count = dataCount + 0x10000 * dataCountHi;
          const fullData = ans.getData();
          answer = Buffer.concat([answer, fullData.subarray(dataOffset, dataOffset + count)]);
          if (!ans.isMoreData()) {
            return answer;
          }
          const remaining = readAndXParameters.get('Remaining') as number;
          max_size = Math.min(max_size, remaining);
          (readAndX.get('Parameters') as SMBReadAndX_Parameters).set('Offset', offset + count);
        }
      }
    } else {
      await this.sendSMB(smb);
      const ans = await this.recvSMB();
      try {
        if (ans.isValidAnswer(constants.SMB_COMMAND_READ_ANDX)) {
          return ans;
        }
        return null;
      } catch {
        return ans;
      }
    }
  }

  async readRaw(
    tid: number,
    fid: number,
    offset = 0,
    maxSize?: number,
    waitAnswer = true,
  ): Promise<Buffer | null> {
    const max_size = maxSize ?? (this._dialectsParameters?.get('MaxBufferSize') as number) ?? 65535;
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const readRaw = new SMBCommand(constants.SMB_COMMAND_READ_RAW);
    readRaw.set('Parameters', new SMBReadRaw_Parameters());
    const params = readRaw.get('Parameters') as SMBReadRaw_Parameters;
    params.set('Fid', fid);
    params.set('Offset', offset);
    params.set('MaxCount', max_size);
    smb.addCommand(readRaw);
    await this.sendSMB(smb);

    if (waitAnswer && this._sess) {
      const data = (await this._sess.recvPacket(this._timeout)).get_trailer();
      if (!data || data.length === 0) {
        return this.readAndX(tid, fid, offset, max_size) as Promise<Buffer>;
      }
      return data;
    }
    return null;
  }

  async write(
    tid: number,
    fid: number,
    data: Buffer,
    offset = 0,
    waitAnswer = true,
  ): Promise<NewSMBPacket | null> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const write = new SMBCommand(constants.SMB_COMMAND_WRITE);
    write.set('Parameters', new SMBWrite_Parameters());
    write.set('Data', new SMBWrite_Data());
    const params = write.get('Parameters') as SMBWrite_Parameters;
    params.set('Fid', fid);
    params.set('Count', data.length);
    params.set('Offset', offset);
    params.set('Remaining', data.length);
    (write.get('Data') as SMBWrite_Data).set('Data', data);
    smb.addCommand(write);
    await this.sendSMB(smb);
    if (waitAnswer) {
      const resp = await this.recvSMB();
      if (resp.isValidAnswer(constants.SMB_COMMAND_WRITE)) {
        return resp;
      }
    }
    return null;
  }

  async writeAndX(
    tid: number,
    fid: number,
    data: Buffer,
    offset = 0,
    waitAnswer = true,
    writePipeMode = false,
    smbPacket?: NewSMBPacket,
  ): Promise<NewSMBPacket | null> {
    let smb: NewSMBPacket;
    if (!smbPacket) {
      smb = new NewSMBPacket();
      smb.set('Tid', tid);
      const writeAndX = new SMBCommand(constants.SMB_COMMAND_WRITE_ANDX);
      smb.addCommand(writeAndX);
      writeAndX.set('Parameters', new SMBWriteAndX_Parameters());
      const params = writeAndX.get('Parameters') as SMBWriteAndX_Parameters;
      params.set('Fid', fid);
      params.set('Offset', offset);
      params.set('WriteMode', 8);
      params.set('Remaining', data.length);
      params.set('DataLength', data.length);
      params.set('DataOffset', smb.getData().length);
      writeAndX.set('Data', data);

      if (writePipeMode && this._dialectsParameters) {
        const maxBuffSize = this._dialectsParameters.get('MaxBufferSize') as number;
        if (data.length > maxBuffSize) {
          const chunksSize = maxBuffSize - 60;
          params.set('WriteMode', 0x0c);
          const sendData = Buffer.concat([Buffer.from([0xff, 0xff]), data]);
          const totalLen = sendData.length;
          params.set('DataLength', chunksSize);
          params.set('Remaining', totalLen - 2);
          writeAndX.set('Data', sendData.subarray(0, chunksSize));
          await this.sendSMB(smb);
          let smbResp: NewSMBPacket | null = null;
          if (waitAnswer) {
            smbResp = await this.recvSMB();
            smbResp!.isValidAnswer(constants.SMB_COMMAND_WRITE_ANDX);
          }
          let alreadySent = chunksSize;
          let remaining = sendData.subarray(chunksSize);
          while (alreadySent < totalLen) {
            params.set('WriteMode', 0x04);
            params.set('DataLength', remaining.subarray(0, chunksSize).length);
            writeAndX.set('Data', remaining.subarray(0, chunksSize));
            await this.sendSMB(smb);
            if (waitAnswer) {
              smbResp = await this.recvSMB();
              smbResp!.isValidAnswer(constants.SMB_COMMAND_WRITE_ANDX);
            }
            alreadySent += params.get('DataLength') as number;
            remaining = remaining.subarray(chunksSize);
          }
          return smbResp;
        }
      }
    } else {
      smb = smbPacket;
    }

    await this.sendSMB(smb);
    if (waitAnswer) {
      const resp = await this.recvSMB();
      if (resp.isValidAnswer(constants.SMB_COMMAND_WRITE_ANDX)) {
        return resp;
      }
    }
    return null;
  }

  async writeRaw(
    tid: number,
    fid: number,
    data: Buffer,
    offset = 0,
    waitAnswer = true,
  ): Promise<NewSMBPacket | null> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const writeRaw = new SMBCommand(constants.SMB_COMMAND_WRITE_RAW);
    writeRaw.set('Parameters', new SMBWriteRaw_Parameters());
    const params = writeRaw.get('Parameters') as SMBWriteRaw_Parameters;
    params.set('Fid', fid);
    params.set('Offset', offset);
    params.set('Count', data.length);
    params.set('DataLength', 0);
    params.set('DataOffset', 0);
    smb.addCommand(writeRaw);
    await this.sendSMB(smb);
    if (this._sess) await this._sess.sendPacket(data);
    if (waitAnswer) {
      const resp = await this.recvSMB();
      if (resp.isValidAnswer(constants.SMB_COMMAND_WRITE_RAW)) {
        return resp;
      }
    }
    return null;
  }

  async transactNamedPipe(
    tid: number,
    fid: number,
    data: Buffer,
    noAnswer = 0,
    waitAnswer = true,
    _offset = 0,
  ): Promise<Buffer | null> {
    const setup = Buffer.alloc(4);
    setup.writeUInt16LE(constants.TRANS_TRANSACT_NMPIPE, 0);
    setup.writeUInt16LE(fid, 2);
    await this.sendTrans(tid, setup, '\\PIPE\\\x00', Buffer.alloc(0), data, noAnswer);

    if (noAnswer || !waitAnswer) return null;
    const smb = await this.recvSMB();
    if (smb.isValidAnswer(constants.SMB_COMMAND_TRANSACTION)) {
      const dataArr = smb.get('Data') as SMBCommand[];
      const transResponse = dataArr[0]!;
      const transParameters = new SMBTransactionResponse_Parameters(
        transResponse.get('Parameters') as Buffer,
      );
      const totalDataCount = transParameters.get('TotalDataCount') as number;
      const d = transResponse.get('Data') as Buffer;
      return d.subarray(d.length - totalDataCount);
    }
    return null;
  }

  async transactNamedPipeRecv(): Promise<Buffer | null> {
    const s = await this.recvSMB();
    if (s.isValidAnswer(constants.SMB_COMMAND_TRANSACTION)) {
      const dataArr = s.get('Data') as SMBCommand[];
      const transResponse = dataArr[0]!;
      const transParameters = new SMBTransactionResponse_Parameters(
        transResponse.get('Parameters') as Buffer,
      );
      const totalDataCount = transParameters.get('TotalDataCount') as number;
      const d = transResponse.get('Data') as Buffer;
      return d.subarray(d.length - totalDataCount);
    }
    return null;
  }

  async waitNamedPipe(tid: number, pipe: string, timeout = 5, noAnswer = 0): Promise<number> {
    const smb = new NewSMBPacket();
    smb.set('Tid', tid);
    const transCommand = new SMBCommand(constants.SMB_COMMAND_TRANSACTION);
    transCommand.set('Parameters', new SMBTransaction_Parameters());
    transCommand.set('Data', new SMBTransaction_Data());
    const setup = Buffer.from([0x53, 0x00, 0x00, 0x00]);
    let name = `\\PIPE${pipe}\x00`;
    if (this._flags2 & F) {
      const startOfName = 32 + 3 + 28 + setup.length;
      const startPad = 2 - (startOfName % 2);
      name = '\x00'.repeat(startPad) + Buffer.from(name, 'latin1').toString('utf-16le');
      const endOfName = startOfName + Buffer.from(name, 'latin1').length;
      const padLen = 4 - (endOfName % 4);
      name += '\x00'.repeat(padLen);
    } else {
      name = Buffer.from(name, 'utf-8').toString('latin1');
    }
    const params = transCommand.get('Parameters') as SMBTransaction_Parameters;
    params.set('Setup', setup);
    params.set('TotalParameterCount', 0);
    params.set('TotalDataCount', 0);
    params.set('MaxParameterCount', 0);
    params.set('MaxDataCount', 0);
    params.set('Timeout', timeout * 1000);
    params.set('ParameterCount', 0);
    params.set('ParameterOffset', 32 + 3 + 28 + setup.length + name.length);
    params.set('DataCount', 0);
    params.set('DataOffset', 0);
    const d = transCommand.get('Data') as SMBTransaction_Data;
    d.set('Name', Buffer.from(name, 'latin1'));
    d.set('Trans_Parameters', Buffer.alloc(0));
    d.set('Trans_Data', Buffer.alloc(0));
    if (noAnswer) params.set('Flags', constants.TRANS_NO_RESPONSE);
    smb.addCommand(transCommand);
    await this.sendSMB(smb);
    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_TRANSACTION)) return 1;
    return 0;
  }

  async ntCreateAndX(
    tid: number,
    filename: string,
    smbPacket?: NewSMBPacket,
    cmd?: SMBCommand,
    shareAccessMode = constants.FILE_SHARE_READ | constants.FILE_SHARE_WRITE,
    disposition = constants.FILE_OPEN,
    accessMask = constants.READ_CONTROL |
      constants.FILE_WRITE_ATTRIBUTES |
      constants.FILE_READ_ATTRIBUTES |
      constants.FILE_WRITE_EA |
      constants.FILE_READ_EA |
      constants.FILE_APPEND_DATA |
      constants.FILE_WRITE_DATA,
  ): Promise<number> {
    filename = filename.replace('/', '\\');
    const filenameBuf = this._flags2 & F ? Buffer.from(filename, 'utf-16le') : filename;

    const smb = smbPacket ?? new NewSMBPacket();
    if (!smbPacket) smb.set('Tid', tid);

    let ntCreate: SMBCommand;
    if (!cmd) {
      ntCreate = new SMBCommand(constants.SMB_COMMAND_NT_CREATE_ANDX);
      ntCreate.set('Parameters', new SMBNtCreateAndX_Parameters());
      ntCreate.set('Data', new SMBNtCreateAndX_Data(this._flags2));
      const params = ntCreate.get('Parameters') as SMBNtCreateAndX_Parameters;
      params.set(
        'FileNameLength',
        typeof filenameBuf === 'string' ? filenameBuf.length : filenameBuf.length,
      );
      params.set('CreateFlags', 0x16);
      params.set('AccessMask', accessMask);
      params.set('CreateOptions', 0x40);
      params.set('ShareAccess', shareAccessMode);
      params.set('Disposition', disposition);
      const d = ntCreate.get('Data') as SMBNtCreateAndX_Data;
      d.set('FileName', filenameBuf);
      if (this._flags2 & F) d.set('Pad', 0x0);
      ntCreate.set('Data', d.getData());
    } else {
      ntCreate = cmd;
    }

    smb.addCommand(ntCreate);
    await this.sendSMB(smb);

    while (true) {
      const resp = await this.recvSMB();
      if (resp.isValidAnswer(constants.SMB_COMMAND_NT_CREATE_ANDX)) {
        const dataArr = resp.get('Data') as SMBCommand[];
        const ntCreateResponse = dataArr[0]!;
        const ntCreateParameters = new SMBNtCreateAndXResponse_Parameters(
          ntCreateResponse.get('Parameters') as Buffer,
        );
        this.fid = ntCreateParameters.get('Fid') as number;
        return this.fid;
      }
    }
  }

  async logoff(): Promise<void> {
    const smb = new NewSMBPacket();
    const logOff = new SMBCommand(constants.SMB_COMMAND_LOGOFF_ANDX);
    logOff.set('Parameters', new SMBLogOffAndX());
    smb.addCommand(logOff);
    await this.sendSMB(smb);
    await this.recvSMB();
    this._uid = 0;
  }

  async echo(text: Buffer | string = '', count = 1): Promise<boolean> {
    const smb = new NewSMBPacket();
    const comEcho = new SMBCommand(constants.SMB_COMMAND_ECHO);
    comEcho.set('Parameters', new SMBEcho_Parameters());
    comEcho.set('Data', new SMBEcho_Data());
    (comEcho.get('Parameters') as SMBEcho_Parameters).set('EchoCount', count);
    (comEcho.get('Data') as SMBEcho_Data).set(
      'Data',
      typeof text === 'string' ? Buffer.from(text, 'latin1') : text,
    );
    smb.addCommand(comEcho);
    await this.sendSMB(smb);
    for (let i = 0; i < count; i++) {
      const resp = await this.recvSMB();
      resp.isValidAnswer(constants.SMB_COMMAND_ECHO);
    }
    return true;
  }

  getUid(): number {
    return this._uid;
  }

  setUid(uid: number): void {
    this._uid = uid;
  }

  getServerDomain(): string {
    return this._serverDomain;
  }

  getServerDnsDomainName(): string {
    return this._serverDnsDomainName;
  }

  getServerDnsHostName(): string {
    return this._serverDnsHostName;
  }

  getServerOS(): string {
    return this._serverOS;
  }

  getServerOSMajor(): number | null {
    return this._serverOSMajor;
  }

  getServerOSMinor(): number | null {
    return this._serverOSMinor;
  }

  getServerOSBuild(): number | null {
    return this._serverOSBuild;
  }

  setServerOS(os: string): void {
    this._serverOS = os;
  }

  getServerLanman(): string {
    return this._serverLanman;
  }

  isLoginRequired(): boolean {
    if (!this._dialectsParameters) return true;
    return (
      ((this._dialectsParameters.get('SecurityMode') as number) & constants.SECURITY_SHARE_MASK) ===
      constants.SECURITY_SHARE_USER
    );
  }

  isSigningRequired(): boolean {
    return this._signatureRequired;
  }

  getNtlmv1Response(key: Buffer): Buffer {
    if (!this._dialectsData) throw new Error('No dialect data');
    const challenge = this._dialectsData.get('Challenge') as Buffer;
    return ntlm.getNtlmv1Response(key, challenge);
  }

  performHostnameValidation(): void {
    if (this._serverName === '') {
      if (!this._validationAllowAbsent) {
        throw new SMB.HostnameValidationException(
          'Hostname was not supplied by target host and absent validation is disallowed',
        );
      }
      return;
    }
    if (
      this._serverName.toLowerCase() !== this._acceptedHostname.toLowerCase() &&
      this._serverDnsHostName.toLowerCase() !== this._acceptedHostname.toLowerCase()
    ) {
      throw new SMB.HostnameValidationException(
        `Supplied hostname ${this._acceptedHostname.toLowerCase()} does not match reported hostnames ${this._serverName.toLowerCase()} or ${this._serverDnsHostName.toLowerCase()}`,
      );
    }
  }

  getCredentials(): Credentials {
    return {
      user: this._userName,
      password: this._password,
      domain: this._domain,
      lmhash: this._lmhash,
      nthash: this._nthash,
      aesKey: this._aesKey,
      tgt: this._TGT,
      tgs: this._TGS,
    };
  }

  getIOCapabilities(): { MaxReadSize: number; MaxWriteSize: number } {
    let maxSize: number;
    if (
      this._dialectsParameters &&
      (this._dialectsParameters.get('Capabilities') as number) & constants.CAP_LARGE_READX &&
      !this._signatureEnabled
    ) {
      maxSize = 65000;
    } else {
      maxSize = (this._dialectsParameters?.get('MaxBufferSize') as number) ?? 65535;
    }
    return { MaxReadSize: maxSize, MaxWriteSize: maxSize };
  }

  async loginExtended(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    useNtlmv2 = true,
  ): Promise<number> {
    const flags2 = this._flags2;
    if (flags2 & F) {
      this._flags2 = flags2 & ~F;
    }

    const smb = new NewSMBPacket();
    if (this._signatureRequired) {
      smb.set('Flags2', (smb.get('Flags2') as number) | constants.FLAGS2_SMB_SECURITY_SIGNATURE);
    }

    const sessionSetup = new SMBCommand(constants.SMB_COMMAND_SESSION_SETUP);
    sessionSetup.set('Parameters', new SMBSessionSetupAndX_Extended_Parameters());
    sessionSetup.set('Data', new SMBSessionSetupAndX_Extended_Data(this._flags2));
    const params = sessionSetup.get('Parameters') as SMBSessionSetupAndX_Extended_Parameters;
    params.set('MaxBufferSize', 61440);
    params.set('MaxMpxCount', 2);
    params.set('VcNumber', 1);
    params.set('SessionKey', 0);
    params.set(
      'Capabilities',
      constants.CAP_EXTENDED_SECURITY |
        constants.CAP_USE_NT_ERRORS |
        constants.CAP_UNICODE |
        constants.CAP_LARGE_READX |
        constants.CAP_LARGE_WRITEX,
    );

    const blob = new SPNEGO_NegTokenInit();
    blob.mechTypeOids = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!];
    const auth = ntlm.getNTLMSSPType1(
      this.getClientName(),
      domain,
      this._signatureRequired,
      useNtlmv2,
    );
    blob.fields.MechToken = auth.getData();

    params.set('SecurityBlobLength', blob.getData().length);
    const d = sessionSetup.get('Data') as SMBSessionSetupAndX_Extended_Data;
    d.set('SecurityBlob', blob.getData());
    d.set('NativeOS', 'Unix');
    d.set('NativeLanMan', 'Samba');
    sessionSetup.set('Data', d.getData());

    smb.addCommand(sessionSetup);
    await this.sendSMB(smb);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_SESSION_SETUP)) {
      this._uid = resp.get('Uid') as number;
      const dataArr = resp.get('Data') as SMBCommand[];
      const sessionResponse = dataArr[0]!;
      const sessionParameters = new SMBSessionSetupAndX_Extended_Response_Parameters(
        sessionResponse.get('Parameters') as Buffer,
      );
      const sessionData = new SMBSessionSetupAndX_Extended_Response_Data(
        resp.get('Flags2') as number,
      );
      sessionData.set('SecurityBlobLength', sessionParameters.get('SecurityBlobLength') as number);
      try {
        sessionData.fromString(sessionResponse.get('Data') as Buffer);
      } catch {
        throw new constants.SessionError(
          'Authentication failed: invalid or truncated server response',
          0x006d,
          0xc000,
        );
      }

      const respToken = new SPNEGO_NegTokenResp(sessionData.get('SecurityBlob') as Buffer);
      const ntlmChallenge = new ntlm.NTLMAuthChallenge(respToken.fields.ResponseToken!);

      const tiLen = ntlmChallenge.get('TargetInfoFields_len') as number;
      if (tiLen > 0) {
        const avPairs = new ntlm.AV_PAIRS(
          (ntlmChallenge.get('TargetInfoFields') as Buffer).subarray(0, tiLen),
        );
        const hostname = avPairs.get(ntlm.NTLMSSP_AV_HOSTNAME);
        if (hostname) {
          try {
            this._serverName = hostname[1].toString('utf-16le');
          } catch {
            // silently discard
          }
        }
        const domainName = avPairs.get(ntlm.NTLMSSP_AV_DOMAINNAME);
        if (domainName) {
          try {
            if (this._serverName !== domainName[1].toString('utf-16le')) {
              this._serverDomain = domainName[1].toString('utf-16le');
            }
          } catch {
            // silently discard
          }
        }
        const dnsDomain = avPairs.get(ntlm.NTLMSSP_AV_DNS_DOMAINNAME);
        if (dnsDomain) {
          try {
            this._serverDnsDomainName = dnsDomain[1].toString('utf-16le');
          } catch {
            // silently discard
          }
        }
        const dnsHost = avPairs.get(ntlm.NTLMSSP_AV_DNS_HOSTNAME);
        if (dnsHost) {
          try {
            this._serverDnsHostName = dnsHost[1].toString('utf-16le');
          } catch {
            // silently discard
          }
        }
      }

      if (this._strictHostnameValidation) {
        this.performHostnameValidation();
      }

      if (ntlmChallenge.has('Version')) {
        const version = ntlmChallenge.get('Version') as Buffer;
        if (version && version.length >= 4) {
          this._serverOSMajor = version[0]!;
          this._serverOSMinor = version[1]!;
          this._serverOSBuild = version.readUInt16LE(2);
        }
      }

      const [type3, exportedSessionKey] = ntlm.getNTLMSSPType3(
        auth,
        respToken.fields.ResponseToken!,
        user,
        password,
        domain,
        lmhash,
        nthash,
        useNtlmv2,
      );

      if (exportedSessionKey) {
        this._signingSessionKey = exportedSessionKey;
      }

      const smb2 = new NewSMBPacket();
      if (this._signatureRequired) {
        smb2.set(
          'Flags2',
          (smb2.get('Flags2') as number) | constants.FLAGS2_SMB_SECURITY_SIGNATURE,
        );
      }

      const respToken2 = new SPNEGO_NegTokenResp();
      respToken2.fields.ResponseToken = type3.getData();

      params.set('SecurityBlobLength', respToken2.getData().length);
      d.set('SecurityBlob', respToken2.getData());
      sessionSetup.set('Data', d.getData());

      this._serverOS = sessionData.get('NativeOS') as string;
      this._serverLanman = sessionData.get('NativeLanMan') as string;

      smb2.addCommand(sessionSetup);
      await this.sendSMB(smb2);

      const resp2 = await this.recvSMB();
      this._uid = 0;
      if (resp2.isValidAnswer(constants.SMB_COMMAND_SESSION_SETUP)) {
        this._uid = resp2.get('Uid') as number;
        const dataArr2 = resp2.get('Data') as SMBCommand[];
        const sessionResponse2 = dataArr2[0]!;
        const sessionParameters2 = new SMBSessionSetupAndXResponse_Parameters(
          sessionResponse2.get('Parameters') as Buffer,
        );
        this._action = sessionParameters2.get('Action') as number;

        if (
          this._dialectsParameters &&
          (this._dialectsParameters.get('SecurityMode') as number) &
            constants.SECURITY_SIGNATURES_REQUIRED
        ) {
          this._signSequenceNumber = 2;
          this._signatureEnabled = true;
        }

        if (flags2 & F) {
          this._flags2 |= F;
        }
        return 1;
      }
      throw new Error('Error: Could not login successfully');
    }
    throw new Error('Error: Could not login successfully');
  }

  async loginStandard(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
  ): Promise<number> {
    const flags2 = this._flags2;
    if (flags2 & F) {
      this._flags2 = flags2 & ~F;
    }

    let pwdAnsi: Buffer | string;
    let pwdUnicode: Buffer | string;

    if (
      this._dialectsParameters &&
      (this._dialectsParameters.get('ChallengeLength') as number) > 0
    ) {
      if (lmhash || nthash) {
        pwdAnsi = this.getNtlmv1Response(
          Buffer.isBuffer(lmhash) ? lmhash : Buffer.from(lmhash as string, 'hex'),
        );
        pwdUnicode = this.getNtlmv1Response(
          Buffer.isBuffer(nthash) ? nthash : Buffer.from(nthash as string, 'hex'),
        );
      } else if (password) {
        const lm = ntlm.computeLmhash(password);
        const nt = ntlm.computeNthash(password);
        pwdAnsi = this.getNtlmv1Response(lm);
        pwdUnicode = this.getNtlmv1Response(nt);
      } else {
        pwdAnsi = '';
        pwdUnicode = '';
      }
    } else {
      pwdAnsi = password;
      pwdUnicode = '';
    }

    const smb = new NewSMBPacket();
    const sessionSetup = new SMBCommand(constants.SMB_COMMAND_SESSION_SETUP);
    sessionSetup.set('Parameters', new SMBSessionSetupAndX_Parameters());
    sessionSetup.set('Data', new SMBSessionSetupAndX_Data(this._flags2));
    const params = sessionSetup.get('Parameters') as SMBSessionSetupAndX_Parameters;
    params.set('MaxBuffer', 61440);
    params.set('MaxMpxCount', 2);
    params.set('VCNumber', process.pid & 0xffff);
    if (this._dialectsParameters) {
      params.set('SessionKey', this._dialectsParameters.get('SessionKey') as number);
    }
    params.set('AnsiPwdLength', typeof pwdAnsi === 'string' ? pwdAnsi.length : pwdAnsi.length);
    params.set(
      'UnicodePwdLength',
      typeof pwdUnicode === 'string' ? pwdUnicode.length : pwdUnicode.length,
    );
    params.set(
      'Capabilities',
      constants.CAP_RAW_MODE |
        constants.CAP_USE_NT_ERRORS |
        constants.CAP_LARGE_READX |
        constants.CAP_LARGE_WRITEX,
    );

    const d = sessionSetup.get('Data') as SMBSessionSetupAndX_Data;
    d.set('AnsiPwd', pwdAnsi);
    d.set('UnicodePwd', pwdUnicode);
    d.set('Account', user);
    d.set('PrimaryDomain', domain);
    d.set('NativeOS', os.platform());
    d.set('NativeLanMan', 'pysmb');
    sessionSetup.set('Data', d.getData());
    smb.addCommand(sessionSetup);
    await this.sendSMB(smb);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_SESSION_SETUP)) {
      this._uid = resp.get('Uid') as number;
      const dataArr = resp.get('Data') as SMBCommand[];
      const sessionResponse = dataArr[0]!;
      const sessionParameters = new SMBSessionSetupAndXResponse_Parameters(
        sessionResponse.get('Parameters') as Buffer,
      );
      const sessionData = new SMBSessionSetupAndXResponse_Data(
        resp.get('Flags2') as number,
        sessionResponse.get('Data') as Buffer,
      );

      this._action = sessionParameters.get('Action') as number;

      if ((this._action & constants.SMB_SETUP_USE_LANMAN_KEY) === 0) {
        this._signingChallengeResponse = Buffer.isBuffer(pwdUnicode)
          ? pwdUnicode
          : Buffer.from(pwdUnicode);
        this._signingSessionKey = ntlm.computeNthash(password);
      } else {
        this._signingChallengeResponse = Buffer.isBuffer(pwdAnsi) ? pwdAnsi : Buffer.from(pwdAnsi);
        this._signingSessionKey = ntlm.computeLmhash(password);
      }

      this._serverOS = sessionData.get('NativeOS') as string;
      this._serverLanman = sessionData.get('NativeLanMan') as string;
      this._serverDomain = sessionData.get('PrimaryDomain') as string;

      if (flags2 & F) {
        this._flags2 |= F;
      }
      return 1;
    }
    throw new Error('Error: Could not login successfully');
  }

  async login(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    ntlmFallback = true,
  ): Promise<void> {
    let lm = lmhash;
    let nt = nthash;
    if (lm || nt) {
      if (Buffer.isBuffer(lm) || (typeof lm === 'string' && lm.length % 2)) lm = `0${lm}`;
      if (Buffer.isBuffer(nt) || (typeof nt === 'string' && nt.length % 2)) nt = `0${nt}`;
      try {
        if (typeof lm === 'string' && !Buffer.isBuffer(lm)) lm = Buffer.from(lm, 'hex');
        if (typeof nt === 'string' && !Buffer.isBuffer(nt)) nt = Buffer.from(nt, 'hex');
      } catch {
        // already converted
      }
    }

    this._userName = user;
    this._password = password;
    this._domain = domain;
    this._lmhash = lm;
    this._nthash = nt;
    this._aesKey = '';
    this._TGT = null;
    this._TGS = null;

    if (
      this._dialectsParameters &&
      (this._dialectsParameters.get('Capabilities') as number) & constants.CAP_EXTENDED_SECURITY
    ) {
      try {
        await this.loginExtended(user, password, domain, lm, nt, true);
      } catch (e) {
        if (ntlmFallback) {
          const lanman = this._serverLanman;
          if (lanman.includes('Windows 2000') || lanman.includes('Samba')) {
            await this.loginExtended(user, password, domain, lm, nt, false);
            this._isNTLMv2 = false;
          } else {
            throw e;
          }
        } else {
          throw e;
        }
      }
    } else if (ntlmFallback) {
      await this.loginStandard(user, password, domain, lm, nt);
      this._isNTLMv2 = false;
    } else {
      throw new constants.SessionError(
        'Cannot authenticate against target, enable ntlm_fallback',
        0,
        0,
      );
    }
  }

  async kerberosLogin(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    aesKey: Buffer | string = '',
    kdcHost = '',
    TGT: KerberosV5.TGTResult | null = null,
    TGS: KerberosV5.TGSResult | null = null,
  ): Promise<number> {
    // Login feature does not support unicode -- disable it if enabled
    const flags2 = this._flags2;
    if (flags2 & F) {
      this._flags2 = flags2 & ~F;
    }

    // Normalize hashes from hex strings to Buffers
    let lm: Buffer | string = lmhash;
    let nt: Buffer | string = nthash;
    if (lm !== '' || nt !== '') {
      if (typeof lm === 'string' && lm.length % 2) lm = `0${lm}`;
      if (typeof nt === 'string' && nt.length % 2) nt = `0${nt}`;
      try {
        if (typeof lm === 'string') lm = Buffer.from(lm, 'hex');
        if (typeof nt === 'string') nt = Buffer.from(nt, 'hex');
      } catch {
        // already converted
      }
    }

    // Store credentials
    this._userName = user;
    this._password = password;
    this._domain = domain;
    this._lmhash = lm;
    this._nthash = nt;
    this._aesKey = aesKey;
    this._kdc = kdcHost;
    this._TGT = TGT;
    this._TGS = TGS;
    this._doKerberos = true;

    const userName = new KrbTypes.Principal(
      user,
      null,
      KrbConstants.PrincipalNameType.NT_PRINCIPAL,
    );

    // Obtain TGS -- either directly provided or via TGT (which itself may need fetching)
    let tgsBytes: Buffer;
    let cipher: KrbCrypto.EnctypeProfile;
    let sessionKey: KrbCrypto.Key;

    if (TGS !== null) {
      tgsBytes = TGS.tgs;
      cipher = TGS.cipher;
      sessionKey = TGS.sessionKey;
    } else {
      // We need a TGT to obtain the TGS
      let tgtBuf: Buffer;
      let tgtCipher: KrbCrypto.EnctypeProfile;
      let tgtSessionKey: KrbCrypto.Key;

      if (TGT !== null) {
        tgtBuf = TGT.tgt;
        tgtCipher = TGT.cipher;
        tgtSessionKey = TGT.sessionKey;
      } else {
        const tgtResult = await KerberosV5.getKerberosTGT(
          userName,
          password,
          domain,
          lm,
          nt,
          aesKey,
          kdcHost || null,
        );
        tgtBuf = tgtResult.tgt;
        tgtCipher = tgtResult.cipher;
        tgtSessionKey = tgtResult.sessionKey;
      }

      // Request TGS for cifs/<remote_name>
      const serverName = new KrbTypes.Principal(
        `cifs/${this._remoteName}`,
        null,
        KrbConstants.PrincipalNameType.NT_SRV_INST,
      );
      const tgsResult = await KerberosV5.getKerberosTGS(
        serverName,
        domain,
        kdcHost || null,
        tgtBuf,
        tgtCipher,
        tgtSessionKey,
      );
      tgsBytes = tgsResult.tgs;
      cipher = tgsResult.cipher;
      sessionKey = tgsResult.sessionKey;
    }

    // Build SMB session setup packet
    const smb = new NewSMBPacket();

    // Enable signature if required
    if (this._signatureRequired) {
      smb.set('Flags2', (smb.get('Flags2') as number) | constants.FLAGS2_SMB_SECURITY_SIGNATURE);
    }

    const sessionSetup = new SMBCommand(constants.SMB_COMMAND_SESSION_SETUP);
    sessionSetup.set('Parameters', new SMBSessionSetupAndX_Extended_Parameters());
    sessionSetup.set('Data', new SMBSessionSetupAndX_Extended_Data(this._flags2));
    const params = sessionSetup.get('Parameters') as SMBSessionSetupAndX_Extended_Parameters;
    params.set('MaxBufferSize', 61440);
    params.set('MaxMpxCount', 2);
    params.set('VcNumber', 1);
    params.set('SessionKey', 0);
    params.set(
      'Capabilities',
      constants.CAP_EXTENDED_SECURITY |
        constants.CAP_USE_NT_ERRORS |
        constants.CAP_UNICODE |
        constants.CAP_LARGE_READX |
        constants.CAP_LARGE_WRITEX,
    );

    // Build SPNEGO NegTokenInit with Kerberos mech type
    const blob = new SPNEGO_NegTokenInit();
    blob.mechTypeOids = [TypesMech['MS KRB5 - Microsoft Kerberos 5']!];

    // Extract raw ticket from the TGS response
    const ticketNode = KrbAsn1.Ticket();
    ticketNode._rawData = extractRawTicketFromKdcRep(tgsBytes);

    // Build AP-REQ
    const apReq = KrbAsn1.AP_REQ();
    apReq.set('pvno', 5);
    apReq.set('msg-type', KrbConstants.ApplicationTagNumbers.AP_REQ);
    KrbAsn1.seqSetFlags(apReq, 'ap-options', []);
    apReq.set('ticket', ticketNode);

    // Build Authenticator
    const authenticator = KrbAsn1.Authenticator();
    authenticator.set('authenticator-vno', 5);
    authenticator.set('crealm', domain);
    authenticator.set('cname', KrbAsn1.principalToAsn1(userName));

    const now = new Date();
    authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
    authenticator.set('ctime', now);

    const encodedAuthenticator = authenticator.encode();

    // Key Usage 11: AP-REQ Authenticator encrypted with the application session key
    const encryptedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, null);

    const apReqEncPart = KrbAsn1.EncryptedData();
    apReqEncPart.set('etype', cipher.enctype);
    apReqEncPart.set('cipher', encryptedAuthenticator);
    apReq.set('authenticator', apReqEncPart);

    const apReqEncoded = apReq.encode();

    // Build MechToken: GSSAPI wrapper around the AP-REQ
    blob.fields.MechToken = Buffer.concat([
      Buffer.from([ASN1_AID]),
      asn1encode(
        Buffer.concat([
          Buffer.from([ASN1_OID]),
          asn1encode(TypesMech['KRB5 - Kerberos 5']!),
          KrbGSSAPI.KRB5_AP_REQ,
          apReqEncoded,
        ]),
      ),
    ]);

    params.set('SecurityBlobLength', blob.getData().length);
    const d = sessionSetup.get('Data') as SMBSessionSetupAndX_Extended_Data;
    d.set('SecurityBlob', blob.getData());
    // Fake data to avoid fingerprinting
    d.set('NativeOS', 'Unix');
    d.set('NativeLanMan', 'Samba');
    sessionSetup.set('Data', d.getData());

    smb.addCommand(sessionSetup);
    await this.sendSMB(smb);

    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_SESSION_SETUP)) {
      this._uid = resp.get('Uid') as number;

      const dataArr = resp.get('Data') as SMBCommand[];
      const sessionResponse = dataArr[0]!;
      const sessionParameters = new SMBSessionSetupAndX_Extended_Response_Parameters(
        sessionResponse.get('Parameters') as Buffer,
      );
      const sessionData = new SMBSessionSetupAndX_Extended_Response_Data(
        resp.get('Flags2') as number,
      );
      sessionData.set('SecurityBlobLength', sessionParameters.get('SecurityBlobLength') as number);
      sessionData.fromString(sessionResponse.get('Data') as Buffer);

      this._action = sessionParameters.get('Action') as number;

      // Enable signing if the server requires it
      if (
        this._dialectsParameters &&
        (this._dialectsParameters.get('SecurityMode') as number) &
          constants.SECURITY_SIGNATURES_REQUIRED
      ) {
        this._signingSessionKey = sessionKey.contents;
        this._signSequenceNumber = 2;
        this._signatureEnabled = true;
      }

      // Restore unicode flag if needed
      if (flags2 & F) {
        this._flags2 |= F;
      }

      return 1;
    }
    throw new Error('Error: Could not login successfully');
  }

  async writeFile(treeId: number, fileId: number, data: Buffer, offset = 0): Promise<number> {
    let maxBufSize: number;
    if (
      this._dialectsParameters &&
      (this._dialectsParameters.get('Capabilities') as number) & constants.CAP_LARGE_WRITEX &&
      !this._signatureEnabled
    ) {
      maxBufSize = 65000;
    } else {
      maxBufSize = ((this._dialectsParameters?.get('MaxBufferSize') as number) ?? 65535) & ~0x3ff;
    }

    let writeOffset = offset;
    let remaining = data;
    while (remaining.length > 0) {
      const writeData = remaining.subarray(0, maxBufSize);
      remaining = remaining.subarray(maxBufSize);
      const smb = await this.writeAndX(treeId, fileId, writeData, writeOffset);
      if (smb) {
        const dataArr = smb.get('Data') as SMBCommand[];
        const writeResponse = dataArr[0]!;
        const writeResponseParameters = new SMBWriteAndXResponse_Parameters(
          writeResponse.get('Parameters') as Buffer,
        );
        writeOffset += writeResponseParameters.get('Count') as number;
      }
    }
    return writeOffset;
  }

  getSocket(): import('node:net').Socket | null {
    return this._sess?.get_socket() ?? null;
  }

  async sendNtTrans(
    tid: number,
    subcommand: number,
    maxParamCount: number,
    setup: Buffer | string = '',
    param: Buffer | string = '',
    data: Buffer | string = '',
  ): Promise<void> {
    const smbPacket = new NewSMBPacket();
    smbPacket.set('Tid', tid);
    const setupBytes = typeof setup === 'string' ? Buffer.from(setup, 'latin1') : setup;
    const paramBytes = typeof param === 'string' ? Buffer.from(param, 'latin1') : param;
    const dataBytes = typeof data === 'string' ? Buffer.from(data, 'latin1') : data;

    const transCommand = new SMBCommand(constants.SMB_COMMAND_NT_TRANSACT);
    transCommand.set('Parameters', new SMBNTTransaction_Parameters());
    const params = transCommand.get('Parameters') as SMBNTTransaction_Parameters;
    if (this._dialectsParameters) {
      params.set('MaxDataCount', this._dialectsParameters.get('MaxBufferSize') as number);
    }
    params.set('Setup', setupBytes);
    params.set('Function', subcommand);
    params.set('TotalParameterCount', paramBytes.length);
    params.set('TotalDataCount', dataBytes.length);
    params.set('MaxParameterCount', maxParamCount);
    params.set('MaxSetupCount', 0);

    const transData = new SMBNTTransaction_Data();
    let offset = 32 + 3 + 38 + setupBytes.length;
    transData.set('Pad1', Buffer.alloc(0));
    if (offset % 4 !== 0) {
      const padLen = 4 - (offset % 4);
      transData.set('Pad1', Buffer.alloc(padLen));
      offset += padLen;
    }
    if (paramBytes.length > 0) {
      params.set('ParameterOffset', offset);
    } else {
      params.set('ParameterOffset', 0);
    }
    offset += paramBytes.length;
    transData.set('Pad2', Buffer.alloc(0));
    if (offset % 4 !== 0) {
      const pad2Len = 4 - (offset % 4);
      transData.set('Pad2', Buffer.alloc(pad2Len));
      offset += pad2Len;
    }
    if (dataBytes.length > 0) {
      params.set('DataOffset', offset);
    } else {
      params.set('DataOffset', 0);
    }
    params.set('DataCount', dataBytes.length);
    params.set('ParameterCount', paramBytes.length);
    transData.set('NT_Trans_Parameters', paramBytes);
    transData.set('NT_Trans_Data', dataBytes);
    transCommand.set('Data', transData.getData());
    smbPacket.addCommand(transCommand);
    await this.sendSMB(smbPacket);
  }

  async querySecInfo(tid: number, fid: number, additionalInformation = 7): Promise<Buffer> {
    const param = Buffer.alloc(8);
    param.writeUInt16LE(fid, 0);
    param.writeUInt16LE(0, 2);
    param.writeUInt32LE(additionalInformation, 4);
    await this.sendNtTrans(tid, 0x0006, 4, '', param, '');
    const resp = await this.recvSMB();
    if (resp.isValidAnswer(constants.SMB_COMMAND_NT_TRANSACT)) {
      const dataArr = resp.get('Data') as SMBCommand[];
      const ntTransResponse = dataArr[0]!;
      const ntTransParameters = new SMBNTTransactionResponse_Parameters(
        ntTransResponse.get('Parameters') as Buffer,
      );
      const totalDataCount = ntTransParameters.get('TotalDataCount') as number;
      const d = ntTransResponse.get('Data') as Buffer;
      return d.subarray(d.length - totalDataCount);
    }
    throw new Error('query_sec_info failed');
  }

  async mkdir(service: string, pathName: string, password?: string | null): Promise<number> {
    pathName = pathName.replace('/', '\\');
    const tid = await this.treeConnectAndX(`\\\\${this._remoteName}\\${service}`, password ?? null);
    try {
      const pathBuf = this._flags2 & F ? Buffer.from(pathName, 'utf-16le') : pathName;
      const smb = new NewSMBPacket();
      smb.set('Tid', tid);
      smb.set('Mid', 0);
      const createDir = new SMBCommand(constants.SMB_COMMAND_CREATE_DIRECTORY);
      const data = new SMBCreateDirectory_Data(this._flags2);
      data.set('DirectoryName', pathBuf);
      createDir.set('Data', data.getData());
      smb.addCommand(createDir);
      await this.sendSMB(smb);
      const resp = await this.recvSMB();
      if (resp.isValidAnswer(constants.SMB_COMMAND_CREATE_DIRECTORY)) return 1;
      return 0;
    } finally {
      await this.disconnectTree(tid);
    }
  }

  async rmdir(service: string, pathName: string, password?: string | null): Promise<void> {
    pathName = pathName.replace('/', '\\');
    const tid = await this.treeConnectAndX(`\\\\${this._remoteName}\\${service}`, password ?? null);
    try {
      const pathBuf = this._flags2 & F ? Buffer.from(pathName, 'utf-16le') : pathName;
      const smb = new NewSMBPacket();
      smb.set('Tid', tid);
      const delDir = new SMBCommand(constants.SMB_COMMAND_DELETE_DIRECTORY);
      const data = new SMBDeleteDirectory_Data(this._flags2);
      data.set('DirectoryName', pathBuf);
      delDir.set('Data', data.getData());
      smb.addCommand(delDir);
      await this.sendSMB(smb);
      const resp = await this.recvSMB();
      resp.isValidAnswer(constants.SMB_COMMAND_DELETE_DIRECTORY);
    } finally {
      await this.disconnectTree(tid);
    }
  }

  async remove(service: string, pathName: string, password?: string | null): Promise<void> {
    pathName = pathName.replace('/', '\\');
    const tid = await this.treeConnectAndX(`\\\\${this._remoteName}\\${service}`, password ?? null);
    try {
      const smb = new NewSMBPacket();
      smb.set('Tid', tid);
      smb.set('Mid', 0);
      const cmd = new SMBCommand(constants.SMB_COMMAND_DELETE);
      const params = new SMBDelete_Parameters();
      params.set(
        'SearchAttributes',
        constants.ATTR_HIDDEN | constants.ATTR_SYSTEM | constants.ATTR_ARCHIVE,
      );
      cmd.set('Parameters', params);
      const data = new SMBDelete_Data(this._flags2);
      const pathBuf =
        this._flags2 & F
          ? Buffer.from(pathName + '\x00', 'utf-16le')
          : Buffer.from(pathName + '\x00', 'latin1');
      data.set('FileName', pathBuf);
      cmd.set('Data', data.getData());
      smb.addCommand(cmd);
      await this.sendSMB(smb);
      const resp = await this.recvSMB();
      resp.isValidAnswer(constants.SMB_COMMAND_DELETE);
    } finally {
      await this.disconnectTree(tid);
    }
  }

  async rename(
    service: string,
    oldPath: string,
    newPath: string,
    password?: string | null,
  ): Promise<number> {
    oldPath = oldPath.replace('/', '\\');
    newPath = newPath.replace('/', '\\');
    const tid = await this.treeConnectAndX(`\\\\${this._remoteName}\\${service}`, password ?? null);
    try {
      const smb = new NewSMBPacket();
      smb.set('Tid', tid);
      smb.set('Mid', 0);
      const renameCmd = new SMBCommand(constants.SMB_COMMAND_RENAME);
      const params = new SMBRename_Parameters();
      params.set(
        'SearchAttributes',
        constants.ATTR_SYSTEM | constants.ATTR_HIDDEN | constants.ATTR_DIRECTORY,
      );
      renameCmd.set('Parameters', params);
      const data = new SMBRename_Data(this._flags2);
      const oldBuf = this._flags2 & F ? Buffer.from(oldPath, 'utf-16le') : oldPath;
      const newBuf = this._flags2 & F ? Buffer.from(newPath, 'utf-16le') : newPath;
      data.set('OldFileName', oldBuf);
      data.set('NewFileName', newBuf);
      renameCmd.set('Data', data.getData());
      smb.addCommand(renameCmd);
      await this.sendSMB(smb);
      const resp = await this.recvSMB();
      if (resp.isValidAnswer(constants.SMB_COMMAND_RENAME)) return 1;
      return 0;
    } finally {
      await this.disconnectTree(tid);
    }
  }

  async listPath(_service: string, _path: string, _password?: string | null): Promise<unknown[]> {
    throw new Error(
      'listPath not yet fully implemented for SMB1 (requires SMBFindFirst2 transaction)',
    );
  }
}
