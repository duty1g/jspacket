import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import os from 'node:os';
import * as crypto from '@impacket/crypto';
import * as nmb from '@impacket/nmb';
import * as ntlmMod from '@impacket/ntlm';
import { SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech } from '@impacket/spnego';
import * as krb5 from '@impacket/krb5';
import { type FieldDescriptor, Structure } from '@impacket/structure';
import * as constants from './constants.js';
import {
  SMB2Cancel,
  SMB2Close,
  SMB2Create,
  SMB2Create_Response,
  SMB2Echo,
  SMB2EncryptionCapabilities,
  SMB2Flush,
  SMB2Ioctl,
  SMB2Ioctl_Response,
  SMB2Lock,
  SMB2Lock_Response,
  SMB2Logoff,
  SMB2Negotiate,
  SMB2NegotiateContext,
  SMB2Negotiate_Response,
  SMB2Packet,
  SMB2PreAuthIntegrityCapabilities,
  SMB2QueryDirectory,
  SMB2QueryDirectory_Response,
  SMB2QueryInfo,
  SMB2QueryInfo_Response,
  SMB2Read,
  SMB2Read_Response,
  SMB2SessionSetup,
  SMB2SessionSetup_Response,
  SMB2SetInfo,
  SMB2SetInfo_Response,
  SMB2TreeConnect,
  SMB2TreeConnect_Response,
  SMB2TreeDisconnect,
  SMB2Write,
  SMB2Write_Response,
  SMB2_FILEID,
  SMB2_LOCK_ELEMENT,
  SMB2_TRANSFORM_HEADER,
  SMB3Packet,
  SMB311ContextData,
  type SMBPacketBase,
} from './structures.js';

const STATUS_PENDING = 0x00000103;
const STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;
const STATUS_INVALID_PARAMETER = 0xc000000d;

export class SessionError extends Error {
  error: number;
  packet: unknown;

  constructor(error = 0, packet: unknown = null) {
    super(`SessionError: 0x${error.toString(16)}`);
    this.error = error;
    this.packet = packet;
  }

  getErrorCode(): number {
    return this.error;
  }
}

export interface SMB3Options {
  myName?: string | null;
  hostType?: number;
  sessPort?: number;
  timeout?: number;
  udp?: boolean;
  preferredDialect?: number | null;
  session?: nmb.NetBIOSTCPSession | null;
  negSessionResponse?: Buffer | null;
}

interface Connection {
  SequenceWindow: number;
  /** Responses received out of order, keyed by MessageID, awaiting their recvSMB(packetID) caller. */
  OutstandingResponses: Map<bigint, SMBPacketBase>;
  GSSNegotiateToken: Buffer;
  MaxTransactSize: number;
  MaxReadSize: number;
  MaxWriteSize: number;
  ServerGuid: Buffer;
  RequireSigning: boolean;
  ServerName: string;
  ServerIP: string;
  ClientName: string;
  Dialect: number;
  SupportsFileLeasing: boolean;
  SupportsMultiCredit: boolean;
  SupportsDirectoryLeasing: boolean;
  SupportsMultiChannel: boolean;
  SupportsPersistentHandles: boolean;
  SupportsEncryption: boolean;
  ClientCapabilities: number;
  ServerCapabilities: number;
  ClientSecurityMode: number;
  ServerSecurityMode: number;
  Capabilities: number;
  PreauthIntegrityHashId: number;
  PreauthIntegrityHashValue: Buffer;
  CipherId: number;
}

interface Session {
  SessionID: bigint;
  TreeConnectTable: Record<number | string, TreeEntry>;
  SessionKey: Buffer;
  SigningRequired: boolean;
  SigningKey: Buffer;
  ApplicationKey: Buffer;
  EncryptionKey: Buffer;
  DecryptionKey: Buffer;
  SessionFlags: number;
  ServerName: string;
  ServerDomain: string;
  ServerDNSDomainName: string;
  ServerDNSHostName: string;
  ServerOS: string;
  ServerOSMajor: number | null;
  ServerOSMinor: number | null;
  ServerOSBuild: number | null;
  SigningActivated: boolean;
  PreauthIntegrityHashValue: Buffer;
  CalculatePreAuthHash: boolean;
  EncryptData: boolean;
  OpenTable: Record<string, OpenFile>;
}

interface TreeEntry {
  ShareName: string;
  TreeConnectId: number;
  Session: bigint;
  NumberOfUses: number;
  IsDfsShare: boolean;
  IsCAShare: boolean;
  IsScaleoutShare: boolean;
  EncryptData: boolean;
}

interface OpenFile {
  FileID: Buffer;
  TreeConnect: number;
  Oplocklevel: number;
  Durable: boolean;
  ResilientHandle: boolean;
  LastDisconnectTime: number;
  FileName: string;
}

function newTreeEntry(): TreeEntry {
  return {
    ShareName: '',
    TreeConnectId: 0,
    Session: 0n,
    NumberOfUses: 0,
    IsDfsShare: false,
    IsCAShare: false,
    IsScaleoutShare: false,
    EncryptData: false,
  };
}

function newOpenFile(): OpenFile {
  return {
    FileID: Buffer.alloc(0),
    TreeConnect: 0,
    Oplocklevel: 0,
    Durable: false,
    ResilientHandle: false,
    LastDisconnectTime: 0,
    FileName: '',
  };
}

export class SMB3 {
  static HostnameValidationException = class extends Error {};

  RequireMessageSigning = false;
  ClientGuid: Buffer;
  MaxDialect: number[] = [];
  RequireSecureNegotiate = false;

  _Connection: Connection;
  _Session: Session;
  SMB_PACKET: typeof SMB2Packet = SMB2Packet;
  _timeout: number;
  _NetBIOSSession: nmb.NetBIOSTCPSession | null = null;
  _preferredDialect: number | null = null;
  _doKerberos = false;

  private _strictHostnameValidation = false;
  private _validationAllowAbsent = true;
  private _acceptedHostname = '';

  private _userName = '';
  private _password = '';
  private _domain = '';
  private _lmhash: Buffer | string = '';
  private _nthash: Buffer | string = '';
  private _kdc = '';
  private _aesKey: Buffer | string = '';
  private _TGT: unknown = null;
  private _TGS: unknown = null;

  constructor(remoteName: string, remoteHost: string, options: SMB3Options = {}) {
    const {
      myName = null,
      hostType = nmb.TYPE_SERVER,
      sessPort = 445,
      timeout = 60,
      udp = false,
      preferredDialect = null,
      session = null,
    } = options;

    this.ClientGuid = nodeRandomBytes(16);
    this._timeout = timeout;
    this._preferredDialect = preferredDialect;

    this._Connection = {
      SequenceWindow: 0,
      OutstandingResponses: new Map<bigint, SMBPacketBase>(),
      GSSNegotiateToken: Buffer.alloc(0),
      MaxTransactSize: 0,
      MaxReadSize: 0,
      MaxWriteSize: 0,
      ServerGuid: Buffer.alloc(0),
      RequireSigning: false,
      ServerName: '',
      ServerIP: remoteHost,
      ClientName: '',
      Dialect: 0,
      SupportsFileLeasing: false,
      SupportsMultiCredit: false,
      SupportsDirectoryLeasing: false,
      SupportsMultiChannel: false,
      SupportsPersistentHandles: false,
      SupportsEncryption: false,
      ClientCapabilities: 0,
      ServerCapabilities: 0,
      ClientSecurityMode: 0,
      ServerSecurityMode: 0,
      Capabilities: 0,
      PreauthIntegrityHashId: 0,
      PreauthIntegrityHashValue: Buffer.alloc(64, 0),
      CipherId: 0,
    };

    this._Session = {
      SessionID: 0n,
      TreeConnectTable: {},
      SessionKey: Buffer.alloc(0),
      SigningRequired: false,
      SigningKey: Buffer.alloc(0),
      ApplicationKey: Buffer.alloc(0),
      EncryptionKey: Buffer.alloc(0),
      DecryptionKey: Buffer.alloc(0),
      SessionFlags: 0,
      ServerName: '',
      ServerDomain: '',
      ServerDNSDomainName: '',
      ServerDNSHostName: '',
      ServerOS: '',
      ServerOSMajor: null,
      ServerOSMinor: null,
      ServerOSBuild: null,
      SigningActivated: false,
      PreauthIntegrityHashValue: Buffer.alloc(64, 0),
      CalculatePreAuthHash: true,
      EncryptData: true,
      OpenTable: {},
    };

    if (sessPort === 445 && remoteName === '*SMBSERVER') {
      this._Connection.ServerName = remoteHost;
    } else {
      this._Connection.ServerName = remoteName;
    }

    if (myName === null) {
      this._Connection.ClientName = '';
    } else {
      this._Connection.ClientName = myName;
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
      this._NetBIOSSession = new nmb.NetBIOSTCPSession(
        localName,
        this._Connection.ServerName,
        remoteHost,
        hostType,
        sessPort,
        this._timeout,
      );
    } else {
      this._NetBIOSSession = session;
      this._Connection.SequenceWindow += 1;
    }
  }

  async negotiateSession(
    preferredDialect?: number | null,
    negSessionResponse?: Buffer | null,
  ): Promise<void> {
    this._Connection.ClientSecurityMode = constants.SMB2_NEGOTIATE_SIGNING_ENABLED;
    if (this.RequireMessageSigning) {
      this._Connection.ClientSecurityMode |= constants.SMB2_NEGOTIATE_SIGNING_REQUIRED;
    }
    this._Connection.Capabilities = constants.SMB2_GLOBAL_CAP_ENCRYPTION;
    let currentDialect = constants.SMB2_DIALECT_WILDCARD;

    let negResp: SMB2Negotiate_Response | null = null;

    if (negSessionResponse) {
      const negPacket = new SMB2Packet(negSessionResponse);
      negResp = new SMB2Negotiate_Response(negPacket.get('Data') as Buffer);
      currentDialect = negResp.get('DialectRevision') as number;
    }

    if (currentDialect === constants.SMB2_DIALECT_WILDCARD) {
      const packet = new this.SMB_PACKET();
      packet.set('Command', constants.SMB2_NEGOTIATE);
      const negSession = new SMB2Negotiate();
      negSession.set('SecurityMode', this._Connection.ClientSecurityMode);
      negSession.set('Capabilities', this._Connection.Capabilities);
      negSession.set('ClientGuid', this.ClientGuid);

      const dialect = preferredDialect ?? this._preferredDialect;
      if (dialect != null) {
        negSession.set('Dialects', [dialect]);
      } else {
        negSession.set('Dialects', [
          constants.SMB2_DIALECT_002,
          constants.SMB2_DIALECT_21,
          constants.SMB2_DIALECT_30,
          constants.SMB2_DIALECT_302,
          constants.SMB2_DIALECT_311,
        ]);
      }
      const dialects = negResp?.get('Dialects') ?? negSession.get('Dialects');
      negSession.set('DialectCount', (dialects as number[]).length);

      if ((dialects as number[]).includes(constants.SMB2_DIALECT_311)) {
        const contextData = new SMB311ContextData();
        const dialectList = dialects as number[];
        if (dialectList.length > 1) {
          contextData.set('NegotiateContextOffset', 64 + 38 + 10);
        } else {
          contextData.set('NegotiateContextOffset', 64 + 38 + 2);
        }
        contextData.set('NegotiateContextCount', 0);

        const negotiateContext = new SMB2NegotiateContext();
        negotiateContext.set('ContextType', constants.SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
        const preAuth = new SMB2PreAuthIntegrityCapabilities();
        preAuth.set('HashAlgorithmCount', 1);
        preAuth.set('SaltLength', 32);
        preAuth.set('HashAlgorithms', Buffer.from([0x01, 0x00]));
        preAuth.set('Salt', nodeRandomBytes(32));
        negotiateContext.set('Data', preAuth.getData());
        negotiateContext.set('DataLength', (negotiateContext.get('Data') as Buffer).length);
        contextData.set('NegotiateContextCount', 1);
        const pad = Buffer.alloc(
          (8 - ((negotiateContext.get('DataLength') as number) % 8)) % 8,
          0xff,
        );

        const negotiateContext2 = new SMB2NegotiateContext();
        negotiateContext2.set('ContextType', constants.SMB2_ENCRYPTION_CAPABILITIES);
        const encCaps = new SMB2EncryptionCapabilities();
        encCaps.set('CipherCount', 1);
        encCaps.set('Ciphers', Buffer.from([0x01, 0x00]));
        negotiateContext2.set('Data', encCaps.getData());
        negotiateContext2.set('DataLength', (negotiateContext2.get('Data') as Buffer).length);
        contextData.set('NegotiateContextCount', 2);

        negSession.set('ClientStartTime', contextData.getData());
        negSession.set('Padding', Buffer.from([0xff, 0xff]));
        negSession.set(
          'NegotiateContextList',
          Buffer.concat([negotiateContext.getData(), pad, negotiateContext2.getData()]),
        );
      }

      packet.set('Data', negSession.getData());
      const packetId = await this.sendSMB(packet);
      const ans = await this.recvSMB(packetId);
      if (!ans.isValidAnswer(constants.STATUS_SUCCESS))
        throw new SessionError(ans.get('Status') as number, ans);
      negResp = new SMB2Negotiate_Response(ans.get('Data') as Buffer);
      if (negResp.get('DialectRevision') === constants.SMB2_DIALECT_311) {
        this.updateConnectionPreAuthHash(ans.rawData!);
      }
    }

    negResp = negResp!;
    this._Connection.MaxTransactSize = Math.min(0x100000, negResp.get('MaxTransactSize') as number);
    this._Connection.MaxReadSize = Math.min(0x100000, negResp.get('MaxReadSize') as number);
    this._Connection.MaxWriteSize = Math.min(0x100000, negResp.get('MaxWriteSize') as number);
    this._Connection.ServerGuid = negResp.get('ServerGuid') as Buffer;
    this._Connection.GSSNegotiateToken = negResp.get('Buffer') as Buffer;
    this._Connection.Dialect = negResp.get('DialectRevision') as number;

    if (
      (negResp.get('SecurityMode') as number) & constants.SMB2_NEGOTIATE_SIGNING_REQUIRED ||
      this._Connection.Dialect === constants.SMB2_DIALECT_311
    ) {
      this._Connection.RequireSigning = true;
    }

    if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
      const negContextCount = negResp.get('NegotiateContextCount') as number;
      if (negContextCount > 0) {
        this.processContextList(negContextCount, negResp.get('NegotiateContextList') as Buffer);
      }
    }

    if ((negResp.get('Capabilities') as number) & constants.SMB2_GLOBAL_CAP_LEASING) {
      this._Connection.SupportsFileLeasing = true;
    }
    if ((negResp.get('Capabilities') as number) & constants.SMB2_GLOBAL_CAP_LARGE_MTU) {
      this._Connection.SupportsMultiCredit = true;
    }

    if (this._Connection.Dialect >= constants.SMB2_DIALECT_30) {
      this.SMB_PACKET = SMB3Packet;
      if ((negResp.get('Capabilities') as number) & constants.SMB2_GLOBAL_CAP_DIRECTORY_LEASING) {
        this._Connection.SupportsDirectoryLeasing = true;
      }
      if ((negResp.get('Capabilities') as number) & constants.SMB2_GLOBAL_CAP_MULTI_CHANNEL) {
        this._Connection.SupportsMultiChannel = true;
      }
      if ((negResp.get('Capabilities') as number) & constants.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES) {
        this._Connection.SupportsPersistentHandles = true;
      }
      if ((negResp.get('Capabilities') as number) & constants.SMB2_GLOBAL_CAP_ENCRYPTION) {
        this._Connection.SupportsEncryption = true;
      }
      this._Connection.ServerCapabilities = negResp.get('Capabilities') as number;
      this._Connection.ServerSecurityMode = negResp.get('SecurityMode') as number;
    }
  }

  private processContextList(contextCount: number, contextList: Buffer): void {
    let offset = 0;
    while (contextCount > 0) {
      const context = new SMB2NegotiateContext(contextList.subarray(offset));
      if (context.get('ContextType') === constants.SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
        const preAuth = new SMB2PreAuthIntegrityCapabilities(context.get('Data') as Buffer);
        const hashAlgos = preAuth.get('HashAlgorithms') as Buffer;
        this._Connection.PreauthIntegrityHashId = hashAlgos.readUInt16LE(0);
      } else if (context.get('ContextType') === constants.SMB2_ENCRYPTION_CAPABILITIES) {
        const encCaps = new SMB2EncryptionCapabilities(context.get('Data') as Buffer);
        const ciphers = encCaps.get('Ciphers') as Buffer;
        const cipherId = ciphers.readUInt16LE(0);
        this._Connection.CipherId = cipherId;
        if (cipherId !== 0) {
          this._Connection.SupportsEncryption = true;
        }
      }
      const dataLen = context.get('DataLength') as number;
      const padding = (8 - (dataLen % 8)) % 8;
      offset += 8 + dataLen + padding;
      contextCount--;
    }
  }

  private updateConnectionPreAuthHash(data: Buffer): void {
    const h = createHash('sha512');
    h.update(this._Connection.PreauthIntegrityHashValue);
    h.update(data);
    this._Connection.PreauthIntegrityHashValue = h.digest();
  }

  private updatePreAuthHash(data: Buffer): void {
    const h = createHash('sha512');
    h.update(this._Session.PreauthIntegrityHashValue);
    h.update(data);
    this._Session.PreauthIntegrityHashValue = h.digest();
  }

  signSMB(packet: SMBPacketBase): void {
    packet.set('Signature', Buffer.alloc(16, 0));
    if (
      this._Connection.Dialect === constants.SMB2_DIALECT_21 ||
      this._Connection.Dialect === constants.SMB2_DIALECT_002
    ) {
      if (this._Session.SessionKey.length > 0) {
        const h = createHash('sha256');
        h.update(this._Session.SessionKey);
        h.update(packet.getData());
        packet.set('Signature', h.digest().subarray(0, 16));
      }
    } else {
      if (this._Session.SessionKey.length > 0) {
        const sig = crypto.aesCmac(this._Session.SigningKey, packet.getData());
        packet.set('Signature', sig);
      }
    }
  }

  async sendSMB(packet: SMBPacketBase): Promise<bigint> {
    if (packet.get('Command') !== constants.SMB2_CANCEL) {
      packet.set('MessageID', BigInt(this._Connection.SequenceWindow));
      this._Connection.SequenceWindow += 1;
    }
    packet.set('SessionID', this._Session.SessionID);

    if (!packet.has('CreditCharge')) {
      packet.set('CreditCharge', 1);
    }

    if (this._Connection.SequenceWindow > 3) {
      packet.set('CreditRequestResponse', 127);
    }

    const messageId = packet.get('MessageID') as bigint;

    if (this._Session.SigningActivated && this._Connection.SequenceWindow > 2) {
      const treeId = packet.get('TreeID') as number;
      if (treeId > 0 && treeId in this._Session.TreeConnectTable) {
        if (!this._Session.TreeConnectTable[treeId]!.EncryptData) {
          packet.set('Flags', constants.SMB2_FLAGS_SIGNED);
          this.signSMB(packet);
        }
      } else if (treeId === 0) {
        packet.set('Flags', constants.SMB2_FLAGS_SIGNED);
        this.signSMB(packet);
      }
    }

    if (packet.get('Command') === constants.SMB2_NEGOTIATE) {
      const data = packet.getData();
      this.updateConnectionPreAuthHash(data);
      this._Session.CalculatePreAuthHash = false;
    }

    if (packet.get('Command') === constants.SMB2_SESSION_SETUP) {
      this._Session.CalculatePreAuthHash = true;
    }

    if (!this._NetBIOSSession) throw new Error('No session');

    const treeId = packet.get('TreeID') as number;
    const shouldEncrypt =
      (this._Session.SessionFlags & constants.SMB2_SESSION_FLAG_ENCRYPT_DATA) !== 0 ||
      (treeId !== 0 &&
        treeId in this._Session.TreeConnectTable &&
        this._Session.TreeConnectTable[treeId]!.EncryptData);

    if (shouldEncrypt) {
      const plainText = packet.getData();
      const transformHeader = new SMB2_TRANSFORM_HEADER();
      const nonceBuf = Buffer.alloc(16, 0);
      const randomNonce = nodeRandomBytes(11);
      randomNonce.copy(nonceBuf, 0);
      transformHeader.set('Nonce', nonceBuf);
      transformHeader.set('OriginalMessageSize', plainText.length);
      transformHeader.set('EncryptionAlgorithm', constants.SMB2_ENCRYPTION_AES128_CCM);
      transformHeader.set('SessionID', this._Session.SessionID);

      const headerData = transformHeader.getData();
      const aad = headerData.subarray(20);

      const cipher = createCipheriv('aes-128-ccm', this._Session.EncryptionKey, randomNonce, {
        authTagLength: 16,
      });
      cipher.setAAD(aad, { plaintextLength: plainText.length });
      const cipherText = Buffer.concat([cipher.update(plainText), cipher.final()]);
      const signature = cipher.getAuthTag();

      transformHeader.set('Signature', signature);
      const encryptedPacket = Buffer.concat([transformHeader.getData(), cipherText]);
      await this._NetBIOSSession.sendPacket(encryptedPacket);
    } else {
      const data = packet.getData();
      if (this._Session.CalculatePreAuthHash) {
        this.updatePreAuthHash(data);
      }
      await this._NetBIOSSession.sendPacket(data);
    }

    return messageId;
  }

  /**
   * Read one packet off the wire and parse it, decrypting an SMB2_TRANSFORM
   * (0xfd 'SMB') envelope when present.
   */
  private async recvOnePacket(): Promise<SMBPacketBase> {
    if (!this._NetBIOSSession) throw new Error('No session');
    const trailer = (await this._NetBIOSSession.recvPacket(this._timeout)).get_trailer();
    if (
      trailer.length >= 4 &&
      trailer[0] === 0xfd &&
      trailer.subarray(1, 4).toString('latin1') === 'SMB'
    ) {
      return this.decryptPacket(trailer);
    }
    return new SMB2Packet(trailer);
  }

  /**
   * Receive the response for a given MessageID. When multiple requests are in
   * flight the server may answer them in any order, so a packet whose
   * MessageID does not match the one we are waiting for is stashed in
   * OutstandingResponses and delivered to its own caller later, rather than
   * being wrongly returned here. Passing null/undefined returns the next
   * non-pending packet regardless of MessageID (legacy behaviour).
   */
  async recvSMB(packetID?: bigint | null): Promise<SMBPacketBase> {
    // Already received out of order on a previous call? Hand it back now.
    if (packetID != null && this._Connection.OutstandingResponses.has(packetID)) {
      const stashed = this._Connection.OutstandingResponses.get(packetID)!;
      this._Connection.OutstandingResponses.delete(packetID);
      return stashed;
    }

    let packet = await this.recvOnePacket();

    // Drain interim STATUS_PENDING async-in-progress notifications.
    while (packet.get('Status') === STATUS_PENDING) {
      packet = await this.recvOnePacket();
    }

    if (packetID == null || (packet.get('MessageID') as bigint) === packetID) {
      if (this._Connection.Dialect > constants.SMB2_DIALECT_002) {
        const creditCharge = packet.get('CreditCharge') as number;
        this._Connection.SequenceWindow += creditCharge - 1;
      }
      return packet;
    }

    // Not the response we're waiting for — stash it for its own caller and
    // keep reading until ours arrives.
    this._Connection.OutstandingResponses.set(packet.get('MessageID') as bigint, packet);
    return this.recvSMB(packetID);
  }

  private decryptPacket(trailer: Buffer): SMBPacketBase {
    const transformHeader = new SMB2_TRANSFORM_HEADER(trailer);
    const headerData = transformHeader.getData();
    const aad = headerData.subarray(20);
    const nonce = (transformHeader.get('Nonce') as Buffer).subarray(0, 11);
    const signature = transformHeader.get('Signature') as Buffer;
    const originalMessageSize = transformHeader.get('OriginalMessageSize') as number;
    const cipherText = trailer.subarray(headerData.length);

    const decipher = createDecipheriv('aes-128-ccm', this._Session.DecryptionKey, nonce, {
      authTagLength: 16,
    });
    decipher.setAuthTag(signature);
    decipher.setAAD(aad, { plaintextLength: originalMessageSize });
    const plainText = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return new SMB2Packet(plainText);
  }

  getKerberos(): boolean {
    return this._doKerberos;
  }

  getServerName(): string {
    return this._Session.ServerName;
  }

  getClientName(): string {
    return this._Session.ServerName || this._Connection.ClientName;
  }

  getRemoteName(): string {
    return this._Session.ServerName || this._Connection.ServerName;
  }

  setRemoteName(name: string): boolean {
    this._Session.ServerName = name;
    return true;
  }

  getServerIP(): string {
    return this._Connection.ServerIP;
  }

  getServerDomain(): string {
    return this._Session.ServerDomain;
  }

  getServerDNSDomainName(): string {
    return this._Session.ServerDNSDomainName;
  }

  getServerDNSHostName(): string {
    return this._Session.ServerDNSHostName;
  }

  getServerOS(): string {
    return this._Session.ServerOS;
  }

  getServerOSMajor(): number | null {
    return this._Session.ServerOSMajor;
  }

  getServerOSMinor(): number | null {
    return this._Session.ServerOSMinor;
  }

  getServerOSBuild(): number | null {
    return this._Session.ServerOSBuild;
  }

  isGuestSession(): boolean {
    return (this._Session.SessionFlags & constants.SMB2_SESSION_FLAG_IS_GUEST) !== 0;
  }

  setTimeout(timeout: number): void {
    this._timeout = timeout;
  }

  getDialect(): number {
    return this._Connection.Dialect;
  }

  getSessionKey(): Buffer {
    if (this._Connection.Dialect >= constants.SMB2_DIALECT_30 && this._Session.ApplicationKey?.length) {
      return this._Session.ApplicationKey;
    }
    return this._Session.SessionKey;
  }

  setSessionKey(key: Buffer): void {
    this._Session.SessionKey = key;
    this._Session.SigningActivated = true;
  }

  isLoginRequired(): boolean {
    return true;
  }

  isSigningRequired(): boolean {
    return this._Connection.RequireSigning;
  }

  doesSupportNTLMv2(): boolean {
    return true;
  }

  closeSession(): void {
    if (this._NetBIOSSession) {
      this._NetBIOSSession.close();
      this._NetBIOSSession = null;
    }
  }

  getSocket(): import('node:net').Socket | null {
    return this._NetBIOSSession?.get_socket() ?? null;
  }

  setHostnameValidation(validate: boolean, acceptEmpty: boolean, hostname: string): void {
    this._strictHostnameValidation = validate;
    this._validationAllowAbsent = acceptEmpty;
    this._acceptedHostname = hostname;
  }

  performHostnameValidation(): void {
    if (this._Session.ServerName === '') {
      if (!this._validationAllowAbsent) {
        throw new SMB3.HostnameValidationException(
          'Hostname was not supplied by target host and absent validation is disallowed',
        );
      }
      return;
    }
    if (
      this._Session.ServerName.toLowerCase() !== this._acceptedHostname.toLowerCase() &&
      this._Session.ServerDNSHostName.toLowerCase() !== this._acceptedHostname.toLowerCase()
    ) {
      throw new SMB3.HostnameValidationException(
        `Supplied hostname ${this._acceptedHostname.toLowerCase()} does not match reported hostnames ${this._Session.ServerName.toLowerCase()} or ${this._Session.ServerDNSHostName.toLowerCase()}`,
      );
    }
  }

  getCredentials() {
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
    return {
      MaxReadSize: this._Connection.MaxReadSize,
      MaxWriteSize: this._Connection.MaxWriteSize,
    };
  }

  async login(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
  ): Promise<boolean> {
    let lm = lmhash;
    let nt = nthash;
    if (lm || nt) {
      if (typeof lm === 'string' && lm.length % 2) lm = `0${lm}`;
      if (typeof nt === 'string' && nt.length % 2) nt = `0${nt}`;
      try {
        if (typeof lm === 'string') lm = Buffer.from(lm, 'hex');
        if (typeof nt === 'string') nt = Buffer.from(nt, 'hex');
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

    const sessionSetup = new SMB2SessionSetup();
    sessionSetup.set(
      'SecurityMode',
      this.RequireMessageSigning
        ? constants.SMB2_NEGOTIATE_SIGNING_REQUIRED
        : constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
    );
    sessionSetup.set('Flags', 0);

    const blob = new SPNEGO_NegTokenInit();
    blob.mechTypeOids = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!];
    const auth = ntlmMod.getNTLMSSPType1(
      this._Connection.ClientName,
      domain,
      this._Connection.RequireSigning,
    );
    blob.fields.MechToken = auth.getData();

    sessionSetup.set('SecurityBufferLength', blob.getData().length);
    sessionSetup.set('Buffer', blob.getData());

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_SESSION_SETUP);
    packet.set('Data', sessionSetup.getData());

    this._Session.PreauthIntegrityHashValue = Buffer.from(
      this._Connection.PreauthIntegrityHashValue,
    );

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);

    if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
      this.updatePreAuthHash(ans.rawData!);
    }

    if (!ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    this._Session.SessionID = ans.get('SessionID') as bigint;
    this._Session.SigningRequired = this._Connection.RequireSigning;

    const sessionSetupResponse = new SMB2SessionSetup_Response(ans.get('Data') as Buffer);
    const respToken = new SPNEGO_NegTokenResp(sessionSetupResponse.get('Buffer') as Buffer);
    const ntlmChallenge = new ntlmMod.NTLMAuthChallenge(respToken.fields.ResponseToken!);

    const tiLen = ntlmChallenge.get('TargetInfoFields_len') as number;
    if (tiLen > 0) {
      const avPairs = new ntlmMod.AV_PAIRS(
        (ntlmChallenge.get('TargetInfoFields') as Buffer).subarray(0, tiLen),
      );
      const hostname = avPairs.get(ntlmMod.NTLMSSP_AV_HOSTNAME);
      if (hostname) {
        try {
          this._Session.ServerName = hostname[1].toString('utf-16le');
        } catch {
          // silently discard
        }
      }
      const domainName = avPairs.get(ntlmMod.NTLMSSP_AV_DOMAINNAME);
      if (domainName) {
        try {
          if (this._Session.ServerName !== domainName[1].toString('utf-16le')) {
            this._Session.ServerDomain = domainName[1].toString('utf-16le');
          }
        } catch {
          // silently discard
        }
      }
      const dnsDomain = avPairs.get(ntlmMod.NTLMSSP_AV_DNS_DOMAINNAME);
      if (dnsDomain) {
        try {
          this._Session.ServerDNSDomainName = dnsDomain[1].toString('utf-16le');
        } catch {
          // silently discard
        }
      }
      const dnsHost = avPairs.get(ntlmMod.NTLMSSP_AV_DNS_HOSTNAME);
      if (dnsHost) {
        try {
          this._Session.ServerDNSHostName = dnsHost[1].toString('utf-16le');
        } catch {
          // silently discard
        }
      }

      if (this._strictHostnameValidation) {
        this.performHostnameValidation();
      }

      if (ntlmChallenge.has('Version')) {
        const version = ntlmChallenge.get('Version') as Buffer;
        if (version && version.length >= 4) {
          this._Session.ServerOSMajor = version[0]!;
          this._Session.ServerOSMinor = version[1]!;
          this._Session.ServerOSBuild = version.readUInt16LE(2);
        }
      }
    }

    const [type3, exportedSessionKey] = ntlmMod.getNTLMSSPType3(
      auth,
      respToken.fields.ResponseToken!,
      user,
      password,
      domain,
      lm,
      nt,
    );

    const respToken2 = new SPNEGO_NegTokenResp();
    respToken2.fields.ResponseToken = type3.getData();

    sessionSetup.set('SecurityBufferLength', respToken2.getData().length);
    sessionSetup.set('Buffer', respToken2.getData());

    const packet2 = new this.SMB_PACKET();
    packet2.set('Command', constants.SMB2_SESSION_SETUP);
    packet2.set('Data', sessionSetup.getData());

    const packetID2 = await this.sendSMB(packet2);
    const resp = await this.recvSMB(packetID2);

    if (exportedSessionKey) {
      this._Session.SessionKey = exportedSessionKey;
      if (this._Session.SigningRequired && this._Connection.Dialect >= constants.SMB2_DIALECT_30) {
        if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
          this._Session.SigningKey = crypto.kdfCounterMode(
            exportedSessionKey,
            Buffer.from('SMBSigningKey\x00'),
            this._Session.PreauthIntegrityHashValue,
            128,
          );
        } else {
          this._Session.SigningKey = crypto.kdfCounterMode(
            exportedSessionKey,
            Buffer.from('SMB2AESCMAC\x00'),
            Buffer.from('SmbSign\x00'),
            128,
          );
        }
      }
    }

    if (!resp.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(resp.get('Status') as number, resp);
    }

    const sessionSetupResponse2 = new SMB2SessionSetup_Response(resp.get('Data') as Buffer);
    this._Session.SessionFlags = sessionSetupResponse2.get('SessionFlags') as number;
    this._Session.SessionID = resp.get('SessionID') as bigint;

    if (user === '' || this.isGuestSession()) {
      this._Connection.SupportsEncryption = false;
    }

    if (this._Session.SigningRequired) {
      this._Session.SigningActivated = true;
    }

    if (
      this._Connection.Dialect >= constants.SMB2_DIALECT_30 &&
      this._Connection.SupportsEncryption
    ) {
      this._Session.SessionFlags |= constants.SMB2_SESSION_FLAG_ENCRYPT_DATA;
      if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
        this._Session.ApplicationKey = crypto.kdfCounterMode(
          exportedSessionKey,
          Buffer.from('SMBAppKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
        this._Session.EncryptionKey = crypto.kdfCounterMode(
          exportedSessionKey,
          Buffer.from('SMBC2SCipherKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
        this._Session.DecryptionKey = crypto.kdfCounterMode(
          exportedSessionKey,
          Buffer.from('SMBS2CCipherKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
      } else {
        this._Session.ApplicationKey = crypto.kdfCounterMode(
          exportedSessionKey,
          Buffer.from('SMB2APP\x00'),
          Buffer.from('SmbRpc\x00'),
          128,
        );
        this._Session.EncryptionKey = crypto.kdfCounterMode(
          exportedSessionKey,
          Buffer.from('SMB2AESCCM\x00'),
          Buffer.from('ServerIn \x00'),
          128,
        );
        this._Session.DecryptionKey = crypto.kdfCounterMode(
          exportedSessionKey,
          Buffer.from('SMB2AESCCM\x00'),
          Buffer.from('ServerOut\x00'),
          128,
        );
      }
    }

    this._Session.CalculatePreAuthHash = false;
    return true;
  }

  async kerberosLogin(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    aesKey: Buffer | string = '',
    kdcHost: string | null = null,
    TGT: krb5.KerberosV5.TGTResult | null = null,
    TGS: krb5.KerberosV5.TGSResult | null = null,
    mutualAuth = false,
  ): Promise<boolean> {
    let lm = lmhash;
    let nt = nthash;
    if (lm || nt) {
      if (typeof lm === 'string' && lm.length % 2) lm = `0${lm}`;
      if (typeof nt === 'string' && nt.length % 2) nt = `0${nt}`;
      try {
        if (typeof lm === 'string') lm = Buffer.from(lm, 'hex');
        if (typeof nt === 'string') nt = Buffer.from(nt, 'hex');
      } catch {
        // already converted
      }
    }

    this._userName = user;
    this._password = password;
    this._domain = domain;
    this._lmhash = lm;
    this._nthash = nt;
    this._kdc = kdcHost ?? '';
    this._aesKey = aesKey;
    this._TGT = TGT;
    this._TGS = TGS;
    this._doKerberos = true;

    const sessionSetup = new SMB2SessionSetup();
    sessionSetup.set(
      'SecurityMode',
      this.RequireMessageSigning
        ? constants.SMB2_NEGOTIATE_SIGNING_REQUIRED
        : constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
    );
    sessionSetup.set('Flags', 0);

    const userName = new krb5.Types.Principal(
      user,
      null,
      krb5.Constants.PrincipalNameType.NT_PRINCIPAL,
    );

    let tgtResult: krb5.KerberosV5.TGTResult;
    if (TGT !== null) {
      tgtResult = TGT;
    } else {
      tgtResult = await krb5.KerberosV5.getKerberosTGT(
        userName,
        password,
        domain,
        lm,
        nt,
        aesKey,
        kdcHost,
      );
    }

    let tgsResult: krb5.KerberosV5.TGSResult;
    if (TGS !== null) {
      tgsResult = TGS;
    } else {
      const serverName = new krb5.Types.Principal(
        `cifs/${this._Connection.ServerName}`,
        null,
        krb5.Constants.PrincipalNameType.NT_SRV_INST,
      );
      tgsResult = await krb5.KerberosV5.getKerberosTGS(
        serverName,
        domain.toUpperCase(),
        kdcHost,
        tgtResult.tgt,
        tgtResult.cipher,
        tgtResult.sessionKey,
      );
    }

    const type1Result = await krb5.KerberosV5.getKerberosType1(
      user,
      password,
      domain,
      lm,
      nt,
      aesKey,
      this._Connection.ServerName,
      kdcHost,
      true,
      tgtResult,
      tgsResult,
    );

    sessionSetup.set('SecurityBufferLength', type1Result.data.length);
    sessionSetup.set('Buffer', type1Result.data);

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_SESSION_SETUP);
    packet.set('Data', sessionSetup.getData());

    this._Session.PreauthIntegrityHashValue = Buffer.from(
      this._Connection.PreauthIntegrityHashValue,
    );

    const packetID = await this.sendSMB(packet);
    let ans = await this.recvSMB(packetID);

    if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
      this.updatePreAuthHash(ans.rawData!);
    }

    this._Session.SessionID = ans.get('SessionID') as bigint;
    this._Session.SigningRequired = this._Connection.RequireSigning;

    let sessionKey: Buffer;

    const status = ans.get('Status') as number;
    if (status === STATUS_MORE_PROCESSING_REQUIRED) {
      const sessionSetupResponse = new SMB2SessionSetup_Response(ans.get('Data') as Buffer);
      const respBuffer = sessionSetupResponse.get('Buffer') as Buffer;
      const type3Result = krb5.KerberosV5.getKerberosType3(
        tgsResult.cipher,
        tgsResult.sessionKey,
        respBuffer,
      );
      sessionKey = type3Result.sessionKey.contents.subarray(0, 16);

      const sessionSetup2 = new SMB2SessionSetup();
      sessionSetup2.set(
        'SecurityMode',
        this.RequireMessageSigning
          ? constants.SMB2_NEGOTIATE_SIGNING_REQUIRED
          : constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
      );
      sessionSetup2.set('Flags', 0);
      sessionSetup2.set('SecurityBufferLength', type3Result.data.length);
      sessionSetup2.set('Buffer', type3Result.data);

      const packet2 = new this.SMB_PACKET();
      packet2.set('Command', constants.SMB2_SESSION_SETUP);
      packet2.set('Data', sessionSetup2.getData());

      const packetID2 = await this.sendSMB(packet2);
      ans = await this.recvSMB(packetID2);

      if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
        throw new SessionError(ans.get('Status') as number, ans);
      }
    } else if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(status, ans);
    } else {
      sessionKey = tgsResult.sessionKey.contents.subarray(0, 16);
    }

    this._Session.SessionKey = sessionKey;

    if (this._Session.SigningRequired && this._Connection.Dialect >= constants.SMB2_DIALECT_30) {
      if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
        this._Session.SigningKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMBSigningKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
      } else {
        this._Session.SigningKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMB2AESCMAC\x00'),
          Buffer.from('SmbSign\x00'),
          128,
        );
      }
    }

    if (user === '' || this.isGuestSession()) {
      this._Connection.SupportsEncryption = false;
    }

    if (this._Session.SigningRequired) {
      this._Session.SigningActivated = true;
    }

    if (
      this._Connection.Dialect >= constants.SMB2_DIALECT_30 &&
      this._Connection.SupportsEncryption
    ) {
      this._Session.SessionFlags |= constants.SMB2_SESSION_FLAG_ENCRYPT_DATA;
      if (this._Connection.Dialect === constants.SMB2_DIALECT_311) {
        this._Session.ApplicationKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMBAppKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
        this._Session.EncryptionKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMBC2SCipherKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
        this._Session.DecryptionKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMBS2CCipherKey\x00'),
          this._Session.PreauthIntegrityHashValue,
          128,
        );
      } else {
        this._Session.ApplicationKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMB2APP\x00'),
          Buffer.from('SmbRpc\x00'),
          128,
        );
        this._Session.EncryptionKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMB2AESCCM\x00'),
          Buffer.from('ServerIn \x00'),
          128,
        );
        this._Session.DecryptionKey = crypto.kdfCounterMode(
          this._Session.SessionKey,
          Buffer.from('SMB2AESCCM\x00'),
          Buffer.from('ServerOut\x00'),
          128,
        );
      }
    }

    this._Session.CalculatePreAuthHash = false;
    this._TGT = tgtResult;
    this._TGS = tgsResult;
    return true;
  }

  async connectTree(share: string): Promise<number> {
    share = share.split('\\').pop()!;
    if (share in this._Session.TreeConnectTable) {
      const treeEntry = this._Session.TreeConnectTable[share]!;
      treeEntry.NumberOfUses += 1;
      this._Session.TreeConnectTable[treeEntry.TreeConnectId]!.NumberOfUses += 1;
      return treeEntry.TreeConnectId;
    }

    const path = `\\\\${this._Connection.ServerIP}\\${share}`;
    const treeConnect = new SMB2TreeConnect();
    treeConnect.set('Buffer', Buffer.from(path, 'utf-16le'));
    treeConnect.set('PathLength', (treeConnect.get('Buffer') as Buffer).length);

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_TREE_CONNECT);
    packet.set('Data', treeConnect.getData());

    const packetID = await this.sendSMB(packet);
    const resp = await this.recvSMB(packetID);

    if (!resp.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(resp.get('Status') as number, resp);
    }

    const treeConnectResponse = new SMB2TreeConnect_Response(resp.get('Data') as Buffer);
    const treeEntry = newTreeEntry();
    treeEntry.ShareName = share;
    treeEntry.TreeConnectId = resp.get('TreeID') as number;
    treeEntry.Session = resp.get('SessionID') as bigint;
    treeEntry.NumberOfUses = 1;

    if ((treeConnectResponse.get('Capabilities') as number) & constants.SMB2_SHARE_CAP_DFS) {
      treeEntry.IsDfsShare = true;
    }
    if (
      (treeConnectResponse.get('Capabilities') as number) &
      constants.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
    ) {
      treeEntry.IsCAShare = true;
    }
    if (
      this._Connection.Dialect >= constants.SMB2_DIALECT_30 &&
      this._Connection.SupportsEncryption
    ) {
      if (
        (treeConnectResponse.get('ShareFlags') as number) & constants.SMB2_SHAREFLAG_ENCRYPT_DATA
      ) {
        treeEntry.EncryptData = true;
      }
    }
    if ((treeConnectResponse.get('Capabilities') as number) & constants.SMB2_SHARE_CAP_SCALEOUT) {
      treeEntry.IsScaleoutShare = true;
    }

    this._Session.TreeConnectTable[treeEntry.TreeConnectId] = treeEntry;
    this._Session.TreeConnectTable[share] = treeEntry;
    return treeEntry.TreeConnectId;
  }

  async disconnectTree(treeId: number): Promise<boolean> {
    if (!(treeId in this._Session.TreeConnectTable)) {
      throw new SessionError(STATUS_INVALID_PARAMETER);
    }

    const treeEntry = this._Session.TreeConnectTable[treeId]!;
    if (treeEntry.NumberOfUses > 1) {
      treeEntry.NumberOfUses -= 1;
      this._Session.TreeConnectTable[treeEntry.ShareName]!.NumberOfUses -= 1;
      return true;
    }

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_TREE_DISCONNECT);
    packet.set('TreeID', treeId);
    packet.set('Data', new SMB2TreeDisconnect().getData());

    const packetID = await this.sendSMB(packet);
    const resp = await this.recvSMB(packetID);

    if (!resp.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(resp.get('Status') as number, resp);
    }

    const shareName = this._Session.TreeConnectTable[treeId]!.ShareName;
    delete this._Session.TreeConnectTable[shareName];
    delete this._Session.TreeConnectTable[treeId];
    return true;
  }

  async create(
    treeId: number,
    fileName: string,
    desiredAccess: number,
    shareMode: number,
    creationOptions: number,
    creationDisposition: number,
    fileAttributes: number,
    impersonationLevel = constants.SMB2_IL_IMPERSONATION,
    securityFlags = 0,
    oplockLevel = constants.SMB2_OPLOCK_LEVEL_NONE,
  ): Promise<Buffer> {
    if (!(treeId in this._Session.TreeConnectTable)) {
      throw new SessionError(STATUS_INVALID_PARAMETER);
    }

    fileName = fileName.replace('/', '\\');
    if (fileName.startsWith('\\')) fileName = fileName.slice(1);

    const smb2Create = new SMB2Create();
    smb2Create.set('SecurityFlags', securityFlags);
    smb2Create.set('RequestedOplockLevel', oplockLevel);
    smb2Create.set('ImpersonationLevel', impersonationLevel);
    smb2Create.set('DesiredAccess', desiredAccess);
    smb2Create.set('FileAttributes', fileAttributes);
    smb2Create.set('ShareAccess', shareMode);
    smb2Create.set('CreateDisposition', creationDisposition);
    smb2Create.set('CreateOptions', creationOptions);

    const nameBuf = fileName ? Buffer.from(fileName, 'utf-16le') : Buffer.from([0x00]);
    smb2Create.set('NameLength', fileName ? nameBuf.length : 0);
    smb2Create.set('Buffer', nameBuf);
    smb2Create.set('CreateContextsOffset', 0);
    smb2Create.set('CreateContextsLength', 0);

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_CREATE);
    packet.set('TreeID', treeId);
    packet.set('Data', smb2Create.getData());

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);

    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const createResponse = new SMB2Create_Response(ans.get('Data') as Buffer);
    const fileId = createResponse.get('FileID') as Buffer;

    const openFile = newOpenFile();
    openFile.FileID = fileId;
    openFile.TreeConnect = treeId;
    openFile.Oplocklevel = oplockLevel;
    openFile.FileName = fileName;
    this._Session.OpenTable[fileId.toString('hex')] = openFile;

    return fileId;
  }

  async close(treeId: number, fileId: Buffer): Promise<boolean> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_CLOSE);
    packet.set('TreeID', treeId);

    const smbClose = new SMB2Close();
    smbClose.set('Flags', 0);
    smbClose.set('FileID', fileId);
    packet.set('Data', smbClose.getData());

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);

    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const key = fileId.toString('hex');
    delete this._Session.OpenTable[key];
    return true;
  }

  async read(
    treeId: number,
    fileId: Buffer,
    bytesToRead: number,
    offset = 0n,
    waitAnswer = true,
  ): Promise<Buffer> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_READ);
    packet.set('TreeID', treeId);

    const maxBytesToRead = Math.min(this._Connection.MaxReadSize, bytesToRead);
    if (
      this._Connection.Dialect !== constants.SMB2_DIALECT_002 &&
      this._Connection.SupportsMultiCredit
    ) {
      packet.set('CreditCharge', 1 + Math.floor((maxBytesToRead - 1) / 65536));
    }

    const smbRead = new SMB2Read();
    smbRead.set('Padding', 0x50);
    smbRead.set('FileID', fileId);
    smbRead.set('Length', maxBytesToRead);
    smbRead.set('Offset', offset);
    smbRead.set('Buffer', Buffer.from('0'));
    packet.set('Data', smbRead.getData());

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);

    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const readResponse = new SMB2Read_Response(ans.get('Data') as Buffer);
    let retData = readResponse.get('Buffer') as Buffer;
    const dataRemaining = readResponse.get('DataRemaining') as number;
    if (dataRemaining > 0) {
      const more = await this.read(
        treeId,
        fileId,
        dataRemaining,
        offset + BigInt(retData.length),
        waitAnswer,
      );
      retData = Buffer.concat([retData, more]);
    }
    return retData;
  }

  async write(
    treeId: number,
    fileId: Buffer,
    data: Buffer,
    offset = 0n,
    bytesToWrite = 0,
    waitAnswer = true,
  ): Promise<number> {
    if (bytesToWrite === 0) bytesToWrite = data.length;

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_WRITE);
    packet.set('TreeID', treeId);

    const maxBytesToWrite = Math.min(this._Connection.MaxWriteSize, bytesToWrite);
    if (
      this._Connection.Dialect !== constants.SMB2_DIALECT_002 &&
      this._Connection.SupportsMultiCredit
    ) {
      packet.set('CreditCharge', 1 + Math.floor((maxBytesToWrite - 1) / 65536));
    }

    const smbWrite = new SMB2Write();
    smbWrite.set('FileID', fileId);
    smbWrite.set('Length', maxBytesToWrite);
    smbWrite.set('Offset', offset);
    smbWrite.set('WriteChannelInfoOffset', 0);
    smbWrite.set('Buffer', data.subarray(0, maxBytesToWrite));
    packet.set('Data', smbWrite.getData());

    const packetID = await this.sendSMB(packet);
    if (!waitAnswer) return maxBytesToWrite;

    const ans = await this.recvSMB(packetID);
    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const writeResponse = new SMB2Write_Response(ans.get('Data') as Buffer);
    let bytesWritten = writeResponse.get('Count') as number;
    if (bytesWritten < bytesToWrite) {
      bytesWritten += await this.write(
        treeId,
        fileId,
        data.subarray(bytesWritten),
        offset + BigInt(bytesWritten),
        bytesToWrite - bytesWritten,
        waitAnswer,
      );
    }
    return bytesWritten;
  }

  async writeFile(treeId: number, fileId: Buffer, data: Buffer, offset = 0n): Promise<number> {
    const maxWriteSize = this._Connection.MaxWriteSize;
    let writeOffset = offset;
    let remaining = data;
    let totalWritten = 0;
    while (remaining.length > 0) {
      const chunk = remaining.subarray(0, maxWriteSize);
      remaining = remaining.subarray(maxWriteSize);
      const written = await this.write(treeId, fileId, chunk, writeOffset, chunk.length);
      writeOffset += BigInt(written);
      totalWritten += written;
    }
    return totalWritten;
  }

  async echo(): Promise<boolean> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_ECHO);
    packet.set('Data', new SMB2Echo().getData());
    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);
    return ans.isValidAnswer(constants.STATUS_SUCCESS);
  }

  async logoff(): Promise<boolean> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_LOGOFF);
    packet.set('Data', new SMB2Logoff().getData());
    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);
    return ans.isValidAnswer(constants.STATUS_SUCCESS);
  }

  async flush(treeId: number, fileId: Buffer): Promise<boolean> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_FLUSH);
    packet.set('TreeID', treeId);
    const smbFlush = new SMB2Flush();
    smbFlush.set('FileID', fileId);
    packet.set('Data', smbFlush.getData());
    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);
    return ans.isValidAnswer(constants.STATUS_SUCCESS);
  }

  async queryDirectory(
    treeId: number,
    fileId: Buffer,
    searchString = '*',
    resumeIndex = 0,
    informationClass = constants.FILENAMES_INFORMATION,
    maxBufferSize?: number,
  ): Promise<Buffer> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_QUERY_DIRECTORY);
    packet.set('TreeID', treeId);

    const qd = new SMB2QueryDirectory();
    qd.set('FileInformationClass', informationClass);
    qd.set('Flags', resumeIndex !== 0 ? constants.SMB2_INDEX_SPECIFIED : 0);
    qd.set('FileIndex', resumeIndex);
    qd.set('FileID', fileId);
    qd.set('OutputBufferLength', maxBufferSize ?? this._Connection.MaxReadSize);
    qd.set('Buffer', Buffer.from(searchString, 'utf-16le'));
    qd.set('FileNameLength', (qd.get('Buffer') as Buffer).length);
    packet.set('Data', qd.getData());

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);

    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const qdResp = new SMB2QueryDirectory_Response(ans.get('Data') as Buffer);
    return qdResp.get('Buffer') as Buffer;
  }

  async queryInfo(
    treeId: number,
    fileId: Buffer,
    inputBlob: Buffer = Buffer.alloc(0),
    infoType = constants.SMB2_0_INFO_FILE,
    fileInfoClass = constants.SMB2_FILE_STANDARD_INFO,
    additionalInformation = 0,
    flags = 0,
  ): Promise<Buffer> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_QUERY_INFO);
    packet.set('TreeID', treeId);

    const qi = new SMB2QueryInfo();
    qi.set('InfoType', infoType);
    qi.set('FileInfoClass', fileInfoClass);
    qi.set('OutputBufferLength', 0x1000);
    qi.set('InputBufferLength', inputBlob.length);
    qi.set('AdditionalInformation', additionalInformation);
    qi.set('Flags', flags);
    qi.set('FileID', fileId);
    qi.set('Buffer', inputBlob);
    packet.set('Data', qi.getData());

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);

    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const qiResp = new SMB2QueryInfo_Response(ans.get('Data') as Buffer);
    return qiResp.get('Buffer') as Buffer;
  }

  async setInfo(
    treeId: number,
    fileId: Buffer,
    inputBlob: Buffer = Buffer.alloc(0),
    infoType = constants.SMB2_0_INFO_FILE,
    fileInfoClass = constants.SMB2_FILE_STANDARD_INFO,
    additionalInformation = 0,
  ): Promise<boolean> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_SET_INFO);
    packet.set('TreeID', treeId);

    const si = new SMB2SetInfo();
    si.set('InfoType', infoType);
    si.set('FileInfoClass', fileInfoClass);
    si.set('BufferLength', inputBlob.length);
    si.set('AdditionalInformation', additionalInformation);
    si.set('FileID', fileId);
    si.set('Buffer', inputBlob);
    packet.set('Data', si.getData());

    const packetID = await this.sendSMB(packet);
    const ans = await this.recvSMB(packetID);
    return ans.isValidAnswer(constants.STATUS_SUCCESS);
  }

  async ioctl(
    treeId: number,
    fileId: Buffer | null,
    ctlCode: number,
    flags = 0,
    inputBlob: Buffer = Buffer.alloc(0),
    maxInputResponse: number | null = null,
    maxOutputResponse: number | null = null,
    waitAnswer = true,
  ): Promise<Buffer> {
    const fid = fileId ?? Buffer.alloc(16, 0xff);

    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_IOCTL);
    packet.set('TreeID', treeId);

    const smbIoctl = new SMB2Ioctl();
    smbIoctl.set('FileID', fid);
    smbIoctl.set('CtlCode', ctlCode);
    smbIoctl.set('MaxInputResponse', maxInputResponse ?? 0);
    smbIoctl.set('MaxOutputResponse', maxOutputResponse ?? 0);
    smbIoctl.set('InputCount', inputBlob.length);
    if (inputBlob.length === 0) {
      smbIoctl.set('InputOffset', 0);
      smbIoctl.set('Buffer', Buffer.from([0x00]));
    } else {
      smbIoctl.set('Buffer', inputBlob);
    }
    smbIoctl.set('OutputOffset', 0);
    smbIoctl.set('OutputCount', 0);
    smbIoctl.set('Flags', flags);
    packet.set('Data', smbIoctl.getData());

    const packetID = await this.sendSMB(packet);
    if (!waitAnswer) return Buffer.alloc(0);

    const ans = await this.recvSMB(packetID);
    if (!ans.isValidAnswer(constants.STATUS_SUCCESS)) {
      throw new SessionError(ans.get('Status') as number, ans);
    }

    const ioctlResp = new SMB2Ioctl_Response(ans.get('Data') as Buffer);
    return ioctlResp.get('Buffer') as Buffer;
  }

  async cancel(packetID: bigint): Promise<void> {
    const packet = new this.SMB_PACKET();
    packet.set('Command', constants.SMB2_CANCEL);
    packet.set('MessageID', packetID);
    packet.set('Data', new SMB2Cancel().getData());
    await this.sendSMB(packet);
  }

  ntCreateAndX = SMB3.prototype.create;
  readAndX = SMB3.prototype.read;
  writeAndX = SMB3.prototype.write;
  openAndX = SMB3.prototype.create;

  async TransactNamedPipe(
    treeId: number,
    fileId: Buffer,
    data: Buffer,
    waitAnswer = true,
  ): Promise<Buffer> {
    return this.ioctl(
      treeId,
      fileId,
      constants.FSCTL_PIPE_TRANSCEIVE,
      constants.SMB2_0_IOCTL_IS_FSCTL,
      data,
      0,
      0x100000,
      waitAnswer,
    );
  }

  async TransactNamedPipeRecv(): Promise<Buffer> {
    throw new Error(
      'TransactNamedPipeRecv not implemented — use TransactNamedPipe with waitAnswer=true',
    );
  }

  async waitNamedPipe(treeId: number, pipename: string, timeout = 5): Promise<boolean> {
    const pipeWait = new (await import('./structures.js')).FSCTL_PIPE_WAIT_STRUCTURE();
    const baseName = pipename.replace(/^\\+/, '');
    const nameBuf = Buffer.from(baseName, 'utf-16le');
    pipeWait.set('Timeout', timeout * 100000);
    pipeWait.set('NameLength', nameBuf.length);
    pipeWait.set('TimeoutSpecified', 1);
    pipeWait.set('Name', nameBuf);
    await this.ioctl(treeId, null, constants.FSCTL_PIPE_WAIT, constants.SMB2_0_IOCTL_IS_FSCTL, pipeWait.getData(), 0, 0);
    return true;
  }
}
