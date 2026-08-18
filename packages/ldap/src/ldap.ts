import { Buffer } from 'node:buffer';
import { connect as netConnect, type Socket } from 'node:net';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import { getGlobalProxy, createSocket, createTlsSocket } from '@impacket/socks';
import { createHash, randomInt } from 'node:crypto';
import {
  getNTLMSSPType1,
  getNTLMSSPType3,
  NTLMAuthChallenge,
  VERSION as NTLM_VERSION,
  hmacMd5,
} from '@impacket/ntlm';
import {
  SPNEGO_NegTokenInit,
  SPNEGO_NegTokenResp,
  SPNEGOCipher,
  TypesMech,
} from '@impacket/spnego';
import {
  KerberosV5,
  Types as KrbTypes,
  Constants as KrbConstants,
  Asn1 as KrbAsn1,
  Crypto as KrbCrypto,
  CCache as KrbCCache,
  GSSAPI as KrbGSSAPI,
} from '@impacket/krb5';
import {
  type LdapControl,
  type Filter,
  type SearchRequest,
  type SearchResultEntry,
  type BindRequest,
  type AuthenticationChoice,
  type ExtendedResponse,
  type Substring,
  ProtocolOpTag,
  ResultCode,
  Scope,
  DerefAliases,
  Operation,
  CONTROL_PAGEDRESULTS,
  NOTIFICATION_DISCONNECT,
  KNOWN_NOTIFICATIONS,
  encodeBindRequest,
  encodeSearchRequest,
  encodeLDAPMessage,
  decodeLDAPMessage,
  decodeBindResponse,
  decodeSearchResultEntry,
  decodeSearchResultReference,
  decodeExtendedResponse,
  decodeControl,
  decodeSimplePagedResultsControlValue,
  createSimplePagedResultsControl,
  encodeUnbindRequest,
  encodeAbandonRequest,
  encodeModifyRequest,
  encodeAddRequest,
  encodeDelRequest,
  encodeModifyDNRequest,
  encodeCompareRequest,
  type ModifyRequest,
  type ModifyChange,
  type AddRequest,
  type ModifyDNRequest,
  type CompareRequest,
  type Attribute,
  type LDAPResult,
  decodeLDAPResult,
} from './ldapasn1.js';

export class LDAPFilterSyntaxError extends SyntaxError {}
export class LDAPFilterInvalidException extends Error {}
export class LDAPSessionError extends Error {
  error = 0;
  packet: Buffer | null = null;
  errorString: string;
  constructor(opts: { error?: number; packet?: Buffer; errorString?: string } = {}) {
    super(opts.errorString ?? '');
    this.error = opts.error ?? 0;
    this.packet = opts.packet ?? null;
    this.errorString = opts.errorString ?? '';
  }
  getErrorCode(): number {
    return this.error;
  }
  getErrorPacket(): Buffer | null {
    return this.packet;
  }
  getErrorString(): string {
    return this.errorString;
  }
}
export class LDAPSearchError extends LDAPSessionError {
  answers: SearchResultEntry[] = [];
  constructor(
    opts: {
      error?: number;
      packet?: Buffer;
      errorString?: string;
      answers?: SearchResultEntry[];
    } = {},
  ) {
    super(opts);
    this.answers = opts.answers ?? [];
  }
  getAnswers(): SearchResultEntry[] {
    return this.answers;
  }
}

const RE_OPERATOR = /([:<>~]?=)/;
const RE_ATTRIBUTE = /^([a-z][a-z0-9-]*(?:;(?:[a-z0-9-]+))*)$/i;
const RE_EX_ATTRIBUTE_1 =
  /^([a-z][a-z0-9-]*(?:;(?:[a-z0-9-]+))*)(:dn)?(?::([a-z][a-z0-9-]*|(?:(?:\d|[1-9]\d+)(?:\.(?:\d|[1-9]\d+))*)))?$/i;
const RE_EX_ATTRIBUTE_2 =
  /^(?:()(?::dn)?(?::([a-z][a-z0-9-]*|(?:(?:\d|[1-9]\d+)(?:\.(?:\d|[1-9]\d+))*))))?$/i;

export interface LDAPConnectionOptions {
  url: string;
  baseDN?: string;
  dstIp?: string;
  signing?: boolean;
}

export interface LoginOptions {
  user?: string;
  password?: string;
  domain?: string;
  lmhash?: string | Buffer;
  nthash?: string | Buffer;
  authenticationChoice?: 'simple' | 'sicilyPackageDiscovery' | 'sicilyNegotiate' | 'sasl';
}

export class LDAPConnection {
  private socket: Socket | TLSSocket | null = null;
  private baseDN: string;
  private dstIp: string | undefined;
  private dstHost: string;
  private dstPort: number;
  private ssl: boolean;
  private signing: boolean;
  private bound = false;
  private channelBindingValue: Buffer | null = null;
  private sequenceNumber = 0;
  private authType: string | null = null;
  private spnegoCipherBlob: SPNEGOCipher | null = null;
  private gssapiCipher: ReturnType<typeof KrbGSSAPI.GSSAPI> | null = null;
  private krbSessionKey: KrbCrypto.Key | null = null;
  private ntlmVersion: NTLM_VERSION;
  private messageID = 1;
  private recvBuf: Buffer = Buffer.alloc(0);

  constructor(opts: LDAPConnectionOptions) {
    this.baseDN = opts.baseDN ?? '';
    this.dstIp = opts.dstIp;
    this.signing = opts.signing ?? true;
    this.ntlmVersion = new NTLM_VERSION();
    this.ntlmVersion.set('ProductMajorVersion', 10);
    this.ntlmVersion.set('ProductMinorVersion', 0);
    this.ntlmVersion.set('ProductBuild', 19041);
    this.ntlmVersion.set('NTLMRevisionCurrent', 0x0f);

    let url = opts.url;
    if (url.startsWith('ldap://')) {
      this.dstPort = 389;
      this.ssl = false;
      this.dstHost = url.slice(7);
    } else if (url.startsWith('ldaps://')) {
      this.dstPort = 636;
      this.ssl = true;
      this.signing = false;
      this.dstHost = url.slice(8);
    } else if (url.startsWith('gc://')) {
      this.dstPort = 3268;
      this.ssl = false;
      this.signing = false;
      this.dstHost = url.slice(5);
    } else {
      throw new LDAPSessionError({ errorString: `Unknown URL prefix: '${url}'` });
    }
  }

  async connect(): Promise<void> {
    const targetHost = this.dstIp ?? this.dstHost;
    if (getGlobalProxy()) {
      if (this.ssl) {
        const sock = await createTlsSocket(targetHost, this.dstPort, {
          rejectUnauthorized: false,
          ciphers: 'ALL:@SECLEVEL=0',
        }) as TLSSocket;
        sock.setNoDelay(true);
        this.socket = sock;
        const cert = sock.getPeerCertificate();
        if (cert && cert.raw) {
          const peerCertDigest = createHash('sha256').update(Buffer.from(cert.raw)).digest();
          const applicationDataRaw = Buffer.concat([
            Buffer.from('tls-server-end-point:', 'ascii'),
            peerCertDigest,
          ]);
          const lenAppData = Buffer.alloc(4);
          lenAppData.writeUInt32LE(applicationDataRaw.length, 0);
          const channelBindingStruct = Buffer.concat([
            Buffer.alloc(8, 0),
            Buffer.alloc(8, 0),
            lenAppData,
            applicationDataRaw,
          ]);
          this.channelBindingValue = createHash('md5')
            .update(Buffer.from(channelBindingStruct))
            .digest();
        }
      } else {
        const sock = await createSocket(targetHost, this.dstPort);
        sock.setNoDelay(true);
        this.socket = sock;
      }
      return;
    }
    return new Promise((resolve, reject) => {
      if (this.ssl) {
        const sock = tlsConnect(this.dstPort, targetHost, {
          rejectUnauthorized: false,
          ciphers: 'ALL:@SECLEVEL=0',
        });
        sock.setNoDelay(true);
        this.socket = sock;
        sock.once('secureConnect', () => {
          const cert = sock.getPeerCertificate();
          if (cert && cert.raw) {
            const peerCertDigest = createHash('sha256').update(Buffer.from(cert.raw)).digest();
            const applicationDataRaw = Buffer.concat([
              Buffer.from('tls-server-end-point:', 'ascii'),
              peerCertDigest,
            ]);
            const lenAppData = Buffer.alloc(4);
            lenAppData.writeUInt32LE(applicationDataRaw.length, 0);
            const channelBindingStruct = Buffer.concat([
              Buffer.alloc(8, 0),
              Buffer.alloc(8, 0),
              lenAppData,
              applicationDataRaw,
            ]);
            this.channelBindingValue = createHash('md5')
              .update(Buffer.from(channelBindingStruct))
              .digest();
          }
          resolve();
        });
        sock.once('error', reject);
      } else {
        const sock = netConnect(this.dstPort, targetHost);
        sock.setNoDelay(true);
        this.socket = sock;
        sock.once('connect', resolve);
        sock.once('error', reject);
      }
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }

  private parseHash(hash: string | Buffer): Buffer {
    if (Buffer.isBuffer(hash)) return hash;
    if (hash === '') return Buffer.alloc(0);
    let h = hash;
    if (h.length % 2) h = `0${h}`;
    return Buffer.from(h, 'hex');
  }

  async login(opts: LoginOptions = {}): Promise<boolean> {
    const user = opts.user ?? '';
    const password = opts.password ?? '';
    const domain = opts.domain ?? '';
    const lmhash = this.parseHash(opts.lmhash ?? '');
    const nthash = this.parseHash(opts.nthash ?? '');
    const authChoice = opts.authenticationChoice ?? 'sasl';

    if (authChoice === 'simple') {
      const bindReq: BindRequest = {
        version: 3,
        name: domain.includes('.') ? `${user}@${domain}` : domain ? `${domain}\\${user}` : user,
        authentication: { simple: Buffer.from(password, 'utf8') },
      };
      const resp = await this.sendReceive(encodeBindRequest(bindReq));
      const bindResp = decodeBindResponse(resp.protocolOpValue);
      if (bindResp.resultCode !== ResultCode.success) {
        throw new LDAPSessionError({
          error: bindResp.resultCode,
          errorString: `Error in bindRequest -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
        });
      }
      this.authType = 'NTLM-simple';
      this.bound = true;
      return true;
    }

    if (authChoice === 'sicilyPackageDiscovery') {
      const bindReq: BindRequest = {
        version: 3,
        name: user,
        authentication: { sicilyPackageDiscovery: Buffer.alloc(0) },
      };
      await this.sendReceive(encodeBindRequest(bindReq));
      const bindReq2: BindRequest = {
        version: 3,
        name: user,
        authentication: { sicilyNegotiate: this.buildSicilyNegotiate(domain) },
      };
      const resp = await this.sendReceive(encodeBindRequest(bindReq2));
      const bindResp = decodeBindResponse(resp.protocolOpValue);
      if (bindResp.resultCode !== ResultCode.success) {
        throw new LDAPSessionError({
          error: bindResp.resultCode,
          errorString: `Error in bindRequest -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
        });
      }
      this.authType = 'NTLM-sicilyNegotiate';
      this.bound = true;
      return true;
    }

    if (authChoice === 'sicilyNegotiate') {
      const negotiate = getNTLMSSPType1('', domain);
      const bindReq: BindRequest = {
        version: 3,
        name: user,
        authentication: { sicilyNegotiate: negotiate.getData() },
      };
      let resp = await this.sendReceive(encodeBindRequest(bindReq));
      let bindResp = decodeBindResponse(resp.protocolOpValue);
      if (bindResp.resultCode !== ResultCode.success) {
        throw new LDAPSessionError({
          error: bindResp.resultCode,
          errorString: `Error in bindRequest during the NTLMAuthNegotiate request -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
        });
      }
      const type2 = Buffer.from(bindResp.matchedDN, 'latin1');
      let cbv = Buffer.alloc(0);
      if (this.ssl && this.channelBindingValue !== null) {
        cbv = Buffer.from(this.channelBindingValue);
      }
      const [type3, exportedSessionKey] = getNTLMSSPType3(
        negotiate,
        type2,
        user,
        password,
        domain,
        lmhash,
        nthash,
        true,
        cbv,
      );
      const bindReq2: BindRequest = {
        version: 3,
        name: user,
        authentication: { sicilyResponse: type3.getData() },
      };
      resp = await this.sendReceive(encodeBindRequest(bindReq2));
      bindResp = decodeBindResponse(resp.protocolOpValue);
      if (bindResp.resultCode !== ResultCode.success) {
        throw new LDAPSessionError({
          error: bindResp.resultCode,
          errorString: `Error in bindRequest -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
        });
      }
      this.authType = 'NTLM-sicilyNegotiate';
      this.bound = true;
      return true;
    }

    if (authChoice === 'sasl') {
      const negotiate = getNTLMSSPType1('', domain, this.signing, true, this.ntlmVersion.getData());
      const spnegoInit = new SPNEGO_NegTokenInit();
      spnegoInit.mechTypeOids = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']!];
      spnegoInit.fields['MechToken'] = negotiate.getData();

      const auth: AuthenticationChoice = {
        sasl: { mechanism: 'GSS-SPNEGO', credentials: spnegoInit.getData() },
      };
      const bindReq: BindRequest = { version: 3, name: '', authentication: auth };
      let resp = await this.sendReceive(encodeBindRequest(bindReq));
      let bindResp = decodeBindResponse(resp.protocolOpValue);
      if (bindResp.resultCode !== ResultCode.saslBindInProgress) {
        throw new LDAPSessionError({
          error: bindResp.resultCode,
          errorString: `Error in bindRequest during the NTLMAuthNegotiate request -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
        });
      }

      const serverSaslCreds = bindResp.serverSaslCreds ?? Buffer.alloc(0);
      const spnegoResp = new SPNEGO_NegTokenResp(serverSaslCreds);
      const type2 = Buffer.from(spnegoResp.fields['ResponseToken'] ?? Buffer.alloc(0));

      let cbv = Buffer.alloc(0);
      if (this.ssl && this.channelBindingValue !== null) {
        cbv = Buffer.from(this.channelBindingValue);
      }
      const [type3, exportedSessionKey] = getNTLMSSPType3(
        negotiate,
        type2,
        user,
        password,
        domain,
        lmhash,
        nthash,
        true,
        cbv,
        'ldap',
        this.ntlmVersion.getData(),
      );

      const newmic = hmacMd5(
        exportedSessionKey,
        Buffer.concat([
          negotiate.getData(),
          new NTLMAuthChallenge(type2).getData(),
          type3.getData(),
        ]),
      );
      type3.set('MIC', newmic);

      const spnegoResp2 = new SPNEGO_NegTokenResp();
      spnegoResp2.fields['ResponseToken'] = type3.getData();
      if (this.signing) {
        this.spnegoCipherBlob = new SPNEGOCipher(
          Number(negotiate.get('flags')),
          exportedSessionKey,
        );
        const mechListMIC = this.spnegoCipherBlob.sign(
          Buffer.from('300c060a2b06010401823702020a', 'hex'),
          0,
          true,
        );
        spnegoResp2.fields['mechListMIC'] = mechListMIC.getData();
      }

      const auth2: AuthenticationChoice = {
        sasl: { mechanism: 'GSS-SPNEGO', credentials: spnegoResp2.getData() },
      };
      const bindReq2: BindRequest = { version: 3, name: '', authentication: auth2 };
      resp = await this.sendReceive(encodeBindRequest(bindReq2));
      bindResp = decodeBindResponse(resp.protocolOpValue);
      if (bindResp.resultCode !== ResultCode.success) {
        throw new LDAPSessionError({
          error: bindResp.resultCode,
          errorString: `Error in bindRequest -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
        });
      }
      this.authType = 'NTLM-sasl';
      this.bound = true;
      return true;
    }

    throw new LDAPSessionError({ errorString: `Unknown authenticationChoice: '${authChoice}'` });
  }

  async kerberosLogin(opts: {
    user?: string;
    password?: string;
    domain?: string;
    lmhash?: string;
    nthash?: string;
    aesKey?: string;
    kdcHost?: string | null;
    tgt?: KerberosV5.TGTResult | null;
    tgs?: KerberosV5.TGSResult | null;
  } = {}): Promise<boolean> {
    const user = opts.user ?? '';
    const password = opts.password ?? '';
    const domain = opts.domain ?? '';
    const lmhash = opts.lmhash ?? '';
    const nthash = opts.nthash ?? '';
    const aesKey = opts.aesKey ?? '';
    const kdcHost = opts.kdcHost ?? null;
    let tgt = opts.tgt ?? null;
    let tgs = opts.tgs ?? null;

    const targetName = `ldap/${this.dstHost}`;
    const userName = new KrbTypes.Principal(
      user,
      null,
      KrbConstants.PrincipalNameType.NT_PRINCIPAL,
    );

    let cipher: KrbCrypto.EnctypeProfile;
    let sessionKey: KrbCrypto.Key;

    if (tgs === null) {
      if (tgt === null) {
        const tgtResult = await KerberosV5.getKerberosTGT(
          userName, password, domain, lmhash, nthash, aesKey, kdcHost,
        );
        tgt = tgtResult;
      }

      const serverName = new KrbTypes.Principal(
        targetName,
        null,
        KrbConstants.PrincipalNameType.NT_SRV_INST,
      );
      const tgsResult = await KerberosV5.getKerberosTGS(
        serverName, domain.toUpperCase(), kdcHost,
        tgt.tgt, tgt.cipher, tgt.sessionKey,
      );
      cipher = tgsResult.cipher;
      sessionKey = tgsResult.sessionKey;
      tgs = tgsResult;
    } else {
      cipher = tgs.cipher;
      sessionKey = tgs.sessionKey;
    }

    const blob = new SPNEGO_NegTokenInit();
    blob.mechTypeOids = [TypesMech['MS KRB5 - Microsoft Kerberos 5']!];

    const ticketNode = KrbAsn1.Ticket();
    ticketNode._rawData = KerberosV5.extractRawTicket(tgs.tgs);

    const apReq = KrbAsn1.AP_REQ();
    apReq.set('pvno', 5);
    apReq.set('msg-type', KrbConstants.ApplicationTagNumbers.AP_REQ);
    KrbAsn1.seqSetFlags(apReq, 'ap-options', []);
    apReq.set('ticket', ticketNode);

    const authenticator = KrbAsn1.Authenticator();
    authenticator.set('authenticator-vno', 5);
    authenticator.set('crealm', domain.toUpperCase());
    authenticator.set('cname', KerberosV5.buildPrincipalName(userName.type, userName.components));

    const now = new Date();
    authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
    authenticator.set('ctime', now);

    const chkField = new KrbGSSAPI.CheckSumField();
    chkField.Lgth = 16;
    chkField.Flags = KrbGSSAPI.GSS_C_SEQUENCE_FLAG | KrbGSSAPI.GSS_C_REPLAY_FLAG;

    if (this.ssl && this.channelBindingValue !== null) {
      chkField.Bnd = this.channelBindingValue;
    }
    if (this.signing) {
      chkField.Flags |= KrbGSSAPI.GSS_C_CONF_FLAG | KrbGSSAPI.GSS_C_INTEG_FLAG;
    }

    const cksum = KrbAsn1.Checksum();
    cksum.set('cksumtype', 0x8003);
    cksum.set('checksum', chkField.getData());
    authenticator.set('cksum', cksum);
    authenticator.set('seq-number', 0);

    const encodedAuthenticator = authenticator.encode();
    const encryptedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, null);

    const apReqEncPart = KrbAsn1.EncryptedData();
    apReqEncPart.set('etype', cipher.enctype);
    apReqEncPart.set('cipher', encryptedAuthenticator);
    apReq.set('authenticator', apReqEncPart);

    blob.fields['MechToken'] = apReq.encode();

    const auth: AuthenticationChoice = {
      sasl: { mechanism: 'GSS-SPNEGO', credentials: blob.getData() },
    };
    const bindReq: BindRequest = { version: 3, name: '', authentication: auth };
    const resp = await this.sendReceive(encodeBindRequest(bindReq));
    const bindResp = decodeBindResponse(resp.protocolOpValue);
    if (bindResp.resultCode !== ResultCode.success) {
      throw new LDAPSessionError({
        error: bindResp.resultCode,
        errorString: `Error in bindRequest -> ${bindResp.resultCode}: ${bindResp.diagnosticMessage}`,
      });
    }

    this.authType = 'KRB5';
    this.bound = true;

    if (this.signing) {
      this.krbSessionKey = sessionKey;
      this.gssapiCipher = KrbGSSAPI.GSSAPI(cipher);
    }

    return true;
  }

  private buildSicilyNegotiate(domain: string): Buffer {
    const negotiate = getNTLMSSPType1('', domain);
    return negotiate.getData();
  }

  private encrypt(data: Buffer): Buffer {
    if (this.authType === 'NTLM-sasl' && this.spnegoCipherBlob) {
      const [signature, encrypted] = this.spnegoCipherBlob.encrypt(data);
      const sigAndData = Buffer.concat([signature.getData(), encrypted]);
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(sigAndData.length, 0);
      return Buffer.concat([lenBuf, sigAndData]);
    }
    if (this.authType === 'KRB5' && this.gssapiCipher && this.krbSessionKey) {
      const [authData, encrypted] = this.gssapiCipher.GSS_Wrap(
        this.krbSessionKey, data, this.sequenceNumber, 'init',
      );
      const payload = Buffer.concat([authData, encrypted]);
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(payload.length, 0);
      return Buffer.concat([lenBuf, payload]);
    }
    throw new Error(`Encryption not implemented for ${this.authType} protocol`);
  }

  private decrypt(data: Buffer): Buffer {
    if (this.authType === 'NTLM-sasl' && this.spnegoCipherBlob) {
      const payload = data.subarray(4);
      const [, decrypted] = this.spnegoCipherBlob.decrypt(payload);
      return decrypted;
    }
    if (this.authType === 'KRB5' && this.gssapiCipher && this.krbSessionKey) {
      const payload = data.subarray(4);
      const [, decrypted] = this.gssapiCipher.GSS_Unwrap(
        this.krbSessionKey, payload, this.sequenceNumber, 'accept',
      );
      return decrypted;
    }
    throw new Error(`Decryption not implemented for ${this.authType} protocol`);
  }

  send(request: Buffer, controls: LdapControl[] | null = null): void {
    const messageID = this.messageID++;
    const data = encodeLDAPMessage(messageID, request, controls);
    if (this.bound && this.signing && (this.spnegoCipherBlob || this.gssapiCipher)) {
      const encrypted = this.encrypt(data);
      this.sequenceNumber += 1;
      this.socket?.write(encrypted);
    } else {
      this.socket?.write(data);
    }
  }

  private recvRaw(): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new Error('Socket not connected'));
        return;
      }
      const chunks: Buffer[] = [];
      const onData = (chunk: Buffer) => {
        chunks.push(chunk);
        const totalLen = Buffer.concat(chunks).length;
        if (totalLen >= 4) {
          const buf = Buffer.concat(chunks);
          const expectedLen = buf.readUInt32BE(0) + 4;
          if (buf.length >= expectedLen) {
            this.socket?.removeListener('data', onData);
            this.socket?.removeListener('error', onErr);
            resolve(buf);
          }
        }
      };
      const onErr = (err: Error) => {
        this.socket?.removeListener('data', onData);
        this.socket?.removeListener('error', onErr);
        reject(err);
      };
      this.socket.on('data', onData);
      this.socket.on('error', onErr);
    });
  }

  private parseBerLength(buf: Buffer): { totalNeeded: number } | null {
    if (buf.length < 2) return null;
    const firstLenByte = buf[1]!;
    let msgLen: number;
    let lenBytes: number;
    if (firstLenByte < 0x80) {
      msgLen = firstLenByte;
      lenBytes = 1;
    } else if (firstLenByte === 0x80) {
      throw new Error('DER indefinite length not supported');
    } else {
      lenBytes = (firstLenByte & 0x7f) + 1;
      if (buf.length < 1 + lenBytes) return null;
      msgLen = 0;
      for (let i = 1; i < lenBytes; i++) {
        msgLen = (msgLen << 8) | buf[1 + i]!;
      }
    }
    return { totalNeeded: 1 + lenBytes + msgLen };
  }

  async recvRawUnencrypted(): Promise<Buffer> {
    const parsed = this.parseBerLength(this.recvBuf);
    if (parsed && this.recvBuf.length >= parsed.totalNeeded) {
      const msg = this.recvBuf.subarray(0, parsed.totalNeeded);
      this.recvBuf = this.recvBuf.subarray(parsed.totalNeeded);
      return msg;
    }

    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new Error('Socket not connected'));
        return;
      }
      const chunks: Buffer[] = [this.recvBuf];
      this.recvBuf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        chunks.push(chunk);
        const buf = Buffer.concat(chunks);
        try {
          const p = this.parseBerLength(buf);
          if (!p) return;
          if (buf.length >= p.totalNeeded) {
            this.socket?.removeListener('data', onData);
            this.socket?.removeListener('error', onErr);
            this.recvBuf = buf.subarray(p.totalNeeded);
            resolve(buf.subarray(0, p.totalNeeded));
          }
        } catch (e) {
          this.socket?.removeListener('data', onData);
          this.socket?.removeListener('error', onErr);
          reject(e);
        }
      };
      const onErr = (err: Error) => {
        this.socket?.removeListener('data', onData);
        this.socket?.removeListener('error', onErr);
        reject(err);
      };
      this.socket.on('data', onData);
      this.socket.on('error', onErr);
    });
  }

  async recv(): Promise<ReturnType<typeof decodeLDAPMessage>[]> {
    let data: Buffer;
    if (this.bound && this.signing && (this.spnegoCipherBlob || this.gssapiCipher)) {
      data = await this.recvRaw();
      data = this.decrypt(data);
    } else {
      data = await this.recvRawUnencrypted();
    }

    const messages: ReturnType<typeof decodeLDAPMessage>[] = [];
    let remaining = data;
    while (remaining.length > 0) {
      const msg = decodeLDAPMessage(remaining);
      messages.push(msg);
      remaining = msg.remaining;
    }

    for (const message of messages) {
      if (message.messageID === 0) {
        const extResp = decodeExtendedResponse(message.protocolOpValue);
        const name = extResp.responseName ?? '';
        const notification = KNOWN_NOTIFICATIONS[name] ?? `Unsolicited Notification '${name}'`;
        if (name === NOTIFICATION_DISCONNECT) {
          this.close();
        }
        throw new LDAPSessionError({
          error: extResp.resultCode,
          errorString: `${notification} -> ${extResp.resultCode}: ${extResp.diagnosticMessage}`,
        });
      }
    }

    return messages;
  }

  async sendReceive(
    request: Buffer,
    controls: LdapControl[] | null = null,
  ): Promise<ReturnType<typeof decodeLDAPMessage>> {
    this.send(request, controls);
    const resp = await this.recv();
    return resp[0]!;
  }

  async search(
    opts: {
      searchBase?: string;
      scope?: Scope;
      derefAliases?: DerefAliases;
      sizeLimit?: number;
      timeLimit?: number;
      typesOnly?: boolean;
      searchFilter?: string;
      attributes?: string[];
      searchControls?: LdapControl[];
      perRecordCallback?: (entry: SearchResultEntry) => void;
    } = {},
  ): Promise<SearchResultEntry[]> {
    const searchBase = opts.searchBase ?? this.baseDN;
    const scope = opts.scope ?? Scope.wholeSubtree;
    const derefAliases = opts.derefAliases ?? DerefAliases.neverDerefAliases;
    const sizeLimit = opts.sizeLimit ?? 0;
    const timeLimit = opts.timeLimit ?? 0;
    const typesOnly = opts.typesOnly ?? false;
    const searchFilter = opts.searchFilter ?? '(objectClass=*)';
    const attributes = opts.attributes ?? [];
    const searchControls = opts.searchControls ?? null;

    if (typeof searchFilter !== 'string') {
      throw new LDAPFilterInvalidException('searchFilter must be a string');
    }

    const filter = this.parseFilter(searchFilter);
    const searchReq: SearchRequest = {
      baseObject: searchBase,
      scope,
      derefAliases,
      sizeLimit,
      timeLimit,
      typesOnly,
      filter,
      attributes,
    };

    const answers: SearchResultEntry[] = [];
    let done = false;
    while (!done) {
      this.send(encodeSearchRequest(searchReq), searchControls);
      let gotDone = false;
      while (!gotDone) {
        const response = await this.recv();
        for (const message of response) {
          if (
            message.protocolOpTag === ProtocolOpTag.searchResDone &&
            message.protocolOpCls === 0x40
          ) {
            const result = decodeBindResponse(message.protocolOpValue);
            if (result.resultCode === ResultCode.success || result.resultCode === ResultCode.sizeLimitExceeded) {
              done = this.handleControls(searchControls, message.controls);
            } else {
              throw new LDAPSearchError({
                error: result.resultCode,
                errorString: `Error in searchRequest -> ${result.resultCode}: ${result.diagnosticMessage}`,
                answers,
              });
            }
            gotDone = true;
          } else if (
            message.protocolOpTag === ProtocolOpTag.searchResEntry &&
            message.protocolOpCls === 0x40
          ) {
            const entry = decodeSearchResultEntry(message.protocolOpValue);
            if (opts.perRecordCallback) {
              opts.perRecordCallback(entry);
            } else {
              answers.push(entry);
            }
          }
        }
      }
    }
    return answers;
  }

  private handleControls(
    requestControls: LdapControl[] | null,
    responseControls: LdapControl[] | null,
  ): boolean {
    let done = true;
    if (requestControls !== null) {
      for (const requestControl of requestControls) {
        if (responseControls !== null) {
          for (const responseControl of responseControls) {
            if (requestControl.controlType === CONTROL_PAGEDRESULTS) {
              if (responseControl.controlType === CONTROL_PAGEDRESULTS) {
                const decoded = decodeSimplePagedResultsControlValue(
                  responseControl.controlValue ?? Buffer.alloc(0),
                );
                if (decoded.cookie.length > 0) {
                  done = false;
                }
                const newCtrl = createSimplePagedResultsControl(decoded.size, decoded.cookie);
                requestControl.controlValue = newCtrl.controlValue;
                break;
              }
            }
          }
        }
      }
    }
    return done;
  }

  parseFilter(filterStr: string): Filter {
    const filterList = [...filterStr].reverse();
    const searchFilter = this.consumeCompositeFilter(filterList);
    if (filterList.length > 0) {
      throw new LDAPFilterSyntaxError(`unexpected token: '${filterList[filterList.length - 1]}'`);
    }
    return searchFilter;
  }

  private consumeCompositeFilter(filterList: string[]): Filter {
    let c = filterList.pop();
    if (c === undefined) throw new LDAPFilterSyntaxError('EOL while parsing search filter');
    if (c !== '(') {
      filterList.push(c);
      throw new LDAPFilterSyntaxError(`unexpected token: '${c}'`);
    }
    const operator = filterList.pop();
    if (operator === undefined) throw new LDAPFilterSyntaxError('EOL while parsing search filter');
    if (operator !== '!' && operator !== '&' && operator !== '|') {
      filterList.push(operator);
      filterList.push(c);
      return this.consumeSimpleFilter(filterList);
    }
    const filters: Filter[] = [];
    while (true) {
      try {
        filters.push(this.consumeCompositeFilter(filterList));
      } catch (e) {
        if (e instanceof LDAPFilterSyntaxError) break;
        throw e;
      }
    }
    c = filterList.pop();
    if (c === undefined) throw new LDAPFilterSyntaxError('EOL while parsing search filter');
    if (c !== ')') {
      filterList.push(c);
      throw new LDAPFilterSyntaxError(`unexpected token: '${c}'`);
    }
    return this.compileCompositeFilter(operator, filters);
  }

  private consumeSimpleFilter(filterList: string[]): Filter {
    let c = filterList.pop();
    if (c === undefined) throw new LDAPFilterSyntaxError('EOL while parsing search filter');
    if (c !== '(') {
      filterList.push(c);
      throw new LDAPFilterSyntaxError(`unexpected token: '${c}'`);
    }
    const filterChars: string[] = [];
    while (true) {
      c = filterList.pop();
      if (c === undefined) throw new LDAPFilterSyntaxError('EOL while parsing search filter');
      if (c === ')') break;
      if (c === '(') {
        filterList.push(c);
        throw new LDAPFilterSyntaxError("unexpected token: '('");
      }
      filterChars.push(c);
    }
    const filterStr = filterChars.join('');
    const parts = filterStr.split(RE_OPERATOR);
    if (parts.length < 3) {
      throw new LDAPFilterInvalidException(`invalid filter: '(${filterStr})'`);
    }
    const attribute = parts[0]!;
    const operator = parts[1]!;
    const value = parts[2] ?? '';
    return this.compileSimpleFilter(attribute, operator, value);
  }

  private compileCompositeFilter(operator: string, filters: Filter[]): Filter {
    if (operator === '!') {
      if (filters.length !== 1) {
        throw new LDAPFilterInvalidException("'not' filter must have exactly one element");
      }
      return { not: [filters[0]!] };
    }
    if (operator === '&') {
      if (filters.length === 0) {
        throw new LDAPFilterInvalidException("'and' filter must have at least one element");
      }
      return { and: filters };
    }
    if (filters.length === 0) {
      throw new LDAPFilterInvalidException("'or' filter must have at least one element");
    }
    return { or: filters };
  }

  private compileSimpleFilter(attribute: string, operator: string, value: string): Filter {
    if (operator === ':=') {
      const match = RE_EX_ATTRIBUTE_1.exec(attribute) ?? RE_EX_ATTRIBUTE_2.exec(attribute);
      if (!match) {
        throw new LDAPFilterInvalidException(`invalid filter attribute: '${attribute}'`);
      }
      const attr = match[1] ?? '';
      const dn = match[2];
      const matchingRule = match[3];
      const extMatch: {
        matchingRule?: string;
        type?: string;
        matchValue: string;
        dnAttributes: boolean;
      } = {
        matchValue: LDAPConnection.processLdapString(value),
        dnAttributes: dn !== undefined,
      };
      if (attr) extMatch.type = attr;
      if (matchingRule) extMatch.matchingRule = matchingRule;
      return { extensibleMatch: extMatch };
    }

    if (!RE_ATTRIBUTE.test(attribute)) {
      throw new LDAPFilterInvalidException(`invalid filter attribute: '${attribute}'`);
    }
    if (value === '*' && operator === '=') {
      return { present: attribute };
    }
    if (value.includes('*') && operator === '=') {
      const assertions = value.split('*').map((a) => LDAPConnection.processLdapString(a));
      const substrings: Substring[] = [];
      if (assertions[0]) substrings.push({ initial: assertions[0]! });
      for (let i = 1; i < assertions.length - 1; i++) {
        substrings.push({ any: assertions[i]! });
      }
      if (assertions[assertions.length - 1]) {
        substrings.push({ final: assertions[assertions.length - 1]! });
      }
      return { substrings: { type: attribute, substrings } };
    }
    if (!value.includes('*')) {
      const v = LDAPConnection.processLdapString(value);
      if (operator === '=')
        return { equalityMatch: { attributeDesc: attribute, assertionValue: v } };
      if (operator === '~=')
        return { approxMatch: { attributeDesc: attribute, assertionValue: v } };
      if (operator === '>=')
        return { greaterOrEqual: { attributeDesc: attribute, assertionValue: v } };
      if (operator === '<=')
        return { lessOrEqual: { attributeDesc: attribute, assertionValue: v } };
    }
    throw new LDAPFilterInvalidException(`invalid filter '(${attribute}${operator}${value})'`);
  }

  private static processLdapString(ldapstr: string): string {
    return ldapstr.replace(/\\([0-9a-fA-F]{2})/g, (_m, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
  }

  async modify(
    dn: string,
    changes: ModifyChange[],
    controls: LdapControl[] | null = null,
  ): Promise<LDAPResult> {
    const req: ModifyRequest = { object: dn, changes };
    const resp = await this.sendReceive(encodeModifyRequest(req), controls);
    const result = decodeLDAPResult(resp.protocolOpValue);
    if (result.resultCode !== ResultCode.success) {
      throw new LDAPSessionError({
        error: result.resultCode,
        errorString: `Error in modifyRequest -> ${result.resultCode}: ${result.diagnosticMessage}`,
      });
    }
    return result;
  }

  async add(
    dn: string,
    attributes: Attribute[],
    controls: LdapControl[] | null = null,
  ): Promise<LDAPResult> {
    const req: AddRequest = { entry: dn, attributes };
    const resp = await this.sendReceive(encodeAddRequest(req), controls);
    const result = decodeLDAPResult(resp.protocolOpValue);
    if (result.resultCode !== ResultCode.success) {
      throw new LDAPSessionError({
        error: result.resultCode,
        errorString: `Error in addRequest -> ${result.resultCode}: ${result.diagnosticMessage}`,
      });
    }
    return result;
  }

  async delete(
    dn: string,
    controls: LdapControl[] | null = null,
  ): Promise<LDAPResult> {
    const resp = await this.sendReceive(encodeDelRequest(dn), controls);
    const result = decodeLDAPResult(resp.protocolOpValue);
    if (result.resultCode !== ResultCode.success) {
      throw new LDAPSessionError({
        error: result.resultCode,
        errorString: `Error in delRequest -> ${result.resultCode}: ${result.diagnosticMessage}`,
      });
    }
    return result;
  }

  async modifyDN(
    dn: string,
    newRDN: string,
    deleteOldRDN: boolean = true,
    newSuperior?: string,
    controls: LdapControl[] | null = null,
  ): Promise<LDAPResult> {
    const req: ModifyDNRequest = {
      entry: dn,
      newrdn: newRDN,
      deleteoldrdn: deleteOldRDN,
      newSuperior,
    };
    const resp = await this.sendReceive(encodeModifyDNRequest(req), controls);
    const result = decodeLDAPResult(resp.protocolOpValue);
    if (result.resultCode !== ResultCode.success) {
      throw new LDAPSessionError({
        error: result.resultCode,
        errorString: `Error in modifyDNRequest -> ${result.resultCode}: ${result.diagnosticMessage}`,
      });
    }
    return result;
  }

  async compare(
    dn: string,
    attribute: string,
    value: string | Buffer,
    controls: LdapControl[] | null = null,
  ): Promise<boolean> {
    const req: CompareRequest = {
      entry: dn,
      ava: { attributeDesc: attribute, assertionValue: value },
    };
    const resp = await this.sendReceive(encodeCompareRequest(req), controls);
    const result = decodeLDAPResult(resp.protocolOpValue);
    if (result.resultCode === 6) return true; // compareTrue
    if (result.resultCode === 5) return false; // compareFalse
    throw new LDAPSessionError({
      error: result.resultCode,
      errorString: `Error in compareRequest -> ${result.resultCode}: ${result.diagnosticMessage}`,
    });
  }

  async unbind(): Promise<void> {
    this.send(encodeUnbindRequest());
    this.close();
  }

  async abandon(messageID: number): Promise<void> {
    this.send(encodeAbandonRequest(messageID));
  }
}
