import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { Socket } from 'node:net';
import { getGlobalProxy, createSocket as socksCreateSocket } from '@impacket/socks';
import { type AnyValue, type Asn1Sequence, Asn1SequenceOf, parseTLV, parseTLVs, TagClass } from '@impacket/asn1';
import {
  SPNEGO_NegTokenInit,
  SPNEGO_NegTokenResp,
  TypesMech,
  ASN1_AID,
  ASN1_OID,
  asn1encode,
} from '@impacket/spnego';
import * as asn1 from './asn1.js';
import { CCache } from './ccache.js';
import * as constants from './constants.js';
import * as crypto from './crypto.js';
import * as gssapi from './gssapi.js';
import * as types from './types.js';

export class KerberosError extends Error {
  error = 0;
  packet: Record<string, AnyValue> | null = null;

  constructor(opts?: { error?: number; packet?: Record<string, AnyValue> | null }) {
    super();
    if (opts) {
      this.error = opts.error ?? 0;
      this.packet = opts.packet ?? null;
    }
    if (this.packet !== null) {
      const ec = this.packet['error-code'];
      if (ec !== undefined) this.error = Number(ec);
    }
    const [code, msg] = this.getErrorString();
    this.message = `Kerberos SessionError: ${code}(${this.error}) - ${msg}`;
  }

  getErrorCode(): number {
    return this.error;
  }

  getErrorPacket(): Record<string, AnyValue> | null {
    return this.packet;
  }

  getErrorString(): [string, string] {
    return constants.ERROR_MESSAGES[this.error] ?? ['UNKNOWN', `Unknown error code ${this.error}`];
  }

  toString(): string {
    const [code, msg] = this.getErrorString();
    return `Kerberos SessionError: ${code}(${msg})`;
  }
}

export class SessionKeyDecryptionError extends Error {
  message: string;
  asRep: Record<string, AnyValue>;
  cipher: crypto.EnctypeProfile;
  key: crypto.Key;
  cipherText: Buffer;

  constructor(
    message: string,
    asRep: Record<string, AnyValue>,
    cipher: crypto.EnctypeProfile,
    key: crypto.Key,
    cipherText: Buffer,
  ) {
    super(message);
    this.message = message;
    this.asRep = asRep;
    this.cipher = cipher;
    this.key = key;
    this.cipherText = cipherText;
  }

  toString(): string {
    return `SessionKeyDecryptionError: ${this.message}`;
  }
}

export async function sendReceive(
  data: Buffer,
  host: string,
  kdcHost: string | null,
  port = 88,
): Promise<Buffer> {
  const targetHost = kdcHost ?? host;

  let sock: Socket;
  if (getGlobalProxy()) {
    sock = await socksCreateSocket(targetHost, port);
  } else {
    sock = new Socket();
    sock.setNoDelay(true);
    await new Promise<void>((resolve, reject) => {
      sock.connect(port, targetHost, () => resolve());
      sock.once('error', reject);
    });
  }

  const lenBuf = Buffer.alloc(4);
  lenBuf.writeInt32BE(data.length, 0);
  sock.write(Buffer.concat([lenBuf, data]));

  return new Promise((resolve, reject) => {
    let response = Buffer.alloc(0);
    let expectedLen = -1;

    sock.on('data', (chunk: Buffer) => {
      response = Buffer.concat([response, chunk]);
      if (expectedLen === -1 && response.length >= 4) {
        expectedLen = response.readInt32BE(0);
      }
      if (expectedLen !== -1 && response.length >= expectedLen + 4) {
        sock.destroy();
        resolve(response.subarray(4, 4 + expectedLen));
      }
    });

    sock.on('error', (err) => {
      reject(new Error(`Connection error (${targetHost}:${port}) ${err.message}`));
    });

    sock.on('close', () => {
      if (expectedLen === -1 || response.length < expectedLen + 4) {
        reject(
          new Error(
            `Connection closed prematurely (got ${response.length - 4} of ${expectedLen} bytes)`,
          ),
        );
      }
    });
  });
}

export function buildPrincipalName(type: number, components: string[]): Asn1Sequence {
  return asn1.principalToAsn1({ type, components });
}

export function extractRawTicket(kdcRepBytes: Buffer): Buffer {
  let tlv = parseTLV(kdcRepBytes);
  // Unwrap APPLICATION tag (AS-REP=11, TGS-REP=13)
  if (tlv.cls === TagClass.APPLICATION) tlv = parseTLV(tlv.value);
  // Now inside the SEQUENCE, find context [5] (ticket)
  const inner = parseTLVs(tlv.value);
  for (const t of inner) {
    if (t.cls === TagClass.CONTEXT && t.tag === 5) {
      return t.value;
    }
  }
  throw new Error('Ticket not found in KDC-REP');
}

function encodeAsReq(
  clientName: types.Principal,
  serverName: types.Principal,
  domain: string,
  supportedCiphers: number[],
  nonce: number,
  padata: { type: number; value: Buffer }[] | null,
): Buffer {
  const asReq = asn1.AS_REQ();
  asReq.set('pvno', 5);
  asReq.set('msg-type', constants.ApplicationTagNumbers.AS_REQ);

  if (padata !== null) {
    const padataSeq = new Asn1SequenceOf(asn1.PA_DATA());
    for (const pa of padata) {
      const entry = asn1.PA_DATA();
      entry.set('padata-type', pa.type);
      entry.set('padata-value', pa.value);
      padataSeq.add(entry);
    }
    asReq.set('padata', padataSeq);
  }

  const reqBody = asn1.KDC_REQ_BODY();
  asn1.seqSetFlags(reqBody, 'kdc-options', [
    constants.KDCOptions.forwardable,
    constants.KDCOptions.renewable,
    constants.KDCOptions.proxiable,
  ]);
  reqBody.set('sname', buildPrincipalName(serverName.type, serverName.components));
  reqBody.set('cname', buildPrincipalName(clientName.type, clientName.components));
  reqBody.set('realm', domain);

  const now = new Date(Date.now() + 86400000);
  reqBody.set('till', now);
  reqBody.set('rtime', now);
  reqBody.set('nonce', nonce);

  const etypeSeq = new Asn1SequenceOf(new asn1.Int32());
  for (const c of supportedCiphers) {
    etypeSeq.add(new asn1.Int32(c));
  }
  reqBody.set('etype', etypeSeq);

  asReq.set('req-body', reqBody);
  return asReq.encode();
}

function parseETYPE_INFO2(data: Buffer): Record<number, Buffer> {
  const result: Record<number, Buffer> = {};
  const info2 = asn1.ETYPE_INFO2();
  info2.decode(data);
  for (const entry of info2.items) {
    const etype = Number((entry as unknown as { values: Record<string, AnyValue> }).values.etype);
    let salt = Buffer.alloc(0);
    const saltVal = (entry as unknown as { values: Record<string, AnyValue> }).values.salt;
    if (saltVal !== undefined && typeof saltVal === 'string') {
      salt = Buffer.from(saltVal, 'utf8');
    } else if (Buffer.isBuffer(saltVal)) {
      salt = Buffer.from(saltVal);
    }
    result[etype] = salt;
  }
  return result;
}

function parseETYPE_INFO(data: Buffer): Record<number, Buffer> {
  const result: Record<number, Buffer> = {};
  const info = asn1.ETYPE_INFO();
  info.decode(data);
  for (const entry of info.items) {
    const etype = Number((entry as unknown as { values: Record<string, AnyValue> }).values.etype);
    let salt = Buffer.alloc(0);
    const saltVal = (entry as unknown as { values: Record<string, AnyValue> }).values.salt;
    if (saltVal !== undefined && Buffer.isBuffer(saltVal)) {
      salt = Buffer.from(saltVal);
    }
    result[etype] = salt;
  }
  return result;
}

export interface TGTResult {
  tgt: Buffer;
  cipher: crypto.EnctypeProfile;
  key: crypto.Key;
  sessionKey: crypto.Key;
}

export async function getKerberosTGT(
  clientName: types.Principal,
  password: string,
  domain: string,
  lmhash: Buffer | string,
  nthash: Buffer | string,
  aesKey: Buffer | string = '',
  kdcHost: string | null = null,
  requestPAC = true,
  serverName: types.Principal | string | null = null,
  kerberoastNoPreauth = false,
): Promise<TGTResult> {
  const ccachePath = process.env['KRB5CCNAME'];
  if (ccachePath && existsSync(ccachePath)) {
    try {
      const ccache = CCache.loadFile(ccachePath);
      const upperDom = domain.toUpperCase();
      const tgtCred = ccache.getCredential(`krbtgt/${upperDom}@${upperDom}`);
      if (tgtCred) {
        const converted = tgtCred.toTGT();
        return {
          tgt: converted.data,
          cipher: converted.cipher,
          key: converted.sessionKey,
          sessionKey: converted.sessionKey,
        };
      }
    } catch {
      // ccache load failed, fall through to network request
    }
  }

  const _lmhashBuf = typeof lmhash === 'string' ? Buffer.from(lmhash, 'hex') : lmhash;
  const nthashBuf = typeof nthash === 'string' ? Buffer.from(nthash, 'hex') : nthash;
  const aesKeyBuf =
    typeof aesKey === 'string' ? (aesKey ? Buffer.from(aesKey, 'hex') : Buffer.alloc(0)) : aesKey;

  const upperDomain = domain.toUpperCase();

  let srvName: types.Principal;
  if (serverName === null) {
    srvName = new types.Principal(
      `krbtgt/${upperDomain}`,
      null,
      constants.PrincipalNameType.NT_PRINCIPAL,
    );
  } else if (serverName instanceof types.Principal) {
    srvName = serverName;
  } else {
    srvName = new types.Principal(serverName, null, constants.PrincipalNameType.NT_PRINCIPAL);
  }

  const pacRequest = asn1.KERB_PA_PAC_REQUEST();
  pacRequest.set('include-pac', requestPAC);
  const encodedPacRequest = pacRequest.encode();

  const supportedCiphers: number[] = [];
  if (nthashBuf.length > 0) {
    supportedCiphers.push(constants.EncryptionTypes.rc4_hmac);
  } else if (aesKeyBuf.length === 32) {
    supportedCiphers.push(constants.EncryptionTypes.aes256_cts_hmac_sha1_96);
  } else if (aesKeyBuf.length === 16) {
    supportedCiphers.push(constants.EncryptionTypes.aes128_cts_hmac_sha1_96);
  } else {
    supportedCiphers.push(constants.EncryptionTypes.aes256_cts_hmac_sha1_96);
  }

  const nonce = Math.floor(Math.random() * 0x7fffffff);

  const message = encodeAsReq(clientName, srvName, upperDomain, supportedCiphers, nonce, [
    { type: constants.PreAuthenticationDataTypes.PA_PAC_REQUEST, value: encodedPacRequest },
  ]);

  let r: Buffer;
  try {
    r = await sendReceive(message, upperDomain, kdcHost);
  } catch (e) {
    if (
      e instanceof KerberosError &&
      e.getErrorCode() === constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP
    ) {
      if (
        supportedCiphers[0] === constants.EncryptionTypes.aes128_cts_hmac_sha1_96 ||
        supportedCiphers[0] === constants.EncryptionTypes.aes256_cts_hmac_sha1_96
      ) {
        supportedCiphers[0] = constants.EncryptionTypes.rc4_hmac;
        const newMsg = encodeAsReq(clientName, srvName, upperDomain, supportedCiphers, nonce, [
          { type: constants.PreAuthenticationDataTypes.PA_PAC_REQUEST, value: encodedPacRequest },
        ]);
        r = await sendReceive(newMsg, upperDomain, kdcHost);
      } else {
        throw e;
      }
    } else {
      throw e;
    }
  }

  let preAuth = true;
  let asRep: Record<string, AnyValue>;
  try {
    const krbErr = asn1.KRB_ERROR();
    krbErr.decode(r);
    asRep = krbErr.values;
  } catch {
    const asRepNode = asn1.AS_REP();
    asRepNode.decode(r);
    asRep = asRepNode.values;
    preAuth = false;
  }

  let encryptionTypesData: Record<number, Buffer> = {};
  let tgt = r;

  if (!preAuth) {
    encryptionTypesData[supportedCiphers[0]!] = Buffer.alloc(0);
  } else {
    const eData = asRep['e-data'] as Buffer;
    const methodData = asn1.METHOD_DATA();
    methodData.decode(eData);
    for (const method of methodData.items) {
      const m = method as unknown as { values: Record<string, AnyValue> };
      const paType = Number(m.values['padata-type']);
      const paValue = m.values['padata-value'] as Buffer;
      if (paType === constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2) {
        encryptionTypesData = { ...encryptionTypesData, ...parseETYPE_INFO2(paValue) };
      } else if (paType === constants.PreAuthenticationDataTypes.PA_ETYPE_INFO) {
        encryptionTypesData = { ...encryptionTypesData, ...parseETYPE_INFO(paValue) };
      }
    }
  }

  const enctype = supportedCiphers[0]!;
  const cipher = crypto._get_enctype_profile(enctype);

  let key: crypto.Key;
  if (nthashBuf.length > 0) {
    key = new crypto.Key(cipher.enctype, nthashBuf);
  } else if (aesKeyBuf.length > 0) {
    key = new crypto.Key(cipher.enctype, aesKeyBuf);
  } else {
    const salt = encryptionTypesData[enctype] ?? Buffer.alloc(0);
    key = cipher.string_to_key(password, salt, null);
  }

  if (preAuth) {
    const timeStamp = asn1.PA_ENC_TS_ENC();
    const now = new Date();
    timeStamp.set('patimestamp', now);
    timeStamp.set('pausec', now.getUTCMilliseconds() * 1000);
    const encodedTimeStamp = timeStamp.encode();

    const encryptedTimeStamp = cipher.encrypt(key, 1, encodedTimeStamp, null);

    const encData = asn1.EncryptedData();
    encData.set('etype', cipher.enctype);
    encData.set('cipher', encryptedTimeStamp);
    const encodedEncData = encData.encode();

    const nonce2 = Math.floor(Math.random() * 0x7fffffff);
    const message2 = encodeAsReq(clientName, srvName, upperDomain, [cipher.enctype], nonce2, [
      { type: constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP, value: encodedEncData },
      { type: constants.PreAuthenticationDataTypes.PA_PAC_REQUEST, value: encodedPacRequest },
    ]);

    tgt = await sendReceive(message2, upperDomain, kdcHost);

    try {
      const asRepNode = asn1.AS_REP();
      asRepNode.decode(tgt);
      asRep = asRepNode.values;
    } catch (asRepErr) {
      try {
        const krbErr = asn1.KRB_ERROR();
        krbErr.decode(tgt);
        throw new KerberosError({ packet: krbErr.values });
      } catch (krbErrParseErr) {
        if (krbErrParseErr instanceof KerberosError) throw krbErrParseErr;
        throw asRepErr as Error;
      }
    }
  }

  const encPart = asRep['enc-part'] as Record<string, AnyValue>;
  const cipherText = encPart.cipher as Buffer;

  if (!preAuth && kerberoastNoPreauth) {
    return { tgt, cipher, key, sessionKey: new crypto.Key(cipher.enctype, Buffer.alloc(0)) };
  }

  let plainText: Buffer;
  try {
    plainText = cipher.decrypt(key, 3, cipherText);
  } catch (e) {
    if (!preAuth) {
      throw new SessionKeyDecryptionError(
        `failed to decrypt session key: ${(e as Error).message}`,
        asRep,
        cipher,
        key,
        cipherText,
      );
    }
    throw e;
  }

  const encAsRepPart = asn1.EncASRepPart();
  encAsRepPart.decode(plainText);

  const sessionKeyType = Number(
    encAsRepPart.get('key')! && (encAsRepPart.get('key') as unknown as { keytype: number }).keytype,
  );
  const sessionKeyValue = (encAsRepPart.get('key') as unknown as { keyvalue: Buffer }).keyvalue;
  const sessionCipher = crypto._get_enctype_profile(sessionKeyType);
  const sessionKey = new crypto.Key(sessionKeyType, sessionKeyValue);

  return { tgt, cipher: sessionCipher, key, sessionKey };
}

export interface TGSResult {
  tgs: Buffer;
  cipher: crypto.EnctypeProfile;
  oldSessionKey: crypto.Key;
  sessionKey: crypto.Key;
}

export async function getKerberosTGS(
  serverName: types.Principal,
  domain: string,
  kdcHost: string | null,
  tgt: Buffer,
  cipher: crypto.EnctypeProfile,
  sessionKey: crypto.Key,
  renew = false,
): Promise<TGSResult> {
  const upperDomain = domain.toUpperCase();

  let decodedTGT: Record<string, AnyValue>;
  try {
    const asRep = asn1.AS_REP();
    asRep.decode(tgt);
    decodedTGT = asRep.values;
  } catch {
    const tgsRep = asn1.TGS_REP();
    tgsRep.decode(tgt);
    decodedTGT = tgsRep.values;
  }

  const ticketNode = asn1.Ticket();
  ticketNode._rawData = extractRawTicket(tgt);

  const apReq = asn1.AP_REQ();
  apReq.set('pvno', 5);
  apReq.set('msg-type', constants.ApplicationTagNumbers.AP_REQ);
  asn1.seqSetFlags(apReq, 'ap-options', []);
  apReq.set('ticket', ticketNode);

  const authenticator = asn1.Authenticator();
  authenticator.set('authenticator-vno', 5);
  authenticator.set('crealm', decodedTGT.crealm as string);

  const crealmName = decodedTGT.cname as Record<string, AnyValue>;
  const cnameType = Number(crealmName['name-type']);
  const cnameItems = crealmName['name-string'] as unknown as { value: string }[];
  const cnameStrings = cnameItems.map((i) => i.value);
  authenticator.set('cname', buildPrincipalName(cnameType, cnameStrings));

  const now = new Date();
  authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
  authenticator.set('ctime', now);

  const encodedAuthenticator = authenticator.encode();
  const encryptedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, null);

  const apReqEncPart = asn1.EncryptedData();
  apReqEncPart.set('etype', cipher.enctype);
  apReqEncPart.set('cipher', encryptedAuthenticator);
  apReq.set('authenticator', apReqEncPart);

  const encodedApReq = apReq.encode();

  const tgsReq = asn1.TGS_REQ();
  tgsReq.set('pvno', 5);
  tgsReq.set('msg-type', constants.ApplicationTagNumbers.TGS_REQ);

  const padataSeq = new Asn1SequenceOf(asn1.PA_DATA());
  const paEntry = asn1.PA_DATA();
  paEntry.set('padata-type', constants.PreAuthenticationDataTypes.PA_TGS_REQ);
  paEntry.set('padata-value', encodedApReq);
  padataSeq.add(paEntry);
  tgsReq.set('padata', padataSeq);

  const reqBody = asn1.KDC_REQ_BODY();
  const opts = [
    constants.KDCOptions.forwardable,
    constants.KDCOptions.renewable,
    constants.KDCOptions.renewable_ok,
    constants.KDCOptions.canonicalize,
  ];
  if (renew) opts.push(constants.KDCOptions.renew);
  asn1.seqSetFlags(reqBody, 'kdc-options', opts);
  reqBody.set('sname', buildPrincipalName(serverName.type, serverName.components));
  reqBody.set('realm', upperDomain);

  const till = new Date(Date.now() + 86400000);
  reqBody.set('till', till);
  reqBody.set('nonce', Math.floor(Math.random() * 0x7fffffff));

  const etypeSeq = new Asn1SequenceOf(new asn1.Int32());
  const etypeSet = new Set([
    constants.EncryptionTypes.aes256_cts_hmac_sha1_96,
    constants.EncryptionTypes.aes128_cts_hmac_sha1_96,
    constants.EncryptionTypes.rc4_hmac,
    constants.EncryptionTypes.des3_cbc_sha1_kd,
    constants.EncryptionTypes.des_cbc_md5,
    cipher.enctype,
  ]);
  for (const e of etypeSet) {
    etypeSeq.add(new asn1.Int32(e));
  }
  reqBody.set('etype', etypeSeq);

  tgsReq.set('req-body', reqBody);

  const message = tgsReq.encode();
  let r: Buffer;
  try {
    r = await sendReceive(message, upperDomain, kdcHost);
  } catch (e) {
    if (
      e instanceof KerberosError &&
      e.getErrorCode() === constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP
    ) {
      const etypeSeq2 = new Asn1SequenceOf(new asn1.Int32());
      etypeSeq2.add(new asn1.Int32(constants.EncryptionTypes.aes256_cts_hmac_sha1_96));
      etypeSeq2.add(new asn1.Int32(constants.EncryptionTypes.aes128_cts_hmac_sha1_96));
      reqBody.set('etype', etypeSeq2);
      tgsReq.set('req-body', reqBody);
      r = await sendReceive(tgsReq.encode(), upperDomain, kdcHost);
    } else {
      throw e;
    }
  }

  let tgsRep: Record<string, AnyValue>;
  try {
    const tgsRepNode = asn1.TGS_REP();
    tgsRepNode.decode(r);
    tgsRep = tgsRepNode.values;
  } catch {
    const krbErr = asn1.KRB_ERROR();
    krbErr.decode(r);
    throw new KerberosError({ packet: krbErr.values });
  }

  const tgsEncPart = tgsRep['enc-part'] as Record<string, AnyValue>;
  const tgsCipherText = tgsEncPart.cipher as Buffer;
  const plainText = cipher.decrypt(sessionKey, 8, tgsCipherText);

  const encTgsRepPart = asn1.EncTGSRepPart();
  encTgsRepPart.decode(plainText);

  const newSessionKeyType = Number(
    (encTgsRepPart.get('key') as unknown as { keytype: number }).keytype,
  );
  const newSessionKeyValue = (encTgsRepPart.get('key') as unknown as { keyvalue: Buffer }).keyvalue;
  const newCipher = crypto._get_enctype_profile(newSessionKeyType);
  const newSessionKey = new crypto.Key(newSessionKeyType, newSessionKeyValue);

  const resRep = asn1.TGS_REP();
  resRep.decode(r);
  const spnTicketValues = resRep.get('ticket') as Record<string, AnyValue>;
  const spnTicketNode = asn1.Ticket();
  spnTicketNode.values = spnTicketValues;
  const spnRealm = spnTicketNode.get('realm') as string;
  const spnNameValues = spnTicketNode.get('sname') as Record<string, AnyValue>;
  const spnNameType = Number(spnNameValues['name-type']);
  const spnNameItems = spnNameValues['name-string'] as unknown as { value: string }[];
  const spnNameStrings = spnNameItems.map((i) => i.value);
  const spn = new types.Principal(
    spnNameStrings.join('/') + '@' + spnRealm,
    null,
    spnNameType,
  );

  if (spn.components[0] === serverName.components[0] || spn.components[0] !== 'krbtgt') {
    return { tgs: r, cipher: newCipher, oldSessionKey: sessionKey, sessionKey: newSessionKey };
  }
  // Cross-realm referral — follow it
  return getKerberosTGS(
    serverName,
    spn.components[1] ?? upperDomain,
    kdcHost,
    r,
    newCipher,
    newSessionKey,
    renew,
  );
}

export interface KerberosType1Result {
  cipher: crypto.EnctypeProfile;
  sessionKey: crypto.Key;
  data: Buffer;
}

export async function getKerberosType1(
  username: string,
  password: string,
  domain: string,
  lmhash: Buffer | string,
  nthash: Buffer | string,
  aesKey: Buffer | string = '',
  targetName: string,
  kdcHost: string | null = null,
  useCache = true,
  tgt: TGTResult | null = null,
  tgs: TGSResult | null = null,
): Promise<KerberosType1Result> {
  const lmhashBuf = typeof lmhash === 'string' ? Buffer.from(lmhash, 'hex') : lmhash;
  const nthashBuf = typeof nthash === 'string' ? Buffer.from(nthash, 'hex') : nthash;
  const aesKeyBuf =
    typeof aesKey === 'string' ? (aesKey ? Buffer.from(aesKey, 'hex') : Buffer.alloc(0)) : aesKey;

  const spn = `host/${targetName}`;
  const userName = new types.Principal(
    username,
    null,
    constants.PrincipalNameType.NT_PRINCIPAL,
  );

  let tgtResult: TGTResult | null = null;
  let tgsResult: TGSResult | null = null;

  // Check ccache for a matching TGS first, then TGT
  if (useCache && tgs === null) {
    const ccachePath = process.env['KRB5CCNAME'];
    if (ccachePath && existsSync(ccachePath)) {
      try {
        const ccache = CCache.loadFile(ccachePath);
        const upperDom = domain.toUpperCase();
        const tgsCred = ccache.getCredential(`${spn}@${upperDom}`);
        if (tgsCred) {
          const converted = tgsCred.toTGS();
          tgsResult = {
            tgs: converted.data,
            cipher: converted.cipher,
            oldSessionKey: converted.sessionKey,
            sessionKey: converted.sessionKey,
          };
        }
      } catch {
        // fall through
      }
    }
  }

  if (tgsResult === null) {
    if (tgt !== null) {
      tgtResult = tgt;
    } else {
      tgtResult = await getKerberosTGT(
        userName,
        password,
        domain,
        lmhashBuf,
        nthashBuf,
        aesKeyBuf,
        kdcHost,
      );
    }

    if (tgs !== null) {
      tgsResult = tgs;
    } else {
      const serverName = new types.Principal(
        spn,
        null,
        constants.PrincipalNameType.NT_SRV_INST,
      );
      tgsResult = await getKerberosTGS(
        serverName,
        domain.toUpperCase(),
        kdcHost,
        tgtResult.tgt,
        tgtResult.cipher,
        tgtResult.sessionKey,
      );
    }
  }

  const blob = new SPNEGO_NegTokenInit();
  blob.mechTypeOids = [TypesMech['MS KRB5 - Microsoft Kerberos 5']!];

  const ticketNode = asn1.Ticket();
  ticketNode._rawData = extractRawTicket(tgsResult.tgs);

  const apReq = asn1.AP_REQ();
  apReq.set('pvno', 5);
  apReq.set('msg-type', constants.ApplicationTagNumbers.AP_REQ);
  asn1.seqSetFlags(apReq, 'ap-options', [constants.APOptions.mutual_required]);
  apReq.set('ticket', ticketNode);

  const authenticator = asn1.Authenticator();
  authenticator.set('authenticator-vno', 5);
  authenticator.set('crealm', domain.toUpperCase());
  authenticator.set('cname', buildPrincipalName(userName.type, userName.components));

  const now = new Date();
  authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
  authenticator.set('ctime', now);

  const chkField = new gssapi.CheckSumField();
  chkField.Lgth = 16;
  chkField.Flags =
    gssapi.GSS_C_CONF_FLAG |
    gssapi.GSS_C_INTEG_FLAG |
    gssapi.GSS_C_SEQUENCE_FLAG |
    gssapi.GSS_C_REPLAY_FLAG |
    gssapi.GSS_C_MUTUAL_FLAG |
    gssapi.GSS_C_DCE_STYLE;

  const cksum = asn1.Checksum();
  cksum.set('cksumtype', 0x8003);
  cksum.set('checksum', chkField.getData());
  authenticator.set('cksum', cksum);
  authenticator.set('seq-number', 0);

  const encodedAuthenticator = authenticator.encode();
  const encryptedAuthenticator = tgsResult.cipher.encrypt(
    tgsResult.sessionKey,
    11,
    encodedAuthenticator,
    null,
  );

  const apReqEncPart = asn1.EncryptedData();
  apReqEncPart.set('etype', tgsResult.cipher.enctype);
  apReqEncPart.set('cipher', encryptedAuthenticator);
  apReq.set('authenticator', apReqEncPart);

  const apReqEncoded = apReq.encode();
  const mechToken = Buffer.concat([
    Buffer.from([ASN1_AID]),
    asn1encode(
      Buffer.concat([
        Buffer.from([ASN1_OID]),
        asn1encode(TypesMech['KRB5 - Kerberos 5']!),
        gssapi.KRB5_AP_REQ,
        apReqEncoded,
      ]),
    ),
  ]);

  blob.fields['MechToken'] = mechToken;

  return {
    cipher: tgsResult.cipher,
    sessionKey: tgsResult.sessionKey,
    data: blob.getData(),
  };
}

export interface KerberosType3Result {
  cipher: crypto.EnctypeProfile;
  sessionKey: crypto.Key;
  data: Buffer;
}

export function getKerberosType3(
  cipher: crypto.EnctypeProfile,
  sessionKey: crypto.Key,
  authData: Buffer,
): KerberosType3Result {
  const negTokenResp = new SPNEGO_NegTokenResp(authData);
  const responseToken = negTokenResp.fields['ResponseToken'] as Buffer;
  if (!responseToken) throw new Error('No ResponseToken in NegTokenResp');

  let apRepData = responseToken;
  if (responseToken[0] === 0x60) {
    const mit = gssapi.MechIndepToken.from_bytes(responseToken);
    const tokId = mit.data.readUInt16BE(0);
    const innerToken = mit.data.subarray(2);
    if (tokId === 0x0300) {
      const krbErr = asn1.KRB_ERROR();
      krbErr.decode(innerToken);
      throw new KerberosError({ packet: krbErr.values });
    }
    apRepData = tokId === 0x0200 ? innerToken : responseToken;
  }

  const apRep = asn1.AP_REP();
  apRep.decode(apRepData);

  const cipherText = (apRep.get('enc-part') as unknown as { cipher: Buffer }).cipher;
  const plainText = cipher.decrypt(sessionKey, 12, cipherText);

  const encAPRepPart = asn1.EncAPRepPart();
  encAPRepPart.decode(plainText);

  const subkey = encAPRepPart.get('subkey') as unknown as {
    keytype: number;
    keyvalue: Buffer;
  };
  const newCipher = crypto._get_enctype_profile(subkey.keytype);
  const sessionKey2 = new crypto.Key(subkey.keytype, subkey.keyvalue);
  const sequenceNumber = Number(encAPRepPart.get('seq-number'));

  delete encAPRepPart.values['subkey'];
  const now = new Date();
  encAPRepPart.set('cusec', now.getUTCMilliseconds() * 1000);
  encAPRepPart.set('ctime', now);
  encAPRepPart.set('seq-number', sequenceNumber);

  const encodedAuthenticator = encAPRepPart.encode();
  const encryptedEncodedAuthenticator = newCipher.encrypt(sessionKey, 12, encodedAuthenticator, null);

  const encPart = asn1.EncryptedData();
  encPart.set('etype', newCipher.enctype);
  encPart.set('cipher', encryptedEncodedAuthenticator);
  apRep.set('enc-part', encPart);

  const resp = new SPNEGO_NegTokenResp();
  resp.fields['ResponseToken'] = apRep.encode();

  return {
    cipher: newCipher,
    sessionKey: sessionKey2,
    data: resp.getData(),
  };
}
