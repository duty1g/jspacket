import { Buffer } from 'node:buffer';
import type { AnyValue } from '@impacket/asn1';
import * as asn1 from './asn1.js';
import * as constants from './constants.js';
import * as crypto from './crypto.js';
import { sendReceive } from './kerberosv5.js';
import * as types from './types.js';

export const KRB5_KPASSWD_PORT = 464;
export const KRB5_KPASSWD_PROTOCOL_VERSION = 0xff80;
export const KRB5_KPASSWD_TGT_SPN = 'kadmin/changepw';

export enum KPasswdResultCodes {
  SUCCESS = 0,
  MALFORMED = 1,
  HARDERROR = 2,
  AUTHERROR = 3,
  SOFTERROR = 4,
  ACCESSDENIED = 5,
  BAD_VERSION = 6,
  INITIAL_FLAG_NEEDED = 7,
  UNKNOWN = 0xffff,
}

export const RESULT_MESSAGES: Record<number, string> = {
  0: 'password changed successfully',
  1: 'protocol error: malformed request',
  2: 'server error (KRB5_KPASSWD_HARDERROR)',
  3: 'authentication failed (may also indicate that the target user was not found)',
  4: 'password change rejected (KRB5_KPASSWD_SOFTERROR)',
  5: 'access denied',
  6: 'protocol error: bad version',
  7: 'protocol error: initial flag needed',
  65535: 'unknown error',
};

export class KPasswdError extends Error {}

export enum PasswordPolicyFlags {
  Complex = 0x1,
  NoAnonChange = 0x2,
  NoClearChange = 0x4,
  LockoutAdmins = 0x8,
  StoreCleartext = 0x10,
  RefusePasswordChange = 0x20,
}

export interface PasswordPolicy {
  minLength: number;
  history: number;
  maxAge: number;
  minAge: number;
  flags: string[];
}

export function decodePasswordPolicy(ppolicyString: Buffer): PasswordPolicy {
  const expectedLen = 2 + 4 + 4 + 4 + 8 + 8;
  if (ppolicyString.length !== expectedLen || ppolicyString[0] !== 0 || ppolicyString[1] !== 0) {
    throw new Error('Invalid password policy format');
  }
  const minLength = ppolicyString.readUInt32BE(2);
  const history = ppolicyString.readUInt32BE(6);
  const flagsRaw = ppolicyString.readUInt32BE(10);
  const maxAgeTicks = Number(ppolicyString.readBigUInt64BE(14));
  const minAgeTicks = Number(ppolicyString.readBigUInt64BE(22));
  const ticksInADay = 86400 * 10000000;
  const flags: string[] = [];
  for (const flag of Object.values(PasswordPolicyFlags)) {
    if (typeof flag === 'number' && flag & flagsRaw) {
      flags.push(PasswordPolicyFlags[flag]!);
    }
  }
  return {
    minLength,
    history,
    maxAge: maxAgeTicks / ticksInADay,
    minAge: minAgeTicks / ticksInADay,
    flags,
  };
}

export function createKPasswdRequest(
  principal: types.Principal,
  domain: string,
  newPasswd: string | Buffer,
  ticketBytes: Buffer,
  cipher: crypto.EnctypeProfile,
  sessionKey: crypto.Key,
  subKey: crypto.Key,
  targetPrincipal: string | null = null,
  targetDomain: string | null = null,
  sequenceNumber: number | null = null,
  now: Date | null = null,
  hostname = 'localhost',
): Buffer {
  if (sequenceNumber === null) {
    sequenceNumber = Math.floor(Math.random() * 0x100000000);
  }
  if (now === null) {
    now = new Date();
  }
  const newPasswdBuf = typeof newPasswd === 'string' ? Buffer.from(newPasswd, 'utf8') : newPasswd;

  const authenticator = asn1.Authenticator();
  authenticator.set('authenticator-vno', 5);
  authenticator.set('crealm', domain);
  authenticator.set(
    'cname',
    asn1.principalToAsn1({ type: principal.type, components: principal.components }),
  );
  authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
  authenticator.set('ctime', now);
  authenticator.set('seq-number', sequenceNumber);

  const subkey = asn1.EncryptionKey();
  subkey.set('keytype', subKey.enctype);
  subkey.set('keyvalue', subKey.contents);
  authenticator.set('subkey', subkey);

  const encodedAuthenticator = authenticator.encode();
  const encryptedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, null);

  const ticketNode = asn1.Ticket();
  ticketNode.decode(ticketBytes);

  const apReq = asn1.AP_REQ();
  apReq.set('pvno', 5);
  apReq.set('msg-type', constants.ApplicationTagNumbers.AP_REQ);
  asn1.seqSetFlags(apReq, 'ap-options', []);
  apReq.set('ticket', ticketNode);
  const apReqEnc = asn1.EncryptedData();
  apReqEnc.set('etype', cipher.enctype);
  apReqEnc.set('cipher', encryptedAuthenticator);
  apReq.set('authenticator', apReqEnc);

  const apReqEncoded = apReq.encode();

  const changePasswdSeq = asn1.ChangePasswdData();
  changePasswdSeq.set('newpasswd', newPasswdBuf);
  if (targetDomain && targetPrincipal) {
    const targName = asn1.PrincipalName();
    targName.set('name-type', constants.PrincipalNameType.NT_PRINCIPAL);
    const nameStrings = new (
      targName.getComponent('name-string') as unknown as {
        new (): import('@impacket/asn1').Asn1SequenceOf;
      }
    )();
    nameStrings.add(new asn1.KerberosString(targetPrincipal));
    targName.set('name-string', nameStrings);
    changePasswdSeq.set('targname', targName);
    changePasswdSeq.set('targrealm', targetDomain.toUpperCase());
  }
  const encodedChangePasswdData = changePasswdSeq.encode();

  const encKrbPrivPart = asn1.EncKrbPrivPart();
  encKrbPrivPart.set('user-data', encodedChangePasswdData);
  encKrbPrivPart.set('seq-number', sequenceNumber);
  const sAddr = asn1.HostAddress();
  sAddr.set('addr-type', constants.AddressType.IPv4);
  sAddr.set('address', Buffer.from(hostname, 'utf8'));
  encKrbPrivPart.set('s-address', sAddr);

  const encodedEncKrbPrivPart = encKrbPrivPart.encode();
  const encryptedEncKrbPrivPart = cipher.encrypt(subKey, 13, encodedEncKrbPrivPart, null);

  const krbPriv = asn1.KRB_PRIV();
  krbPriv.set('pvno', 5);
  krbPriv.set('msg-type', constants.ApplicationTagNumbers.KRB_PRIV);
  const krbPrivEnc = asn1.EncryptedData();
  krbPrivEnc.set('etype', cipher.enctype);
  krbPrivEnc.set('cipher', encryptedEncKrbPrivPart);
  krbPriv.set('enc-part', krbPrivEnc);

  const krbPrivEncoded = krbPriv.encode();

  const apReqLen = apReqEncoded.length;
  const krbPrivLen = krbPrivEncoded.length;
  const messageLen = 2 + 2 + 2 + apReqLen + krbPrivLen;

  const header = Buffer.alloc(6);
  header.writeUInt16BE(messageLen, 0);
  header.writeUInt16BE(KRB5_KPASSWD_PROTOCOL_VERSION, 2);
  header.writeUInt16BE(apReqLen, 4);

  return Buffer.concat([header, apReqEncoded, krbPrivEncoded]);
}

export interface KPasswdReply {
  success: boolean;
  resultCode: number;
  resultCodeMessage: string;
  message: string;
}

export function decodeKPasswdReply(
  encoded: Buffer,
  cipher: crypto.EnctypeProfile,
  subKey: crypto.Key,
): KPasswdReply {
  if (encoded.length < 6) throw new KPasswdError('kpasswd: malformed reply from the server');

  const apRepLen = encoded.readUInt16BE(4);
  const apRepEncoded = encoded.subarray(6, 6 + apRepLen);
  const krbPrivEncoded = encoded.subarray(6 + apRepLen);

  let apRep: Record<string, AnyValue>;
  let krbPriv: Record<string, AnyValue>;
  try {
    const apRepNode = asn1.AP_REP();
    apRepNode.decode(apRepEncoded);
    apRep = apRepNode.values;
    const krbPrivNode = asn1.KRB_PRIV();
    krbPrivNode.decode(krbPrivEncoded);
    krbPriv = krbPrivNode.values;
  } catch {
    throw new KPasswdError('kpasswd: malformed AP_REP or KRB_PRIV in the reply from the server');
  }

  void apRep;

  const encryptedEncKrbPrivPart = krbPriv.cipher as Buffer;
  let encodedEncKrbPrivPart: Buffer;
  try {
    encodedEncKrbPrivPart = cipher.decrypt(subKey, 13, encryptedEncKrbPrivPart);
  } catch {
    throw new KPasswdError('kpasswd: cannot decrypt KRB_PRIV in the reply from the server');
  }

  let result: Buffer;
  try {
    const encKrbPrivPart = asn1.EncKrbPrivPart();
    encKrbPrivPart.decode(encodedEncKrbPrivPart);
    result = encKrbPrivPart.get('user-data') as Buffer;
  } catch {
    throw new KPasswdError(
      'kpasswd: malformed EncKrbPrivPart in the KRB_PRIV in the reply from the server',
    );
  }

  const resultCode = result.readUInt16BE(0);
  const message = result.subarray(2);

  const resultCodeMessage = RESULT_MESSAGES[resultCode] ?? RESULT_MESSAGES[0xffff]!;

  let messageStr: string;
  try {
    const ppolicy = decodePasswordPolicy(message);
    messageStr = `Password policy:\n\tMinimum length: ${ppolicy.minLength}\n\tPassword history: ${ppolicy.history}\n\tFlags: ${ppolicy.flags.join(', ')}\n\tMaximum password age: ${ppolicy.maxAge} days\n\tMinimum password age: ${ppolicy.minAge} days`;
  } catch {
    try {
      messageStr = message.toString('utf8');
    } catch {
      messageStr = message.toString('latin1');
    }
  }

  return {
    success: resultCode === KPasswdResultCodes.SUCCESS,
    resultCode,
    resultCodeMessage,
    message: messageStr,
  };
}

export async function changePassword(
  clientName: string,
  domain: string,
  newPasswd: string,
  oldPasswd = '',
  oldLmhash = '',
  oldNthash = '',
  aesKey = '',
  TGT: { KDC_REP: Buffer; cipher: crypto.EnctypeProfile; sessionKey: crypto.Key } | null = null,
  kdcHost: string | null = null,
  kpasswdHost: string | null = null,
  kpasswdPort = KRB5_KPASSWD_PORT,
  subKey: crypto.Key | null = null,
): Promise<void> {
  await setPassword(
    clientName,
    domain,
    null,
    null,
    newPasswd,
    oldPasswd,
    oldLmhash,
    oldNthash,
    aesKey,
    TGT,
    kdcHost,
    kpasswdHost,
    kpasswdPort,
    subKey,
  );
}

export async function setPassword(
  clientName: string,
  domain: string,
  targetName: string | null,
  targetDomain: string | null,
  newPasswd: string,
  oldPasswd = '',
  oldLmhash = '',
  oldNthash = '',
  aesKey = '',
  TGT: { KDC_REP: Buffer; cipher: crypto.EnctypeProfile; sessionKey: crypto.Key } | null = null,
  kdcHost: string | null = null,
  kpasswdHost: string | null = null,
  kpasswdPort = KRB5_KPASSWD_PORT,
  subKey: crypto.Key | null = null,
): Promise<boolean> {
  if (kpasswdHost === null) {
    kpasswdHost = kdcHost;
  }

  const userName = new types.Principal(clientName, null, constants.PrincipalNameType.NT_PRINCIPAL);

  let tgt: Buffer;
  let cipher: crypto.EnctypeProfile;
  let sessionKey: crypto.Key;

  if (TGT === null) {
    const result = await (await import('./kerberosv5.js')).getKerberosTGT(
      userName,
      oldPasswd,
      domain,
      oldLmhash ? Buffer.from(oldLmhash, 'hex') : Buffer.alloc(0),
      oldNthash ? Buffer.from(oldNthash, 'hex') : Buffer.alloc(0),
      aesKey ? Buffer.from(aesKey, 'hex') : Buffer.alloc(0),
      kdcHost,
      true,
      KRB5_KPASSWD_TGT_SPN,
    );
    tgt = result.tgt;
    cipher = result.cipher;
    sessionKey = result.sessionKey;
  } else {
    tgt = TGT.KDC_REP;
    cipher = TGT.cipher;
    sessionKey = TGT.sessionKey;
  }

  const asRep = asn1.AS_REP();
  asRep.decode(tgt);
  const ticketBytes = asRep.get('ticket') as Buffer;

  if (subKey === null) {
    const subKeyBytes = Buffer.alloc(cipher.keysize);
    for (let i = 0; i < cipher.keysize; i++) subKeyBytes[i] = Math.floor(Math.random() * 256);
    subKey = new crypto.Key(cipher.enctype, subKeyBytes);
  }

  const kpasswordReq = createKPasswdRequest(
    userName,
    domain,
    newPasswd,
    ticketBytes,
    cipher,
    sessionKey,
    subKey,
    targetName,
    targetDomain,
  );

  const kpasswordRep = await sendReceive(kpasswordReq, domain, kpasswdHost, kpasswdPort);

  const reply = decodeKPasswdReply(kpasswordRep, cipher, subKey);
  if (reply.success) return true;

  let errorMessage = reply.resultCodeMessage;
  if (reply.message) errorMessage += `: ${reply.message}`;
  throw new KPasswdError(errorMessage);
}
