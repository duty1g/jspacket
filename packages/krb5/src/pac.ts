import { Buffer } from 'node:buffer';
import { createHash, createHmac } from 'node:crypto';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniFixedArray,
  NDRULONG,
  NDRUSHORT,
  type NDRField,
} from '@impacket/dcerpc';
import {
  FILETIME,
  RPC_UNICODE_STRING,
  PRPC_SID,
  DWORD_ARRAY,
  TypeSerialization1,
} from '@impacket/dcerpc';
import { Enctype, Key } from './crypto.js';
import * as Constants from './constants.js';

export interface ChecksumProfile {
  macsize: number;
  enctype: number;
  checksum(key: Key, keyusage: number, text: Buffer): Buffer;
}

export const PAC_LOGON_INFO = 1;
export const PAC_CREDENTIALS_INFO = 2;
export const PAC_SERVER_CHECKSUM = 6;
export const PAC_PRIVSVR_CHECKSUM = 7;
export const PAC_CLIENT_INFO_TYPE = 10;
export const PAC_DELEGATION_INFO = 11;
export const PAC_UPN_DNS_INFO = 12;
export const PAC_ATTRIBUTES_INFO = 17;
export const PAC_REQUESTOR_INFO = 18;

export const PISID = PRPC_SID;

export class KERB_SID_AND_ATTRIBUTES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Sid', PISID],
    ['Attributes', NDRULONG],
  ];
}

export class KERB_SID_AND_ATTRIBUTES_ARRAY extends NDRUniConformantArray {
  static item = KERB_SID_AND_ATTRIBUTES;
}

export class PKERB_SID_AND_ATTRIBUTES_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', KERB_SID_AND_ATTRIBUTES_ARRAY]];
}

export class GROUP_MEMBERSHIP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['RelativeId', NDRULONG],
    ['Attributes', NDRULONG],
  ];
}

export class GROUP_MEMBERSHIP_ARRAY extends NDRUniConformantArray {
  static item = GROUP_MEMBERSHIP;
}

export class PGROUP_MEMBERSHIP_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', GROUP_MEMBERSHIP_ARRAY]];
}

export class DOMAIN_GROUP_MEMBERSHIP extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['DomainId', PISID],
    ['GroupCount', NDRULONG],
    ['GroupIds', PGROUP_MEMBERSHIP_ARRAY],
  ];
}

export class DOMAIN_GROUP_MEMBERSHIP_ARRAY extends NDRUniConformantArray {
  static item = DOMAIN_GROUP_MEMBERSHIP;
}

export class PDOMAIN_GROUP_MEMBERSHIP_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DOMAIN_GROUP_MEMBERSHIP_ARRAY]];
}

export class CHAR_FIXED_8_ARRAY extends NDRUniFixedArray {
  static align = 1;
  static align64 = 1;
  getDataLen(): number {
    return 8;
  }
}

export class USER_SESSION_KEY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Data', '8s'],
  ];
}

export class PUCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DWORD_ARRAY]];
}

export class RPC_UNICODE_STRING_ARRAY_NDR extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

export class PRPC_UNICODE_STRING_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_UNICODE_STRING_ARRAY_NDR]];
}

export class PACTYPE extends Structure {
  static structure: FieldDescriptor[] = [
    ['cBuffers', '<L=0'],
    ['Version', '<L=0'],
    ['Buffers', ':'],
  ];
}

export class PAC_INFO_BUFFER extends Structure {
  static structure: FieldDescriptor[] = [
    ['ulType', '<L=0'],
    ['cbBufferSize', '<L=0'],
    ['Offset', '<Q=0'],
  ];
}

export class KERB_VALIDATION_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['LogonTime', FILETIME],
    ['LogoffTime', FILETIME],
    ['KickOffTime', FILETIME],
    ['PasswordLastSet', FILETIME],
    ['PasswordCanChange', FILETIME],
    ['PasswordMustChange', FILETIME],
    ['EffectiveName', RPC_UNICODE_STRING],
    ['FullName', RPC_UNICODE_STRING],
    ['LogonScript', RPC_UNICODE_STRING],
    ['ProfilePath', RPC_UNICODE_STRING],
    ['HomeDirectory', RPC_UNICODE_STRING],
    ['HomeDirectoryDrive', RPC_UNICODE_STRING],
    ['LogonCount', NDRUSHORT],
    ['BadPasswordCount', NDRUSHORT],
    ['UserId', NDRULONG],
    ['PrimaryGroupId', NDRULONG],
    ['GroupCount', NDRULONG],
    ['GroupIds', PGROUP_MEMBERSHIP_ARRAY],
    ['UserFlags', NDRULONG],
    ['UserSessionKey', USER_SESSION_KEY],
    ['LogonServer', RPC_UNICODE_STRING],
    ['LogonDomainName', RPC_UNICODE_STRING],
    ['LogonDomainId', PRPC_SID],
    ['LMKey', CHAR_FIXED_8_ARRAY],
    ['UserAccountControl', NDRULONG],
    ['SubAuthStatus', NDRULONG],
    ['LastSuccessfulILogon', FILETIME],
    ['LastFailedILogon', FILETIME],
    ['FailedILogonCount', NDRULONG],
    ['Reserved3', NDRULONG],
    ['SidCount', NDRULONG],
    ['ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY],
    ['ResourceGroupDomainSid', PISID],
    ['ResourceGroupCount', NDRULONG],
    ['ResourceGroupIds', PGROUP_MEMBERSHIP_ARRAY],
  ];
}

export class PKERB_VALIDATION_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', KERB_VALIDATION_INFO]];
}

export class VALIDATION_INFO extends TypeSerialization1 {
  static structure: NDRField[] = [
    ['Data', PKERB_VALIDATION_INFO],
  ];
}

export class PAC_CREDENTIAL_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['EncryptionType', '<L=0'],
    ['SerializedData', ':'],
  ];
}

export class SECPKG_SUPPLEMENTAL_CRED extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['PackageName', RPC_UNICODE_STRING],
    ['CredentialSize', NDRULONG],
    ['Credentials', PUCHAR_ARRAY],
  ];
}

export class SECPKG_SUPPLEMENTAL_CRED_ARRAY extends NDRUniConformantArray {
  static item = SECPKG_SUPPLEMENTAL_CRED;
}

export class PAC_CREDENTIAL_DATA extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['CredentialCount', NDRULONG],
    ['Credentials', SECPKG_SUPPLEMENTAL_CRED_ARRAY],
  ];
}

export class NTLM_SUPPLEMENTAL_CREDENTIAL extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Version', NDRULONG],
    ['Flags', NDRULONG],
    ['LmPassword', '16s'],
    ['NtPassword', '16s'],
  ];
}

export class PAC_CLIENT_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['ClientId', '<Q=0'],
    ['NameLength', '<H=0'],
    ['_Name', '_-Name', 'self["NameLength"]'],
    ['Name', ':'],
  ];
}

export class PAC_SIGNATURE_DATA extends Structure {
  static structure: FieldDescriptor[] = [
    ['SignatureType', '<l=0'],
    ['Signature', ':'],
  ];
}

export class S4U_DELEGATION_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['S4U2proxyTarget', RPC_UNICODE_STRING],
    ['TransitedListSize', NDRULONG],
    ['S4UTransitedServices', PRPC_UNICODE_STRING_ARRAY],
  ];
}

export class UPN_DNS_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['UpnLength', '<H=0'],
    ['UpnOffset', '<H=0'],
    ['DnsDomainNameLength', '<H=0'],
    ['DnsDomainNameOffset', '<H=0'],
    ['Flags', '<L=0'],
  ];
}

export class UPN_DNS_INFO_FULL extends Structure {
  static structure: FieldDescriptor[] = [
    ['UpnLength', '<H=0'],
    ['UpnOffset', '<H=0'],
    ['DnsDomainNameLength', '<H=0'],
    ['DnsDomainNameOffset', '<H=0'],
    ['Flags', '<L=0'],
    ['SamNameLength', '<H=0'],
    ['SamNameOffset', '<H=0'],
    ['SidLength', '<H=0'],
    ['SidOffset', '<H=0'],
  ];
}

export class PAC_CLIENT_CLAIMS_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['Claims', ':'],
  ];
}

export class PAC_DEVICE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UserId', NDRULONG],
    ['PrimaryGroupId', NDRULONG],
    ['AccountDomainId', PISID],
    ['AccountGroupCount', NDRULONG],
    ['AccountGroupIds', PGROUP_MEMBERSHIP_ARRAY],
    ['SidCount', NDRULONG],
    ['ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY],
    ['DomainGroupCount', NDRULONG],
    ['DomainGroup', PDOMAIN_GROUP_MEMBERSHIP_ARRAY],
  ];
}

export class PAC_DEVICE_CLAIMS_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['Claims', ':'],
  ];
}

export class PAC_ATTRIBUTE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['FlagsLength', NDRULONG],
    ['Flags', NDRULONG],
  ];
}

import type { StructureConstructor } from '@impacket/structure';
import { RPC_SID } from '@impacket/dcerpc';

export class PAC_REQUESTOR extends Structure {
  static structure: FieldDescriptor[] = [
    ['UserSid', ':', RPC_SID as unknown as StructureConstructor],
  ];
}

export function getPadLength(dataLength: number): number {
  return getBlockLength(dataLength) - dataLength;
}

export function getBlockLength(dataLength: number): number {
  return Math.floor((dataLength + 7) / 8) * 8;
}

function coerceHexKey(key: string | Buffer | null): Buffer | null {
  if (key === null || key === '' || (Buffer.isBuffer(key) && key.length === 0)) return null;
  if (Buffer.isBuffer(key)) return key;
  try {
    return Buffer.from(key, 'hex');
  } catch {
    return Buffer.from(key, 'utf-8');
  }
}

export function orderedBufferTypes(
  pacInfos: Map<number, Buffer>,
  bufferOrder?: number[],
): number[] {
  const ordered: number[] = [];
  const seen = new Set<number>();

  if (bufferOrder) {
    for (const ulType of bufferOrder) {
      if (pacInfos.has(ulType) && !seen.has(ulType)) {
        ordered.push(ulType);
        seen.add(ulType);
      }
    }
  }

  for (const ulType of pacInfos.keys()) {
    if (!seen.has(ulType)) ordered.push(ulType);
  }

  return ordered;
}

export function buildPacType(pacInfos: Map<number, Buffer>, bufferOrder?: number[]): PACTYPE {
  const orderedTypes = orderedBufferTypes(pacInfos, bufferOrder);
  const infoBufferSize = new PAC_INFO_BUFFER().getData().length;
  let offsetData = 8 + infoBufferSize * orderedTypes.length;
  let infoBuffers = Buffer.alloc(0);
  let dataBlobs = Buffer.alloc(0);

  for (const ulType of orderedTypes) {
    const data = pacInfos.get(ulType)!;

    const infoBuffer = new PAC_INFO_BUFFER();
    infoBuffer.set('ulType', ulType);
    infoBuffer.set('cbBufferSize', data.length);
    infoBuffer.set('Offset', offsetData);
    infoBuffers = Buffer.concat([infoBuffers, infoBuffer.getData()]);

    dataBlobs = Buffer.concat([dataBlobs, data, Buffer.alloc(getPadLength(data.length))]);
    offsetData = getBlockLength(offsetData + data.length);
  }

  const pacType = new PACTYPE();
  pacType.set('cBuffers', orderedTypes.length);
  pacType.set('Version', 0);
  pacType.set('Buffers', Buffer.concat([infoBuffers, dataBlobs]));
  return pacType;
}

function normalizePacChecksumType(
  signatureType: number,
  signatureLength: number,
  aesKey: Buffer | null,
  inferAesSignatureType: boolean,
): number {
  if (inferAesSignatureType && aesKey !== null && signatureLength === 12) {
    if (aesKey.length === 16) return Constants.ChecksumTypes.hmac_sha1_96_aes128;
    if (aesKey.length === 32) return Constants.ChecksumTypes.hmac_sha1_96_aes256;
  }
  return signatureType;
}

class SHA1AES128Checksum implements ChecksumProfile {
  macsize = 12;
  enctype = Enctype.AES128;

  checksum(key: Key, _keyusage: number, text: Buffer): Buffer {
    const kc = deriveChecksumKey(key, 0x99);
    const hmac = createHmac('sha1', kc.contents).update(text).digest();
    return hmac.subarray(0, this.macsize);
  }
}

class SHA1AES256Checksum implements ChecksumProfile {
  macsize = 12;
  enctype = Enctype.AES256;

  checksum(key: Key, _keyusage: number, text: Buffer): Buffer {
    const kc = deriveChecksumKey(key, 0x99);
    const hmac = createHmac('sha1', kc.contents).update(text).digest();
    return hmac.subarray(0, this.macsize);
  }
}

class HMACMD5Checksum implements ChecksumProfile {
  macsize = 16;
  enctype = Enctype.RC4;

  checksum(key: Key, keyusage: number, text: Buffer): Buffer {
    const ksign = createHmac('md5', key.contents).update(Buffer.from('signaturekey\x00')).digest();
    const usageBuf = Buffer.alloc(4);
    usageBuf.writeUInt32LE(keyusage, 0);
    const md5hash = createHash('md5').update(Buffer.concat([usageBuf, text])).digest();
    return createHmac('md5', ksign).update(md5hash).digest();
  }
}

function nfold(ba: Buffer, nbytes: number): Buffer {
  const slen = ba.length;
  if (slen === 0) return Buffer.alloc(nbytes);
  const gcd = (a: number, b: number): number => {
    while (b !== 0) [a, b] = [b, a % b];
    return a;
  };
  const lcm = (nbytes * slen) / gcd(nbytes, slen);

  const rotateRight = (input: Buffer, nbits: number): Buffer => {
    const len = input.length;
    const nbytesShift = Math.floor(nbits / 8) % len;
    const remain = nbits % 8;
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      const lo = input[(i - nbytesShift + len) % len]! >> remain;
      const hi =
        remain === 0 ? 0 : ((input[(i - nbytesShift - 1 + len) % len]! << (8 - remain)) & 0xff);
      out[i] = lo | hi;
    }
    return out;
  };

  const addOnesComplement = (a: Buffer, b: Buffer): Buffer => {
    const n = a.length;
    const v = new Array<number>(n).fill(0);
    for (let i = 0; i < n; i++) v[i] = a[i]! + b[i]!;
    while (v.some((x) => x & ~0xff)) {
      const nv = new Array<number>(n).fill(0);
      for (let i = 0; i < n; i++) {
        nv[i] = (v[(i + 1) % n]! >> 8) + (v[i]! & 0xff);
      }
      for (let i = 0; i < n; i++) v[i] = nv[i]!;
    }
    return Buffer.from(v.map((x) => x & 0xff));
  };

  const bigstr: Buffer[] = [];
  for (let i = 0; i < lcm / slen; i++) {
    bigstr.push(rotateRight(ba, 13 * i));
  }
  const big = Buffer.concat(bigstr);
  let result: Buffer | null = null;
  for (let p = 0; p < lcm; p += nbytes) {
    const slice = big.subarray(p, p + nbytes);
    result = result === null ? Buffer.from(slice) : addOnesComplement(result, slice);
  }
  return result ?? Buffer.alloc(nbytes);
}

function aesEcbEncryptBlock(key: Buffer, plaintext: Buffer): Buffer {
  const { createCipheriv } = require('node:crypto');
  const cipher = createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function deriveChecksumKey(key: Key, usageConstant: number): Key {
  const blocksize = 16;
  const usageBuf = Buffer.alloc(5);
  usageBuf.writeUInt32BE(usageConstant, 0);
  usageBuf[4] = 0x99;
  let plaintext = nfold(usageBuf, blocksize);
  let rndseed = Buffer.alloc(0);
  while (rndseed.length < key.contents.length) {
    const ciphertext = aesEcbEncryptBlock(key.contents, plaintext);
    rndseed = Buffer.concat([rndseed, ciphertext]);
    plaintext = ciphertext;
  }
  return new Key(key.enctype, rndseed.subarray(0, key.contents.length));
}

const checksumTable: Record<number, ChecksumProfile> = {
  [Constants.ChecksumTypes.hmac_sha1_96_aes128]: new SHA1AES128Checksum(),
  [Constants.ChecksumTypes.hmac_sha1_96_aes256]: new SHA1AES256Checksum(),
  [Constants.ChecksumTypes.hmac_md5]: new HMACMD5Checksum(),
  [0xffffff76]: new HMACMD5Checksum(),
};

function getChecksumContext(
  signatureType: number,
  aesKey: Buffer | null,
  ntHash: Buffer | null,
  checksumName: string,
): { checksumFunction: ChecksumProfile; key: Key } {
  const checksumFunction = checksumTable[signatureType];
  if (!checksumFunction) {
    throw new Error(`Invalid ${checksumName} checksum type 0x${signatureType.toString(16)}`);
  }

  if (signatureType === Constants.ChecksumTypes.hmac_sha1_96_aes256) {
    if (aesKey === null) throw new Error(`Missing AES key for ${checksumName} checksum`);
    return { checksumFunction, key: new Key(Enctype.AES256, aesKey) };
  }
  if (signatureType === Constants.ChecksumTypes.hmac_sha1_96_aes128) {
    if (aesKey === null) throw new Error(`Missing AES key for ${checksumName} checksum`);
    return { checksumFunction, key: new Key(Enctype.AES128, aesKey) };
  }
  if (signatureType === Constants.ChecksumTypes.hmac_md5) {
    if (ntHash === null) throw new Error(`Missing NT hash for ${checksumName} checksum`);
    return { checksumFunction, key: new Key(Enctype.RC4, ntHash) };
  }

  throw new Error(`Invalid ${checksumName} checksum type 0x${signatureType.toString(16)}`);
}

export interface SignPacOptions {
  aesKey?: string | Buffer | null;
  ntHash?: string | Buffer | null;
  bufferOrder?: number[];
  checksumSalt?: number;
  inferAesSignatureType?: boolean;
}

export function signPac(
  pacInfos: Map<number, Buffer>,
  options: SignPacOptions = {},
): PACTYPE {
  const {
    aesKey: aesKeyRaw = null,
    ntHash: ntHashRaw = null,
    bufferOrder,
    checksumSalt = Constants.KERB_NON_KERB_CKSUM_SALT,
    inferAesSignatureType = false,
  } = options;

  if (!pacInfos.has(PAC_SERVER_CHECKSUM)) {
    throw new Error('PAC_SERVER_CHECKSUM not found! Aborting');
  }
  if (!pacInfos.has(PAC_PRIVSVR_CHECKSUM)) {
    throw new Error('PAC_PRIVSVR_CHECKSUM not found! Aborting');
  }

  const aesKey = coerceHexKey(aesKeyRaw);
  const ntHash = coerceHexKey(ntHashRaw);

  const serverChecksumData = pacInfos.get(PAC_SERVER_CHECKSUM)!;
  const privsvrChecksumData = pacInfos.get(PAC_PRIVSVR_CHECKSUM)!;

  const serverChecksum = new PAC_SIGNATURE_DATA(serverChecksumData);
  const privsvrChecksum = new PAC_SIGNATURE_DATA(privsvrChecksumData);

  const serverSigType = normalizePacChecksumType(
    serverChecksum.get('SignatureType') as number,
    (serverChecksum.get('Signature') as Buffer).length,
    aesKey,
    inferAesSignatureType,
  );
  const privsvrSigType = normalizePacChecksumType(
    privsvrChecksum.get('SignatureType') as number,
    (privsvrChecksum.get('Signature') as Buffer).length,
    aesKey,
    inferAesSignatureType,
  );

  serverChecksum.set('SignatureType', serverSigType);
  privsvrChecksum.set('SignatureType', privsvrSigType);

  const serverSigLen = (serverChecksum.get('Signature') as Buffer).length;
  const privsvrSigLen = (privsvrChecksum.get('Signature') as Buffer).length;
  serverChecksum.set('Signature', Buffer.alloc(serverSigLen, 0));
  privsvrChecksum.set('Signature', Buffer.alloc(privsvrSigLen, 0));

  pacInfos.set(PAC_SERVER_CHECKSUM, serverChecksum.getData());
  pacInfos.set(PAC_PRIVSVR_CHECKSUM, privsvrChecksum.getData());

  const pacType = buildPacType(pacInfos, bufferOrder);
  const blobToChecksum = pacType.getData();

  const serverCtx = getChecksumContext(serverSigType, aesKey, ntHash, 'Server');
  const privsvrCtx = getChecksumContext(privsvrSigType, aesKey, ntHash, 'Priv');

  const serverSignature = serverCtx.checksumFunction.checksum(
    serverCtx.key,
    checksumSalt,
    blobToChecksum,
  );
  const privsvrSignature = privsvrCtx.checksumFunction.checksum(
    privsvrCtx.key,
    checksumSalt,
    serverSignature,
  );

  serverChecksum.set('Signature', serverSignature);
  privsvrChecksum.set('Signature', privsvrSignature);

  pacInfos.set(PAC_SERVER_CHECKSUM, serverChecksum.getData());
  pacInfos.set(PAC_PRIVSVR_CHECKSUM, privsvrChecksum.getData());

  return buildPacType(pacInfos, bufferOrder);
}