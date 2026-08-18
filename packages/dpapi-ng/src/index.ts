import { Buffer } from 'node:buffer';
import { createHmac, createHash, createCipheriv, createDecipheriv, createECDH } from 'node:crypto';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import { ECDHKey, FFCDHKey, GroupKeyEnvelope } from '@impacket/dcerpc';
import {
  ACE, ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK,
  SR_SECURITY_DESCRIPTOR, LDAP_SID,
} from '@impacket/ldap';

export const KDS_SERVICE_LABEL = Buffer.from('KDS service\0', 'utf16le');
export const KEK_PUBLIC_KEY_LABEL = Buffer.from('KDS public key\0', 'utf16le');

function longToBytes(n: number | bigint, length: number): Buffer {
  const buf = Buffer.alloc(length);
  const val = typeof n === 'bigint' ? n : BigInt(n);
  for (let i = length - 1; i >= 0; i--) {
    buf[i] = Number(val >> BigInt((length - 1 - i) * 8)) & 0xff;
  }
  return buf;
}

function hmacDigest(algo: string, key: Buffer, data: Buffer): Buffer {
  return createHmac(algo, key).update(data).digest();
}

export function SP800_108_Counter(
  master: Buffer,
  keyLen: number,
  prf: (secret: Buffer, input: Buffer) => Buffer,
  numKeys = 1,
  label: Buffer = Buffer.alloc(0),
  context: Buffer = Buffer.alloc(0),
): Buffer | Buffer[] {
  const keyLenEnc = longToBytes(keyLen * numKeys * 8, 4);
  const outputLen = keyLen * numKeys;

  let i = 1;
  const parts: Buffer[] = [];
  let totalLen = 0;

  while (totalLen < outputLen) {
    const info = Buffer.concat([longToBytes(i, 4), label, Buffer.from([0x00]), context, keyLenEnc]);
    const block = prf(master, info);
    parts.push(block);
    totalLen += block.length;
    i += 1;
    if (i > 0xFFFFFFFF) {
      throw new Error('Overflow in SP800 108 counter');
    }
  }

  const dk = Buffer.concat(parts);

  if (numKeys === 1) {
    return dk.subarray(0, keyLen);
  }

  const keys: Buffer[] = [];
  for (let idx = 0; idx < outputLen; idx += keyLen) {
    keys.push(dk.subarray(idx, idx + keyLen));
  }
  return keys;
}

export class KeyIdentifier extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Magic', '<L=0'],
    ['Flags', '<L=0'],
    ['L0Index', '<L=0'],
    ['L1Index', '<L=0'],
    ['L2Index', '<L=0'],
    ['RootKeyId', '16s=b""'],
    ['UnknownLength', '<L=0'],
    ['DomainLength', '<L=0'],
    ['ForestLength', '<L=0'],
    ['_Unknown', '_-Unknown', 'self["UnknownLength"]'],
    ['Unknown', ':'],
    ['_Domain', '_-Domain', 'self["DomainLength"]'],
    ['Domain', ':'],
    ['_Forest', '_-Forest', 'self["ForestLength"]'],
    ['Forest', ':'],
  ];

  override dump(msg?: string, indent = 0): string[] {
    const lines = super.dump(msg, indent);
    const ind = ' '.repeat(indent);
    lines.push(`${ind}Version:\t\t${this.get('Version')}`);
    lines.push(`${ind}Magic:\t\t0x${(this.get('Magic') as number).toString(16)}`);
    lines.push(`${ind}Flags:\t\t${this.get('Flags')}`);
    lines.push(`${ind}L0Index:\t\t${this.get('L0Index')}`);
    lines.push(`${ind}L1Index:\t\t${this.get('L1Index')}`);
    lines.push(`${ind}L2Index:\t\t${this.get('L2Index')}`);
    lines.push(`${ind}RootKeyId:\t\t${this.get('RootKeyId')}`);
    lines.push(`${ind}Unknown:\t\t${this.get('Unknown')}`);
    lines.push(`${ind}Domain:\t\t${(this.get('Domain') as Buffer).toString('utf16le')}`);
    lines.push(`${ind}Forest:\t\t${(this.get('Forest') as Buffer).toString('utf16le')}`);
    return lines;
  }

  isPublicKey(): boolean {
    return Boolean((this.get('Flags') as number) & 1);
  }
}

export class EncryptedPasswordBlob extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Timestamp_lower', '<L=0'],
    ['Timestamp_upper', '<L=0'],
    ['Length', '<L=0'],
    ['Flags', '<L=0'],
    ['_Blob', '_-Blob', 'self["Length"]'],
    ['Blob', ':'],
  ];

  override dump(msg?: string, indent = 0): string[] {
    const lines = super.dump(msg, indent);
    const ind = ' '.repeat(indent);
    const upper = this.get('Timestamp_upper') as number;
    const lower = this.get('Timestamp_lower') as number;
    lines.push(`${ind}Timestamp_upper:\t\t${upper}`);
    lines.push(`${ind}Timestamp_lower:\t\t${lower}`);
    lines.push(`${ind}Update Timestamp:\t\t${(upper << 32) | lower}`);
    lines.push(`${ind}Length:\t\t${this.get('Length')}`);
    lines.push(`${ind}Flags:\t\t${this.get('Flags')}`);
    lines.push(`${ind}Blob:\t\t${this.get('Blob')}`);
    return lines;
  }
}

function intToU32BE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(n);
  return buf;
}

export function createAce(sid: string, mask: number): ACE {
  const nace = new ACE();
  nace.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
  nace.set('AceFlags', 0x00);
  const acedata = new ACCESS_ALLOWED_ACE();
  const amask = new ACCESS_MASK();
  amask.set('Mask', mask);
  acedata.set('Mask', amask);
  const ldapSid = new LDAP_SID();
  ldapSid.fromCanonical(sid);
  acedata.set('Sid', ldapSid);
  nace.set('Ace', acedata);
  return nace;
}

export function createSd(sid: string): SR_SECURITY_DESCRIPTOR {
  const sd = new SR_SECURITY_DESCRIPTOR();
  sd.set('Revision', Buffer.from([0x01]));
  sd.set('Sbz1', Buffer.from([0x00]));
  sd.set('Control', 32772);
  const ownerSid = new LDAP_SID();
  ownerSid.fromCanonical('S-1-5-18');
  sd.set('OwnerSid', ownerSid);
  const groupSid = new LDAP_SID();
  groupSid.fromCanonical('S-1-5-18');
  sd.set('GroupSid', groupSid);
  sd.set('Sacl', Buffer.alloc(0));

  const acl = new ACL();
  acl.set('AclRevision', 2);
  acl.set('Sbz1', 0);
  acl.set('Sbz2', 0);
  (acl as any).aces = [];
  (acl as any).aces.push(createAce(sid, 3));
  (acl as any).aces.push(createAce('S-1-1-0', 2));
  sd.set('Dacl', acl);
  return sd;
}

export function computeKdfHash(length: number, keyMaterial: Buffer, otherinfo: Buffer): Buffer {
  const output: Buffer[] = [];
  let outlen = 0;
  let counter = 1;

  while (length > outlen) {
    const hash = createHash('sha256');
    hash.update(intToU32BE(counter));
    hash.update(keyMaterial);
    hash.update(otherinfo);
    const digest = hash.digest();
    output.push(digest);
    outlen += digest.length;
    counter += 1;
  }

  return Buffer.concat(output).subarray(0, length);
}

export function computeKdfContext(keyGuid: Buffer, l0: number, l1: number, l2: number): Buffer {
  const buf0 = Buffer.alloc(4);
  buf0.writeInt32LE(l0);
  const buf1 = Buffer.alloc(4);
  buf1.writeInt32LE(l1);
  const buf2 = Buffer.alloc(4);
  buf2.writeInt32LE(l2);
  return Buffer.concat([keyGuid, buf0, buf1, buf2]);
}

export function kdf(hashAlgStr: string, secret: Buffer, label: Buffer, context: Buffer, length: number): Buffer {
  let algo = 'sha512';
  if (hashAlgStr.includes('SHA512')) {
    algo = 'sha512';
  } else if (hashAlgStr.includes('SHA256')) {
    algo = 'sha256';
  }

  const prf = (s: Buffer, x: Buffer): Buffer => hmacDigest(algo, s, x);

  return SP800_108_Counter(secret, length, prf, 1, label, context) as Buffer;
}

export function computeL2Key(keyId: KeyIdentifier, gke: GroupKeyEnvelope): Buffer {
  let l1 = gke.get('L1Index') as number;
  const l1KeyBuf = gke.get('L1Key') as Buffer;
  let l1Key: Buffer = Buffer.from(l1KeyBuf);
  let l2 = gke.get('L2Index') as number;
  let l2Key: Buffer = Buffer.from(gke.get('L2Key') as Buffer);

  let reseedL2 = l2 === 31 || l1 !== (keyId.get('L1Index') as number);

  const kdfParamRaw = gke.get('KdfPara') as any;
  const kdfParam = (kdfParamRaw['HashName'] as Buffer).toString('utf16le');

  if (l2 !== 31 && l1 !== (keyId.get('L1Index') as number)) {
    l1 -= 1;
  }

  while (l1 !== (keyId.get('L1Index') as number)) {
    reseedL2 = true;
    l1 -= 1;

    l1Key = kdf(
      kdfParam,
      l1Key,
      KDS_SERVICE_LABEL,
      computeKdfContext(gke.get('RootKeyId') as Buffer, gke.get('L0Index') as number, l1, -1),
      64,
    );
  }

  if (reseedL2) {
    l2 = 31;
    l2Key = kdf(
      kdfParam,
      l1Key,
      KDS_SERVICE_LABEL,
      computeKdfContext(gke.get('RootKeyId') as Buffer, gke.get('L0Index') as number, l1, l2),
      64,
    );
  }

  while (l2 !== (keyId.get('L2Index') as number)) {
    l2 -= 1;
    l2Key = kdf(
      kdfParam,
      l2Key,
      KDS_SERVICE_LABEL,
      computeKdfContext(gke.get('RootKeyId') as Buffer, gke.get('L0Index') as number, l1, l2),
      64,
    );
  }

  return l2Key;
}

export function generateKekSecretFromPubkey(
  gke: GroupKeyEnvelope,
  keyId: KeyIdentifier,
  l2Key: Buffer,
): { secret: Buffer; context: Buffer } | undefined {
  const kdfParamRaw = gke.get('KdfPara') as any;
  const kdfParam = (kdfParamRaw['HashName'] as Buffer).toString('utf16le');

  const privateKey = kdf(
    kdfParam,
    l2Key,
    KDS_SERVICE_LABEL,
    gke.get('SecAlgo') as Buffer,
    Math.ceil((gke.get('PrivKeyLength') as number) / 8),
  );

  const secAlgo = (gke.get('SecAlgo') as Buffer).toString('utf16le');

  if (Buffer.from(secAlgo).equals(Buffer.from('DH\0'))) {
    const ffcdhKey = new FFCDHKey(keyId.get('Unknown') as Buffer);
    const pubKey = ffcdhKey.get('PubKey') as Buffer;
    const fieldOrder = ffcdhKey.get('FieldOrder') as Buffer;

    const pubKeyBigInt = BigInt('0x' + pubKey.toString('hex'));
    const privKeyBigInt = BigInt('0x' + privateKey.toString('hex'));
    const fieldOrderBigInt = BigInt('0x' + fieldOrder.toString('hex'));

    const sharedSecretInt = modPow(pubKeyBigInt, privKeyBigInt, fieldOrderBigInt);
    const hexStr = sharedSecretInt.toString(16);
    const sharedSecret = Buffer.from(hexStr.length % 2 ? '0' + hexStr : hexStr, 'hex');

    const kekContext = Buffer.from('KDS public key\0', 'utf16le');
    const otherinfo = Buffer.concat([
      Buffer.from('SHA512\0', 'utf16le'),
      kekContext,
      KDS_SERVICE_LABEL,
    ]);
    const secret = computeKdfHash(32, sharedSecret, otherinfo);
    return { secret, context: kekContext };
  } else if (secAlgo.includes('ECDH_P')) {
    const ecdhKey = new ECDHKey(keyId.get('Unknown') as Buffer);
    const x = ecdhKey.get('XCoordinate') as Buffer;
    const y = ecdhKey.get('YCoordinate') as Buffer;

    let curveName: string;
    if (secAlgo.includes('ECDH_P256')) {
      curveName = 'prime256v1';
    } else if (secAlgo.includes('ECDH_P384')) {
      curveName = 'secp384r1';
    } else if (secAlgo.includes('ECDH_P521')) {
      curveName = 'secp521r1';
    } else {
      return undefined;
    }

    const peerPubKey = Buffer.concat([Buffer.from([0x04]), x, y]);

    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(privateKey);
    const sharedSecret = ecdh.computeSecret(peerPubKey);

    const kekContext = Buffer.from('KDS public key\0', 'utf16le');
    const otherinfo = Buffer.concat([
      Buffer.from('SHA512\0', 'utf16le'),
      kekContext,
      KDS_SERVICE_LABEL,
    ]);
    const secret = computeKdfHash(32, sharedSecret, otherinfo);
    return { secret, context: kekContext };
  }

  return undefined;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

export function computeKek(gke: GroupKeyEnvelope, keyId: KeyIdentifier): Buffer {
  let kekContext: Buffer | undefined;
  let kekSecret: Buffer | undefined;

  const l2Key = computeL2Key(keyId, gke);
  const kdfParamRaw = gke.get('KdfPara') as any;
  const kdfParam = (kdfParamRaw['HashName'] as Buffer).toString('utf16le');

  if (keyId.isPublicKey()) {
    const result = generateKekSecretFromPubkey(gke, keyId, l2Key);
    if (!result) {
      throw new Error('Failed to generate KEK secret from public key');
    }
    kekSecret = result.secret;
    kekContext = result.context;
  } else {
    kekSecret = l2Key;
    kekContext = keyId.get('Unknown') as Buffer;
  }

  return kdf(kdfParam, kekSecret, KDS_SERVICE_LABEL, kekContext, 32);
}

export function aesUnwrap(wrappingKey: Buffer, wrappedKey: Buffer): Buffer | null {
  const aiv = Buffer.from([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);
  const r: Buffer[] = [];
  for (let i = 0; i < wrappedKey.length; i += 8) {
    r.push(Buffer.from(wrappedKey.subarray(i, i + 8)));
  }
  let a = r.shift()!;
  const n = r.length;

  for (let j = 5; j >= 0; j--) {
    for (let i = n - 1; i >= 0; i--) {
      const xorVal = BigInt(n * j + i + 1);
      const aBigInt = BigInt('0x' + a.toString('hex'));
      const xored = aBigInt ^ xorVal;
      const xoredHex = xored.toString(16).padStart(16, '0');
      const atr = Buffer.concat([Buffer.from(xoredHex, 'hex'), r[i]!]);

      const decipher = createDecipheriv('aes-256-ecb', wrappingKey, null as unknown as Uint8Array);
      decipher.setAutoPadding(false);
      const b = Buffer.concat([decipher.update(atr), decipher.final()]);
      a = b.subarray(0, 8);
      r[i] = b.subarray(8, 16);
    }
  }

  if (a.equals(aiv)) {
    return Buffer.concat(r);
  }
  return null;
}

export function unwrapCek(kek: Buffer, encryptedCek: Buffer): Buffer {
  const r = aesUnwrap(kek, encryptedCek);
  if (r === null) {
    throw new Error('Could not unwrap key');
  }
  return r;
}

export function decryptPlaintext(cek: Buffer, iv: Buffer, encryptedBlob: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', cek, iv);
  return Buffer.concat([decipher.update(encryptedBlob), decipher.final()]);
}
