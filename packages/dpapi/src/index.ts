/**
 * @impacket/dpapi - TypeScript port of impacket/dpapi.py and impacket/dpapi_ng.py
 *
 * DPAPI (Data Protection API) parsing and decryption for Windows credential
 * blobs, master keys, vault files, etc.
 *
 * DPAPI-NG (CNG DPAPI / DPAPI Next Generation) key derivation and decryption.
 *
 * References:
 *   - https://www.passcape.com/index.php?section=docsys&cmd=details&id=28
 *   - https://github.com/jordanbtucker/dpapick
 *   - https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials
 *   - http://blog.digital-forensics.it/2016/01/windows-revaulting.html
 *   - https://www.passcape.com/windows_password_recovery_vault_explorer
 *   - https://www.passcape.com/windows_password_recovery_dpapi_master_key
 */

import { Buffer } from 'node:buffer';
import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  pbkdf2Sync,
} from 'node:crypto';
import { type FieldDescriptor, Structure, hexdump } from '@impacket/structure';
import { md4Hash } from '@impacket/crypto';

// ---------------------------------------------------------------------------
// Algorithm class constants
// ---------------------------------------------------------------------------
export const ALG_CLASS_ANY = 0;
export const ALG_CLASS_SIGNATURE = 1 << 13;
export const ALG_CLASS_MSG_ENCRYPT = 2 << 13;
export const ALG_CLASS_DATA_ENCRYPT = 3 << 13;
export const ALG_CLASS_HASH = 4 << 13;
export const ALG_CLASS_KEY_EXCHANGE = 5 << 13;
export const ALG_CLASS_ALL = 7 << 13;

// Algorithm types
export const ALG_TYPE_ANY = 0;
export const ALG_TYPE_DSS = 1 << 9;
export const ALG_TYPE_RSA = 2 << 9;
export const ALG_TYPE_BLOCK = 3 << 9;
export const ALG_TYPE_STREAM = 4 << 9;
export const ALG_TYPE_DH = 5 << 9;
export const ALG_TYPE_SECURECHANNEL = 6 << 9;

export const ALG_SID_ANY = 0;
export const ALG_SID_RSA_ANY = 0;
export const ALG_SID_RSA_PKCS = 1;
export const ALG_SID_RSA_MSATWORK = 2;
export const ALG_SID_RSA_ENTRUST = 3;
export const ALG_SID_RSA_PGP = 4;
export const ALG_SID_DSS_ANY = 0;
export const ALG_SID_DSS_PKCS = 1;
export const ALG_SID_DSS_DMS = 2;
export const ALG_SID_ECDSA = 3;

// Block cipher sub ids
export const ALG_SID_DES = 1;
export const ALG_SID_3DES = 3;
export const ALG_SID_DESX = 4;
export const ALG_SID_IDEA = 5;
export const ALG_SID_CAST = 6;
export const ALG_SID_SAFERSK64 = 7;
export const ALG_SID_SAFERSK128 = 8;
export const ALG_SID_3DES_112 = 9;
export const ALG_SID_CYLINK_MEK = 12;
export const ALG_SID_RC5 = 13;
export const ALG_SID_AES_128 = 14;
export const ALG_SID_AES_192 = 15;
export const ALG_SID_AES_256 = 16;
export const ALG_SID_AES = 17;
export const ALG_SID_SKIPJACK = 10;
export const ALG_SID_TEK = 11;

export const CRYPT_MODE_CBCI = 6;
export const CRYPT_MODE_CFBP = 7;
export const CRYPT_MODE_OFBP = 8;
export const CRYPT_MODE_CBCOFM = 9;
export const CRYPT_MODE_CBCOFMI = 10;

export const ALG_SID_RC2 = 2;
export const ALG_SID_RC4 = 1;
export const ALG_SID_SEAL = 2;

// Diffie-Hellman sub ids
export const ALG_SID_DH_SANDF = 1;
export const ALG_SID_DH_EPHEM = 2;
export const ALG_SID_AGREED_KEY_ANY = 3;
export const ALG_SID_KEA = 4;
export const ALG_SID_ECDH = 5;

// Hash sub ids
export const ALG_SID_MD2 = 1;
export const ALG_SID_MD4 = 2;
export const ALG_SID_MD5 = 3;
export const ALG_SID_SHA = 4;
export const ALG_SID_SHA1 = 4;
export const ALG_SID_MAC = 5;
export const ALG_SID_RIPEMD = 6;
export const ALG_SID_RIPEMD160 = 7;
export const ALG_SID_SSL3SHAMD5 = 8;
export const ALG_SID_HMAC = 9;
export const ALG_SID_TLS1PRF = 10;
export const ALG_SID_HASH_REPLACE_OWF = 11;
export const ALG_SID_SHA_256 = 12;
export const ALG_SID_SHA_384 = 13;
export const ALG_SID_SHA_512 = 14;

// Secure channel sub ids
export const ALG_SID_SSL3_MASTER = 1;
export const ALG_SID_SCHANNEL_MASTER_HASH = 2;
export const ALG_SID_SCHANNEL_MAC_KEY = 3;
export const ALG_SID_PCT1_MASTER = 4;
export const ALG_SID_SSL2_MASTER = 5;
export const ALG_SID_TLS1_MASTER = 6;
export const ALG_SID_SCHANNEL_ENC_KEY = 7;
export const ALG_SID_ECMQV = 1;

// ---------------------------------------------------------------------------
// Enums (ported from Python Enum classes)
// ---------------------------------------------------------------------------

export function getFlags(myenum: Record<string, number>, flags: number): string {
  return Object.entries(myenum)
    .filter(([, v]) => typeof v === 'number' && (v & flags) !== 0)
    .map(([name]) => name)
    .join('|');
}

export const FLAGS = {
  CRYPTPROTECT_UI_FORBIDDEN: 0x1,
  CRYPTPROTECT_LOCAL_MACHINE: 0x4,
  CRYPTPROTECT_CRED_SYNC: 0x8,
  CRYPTPROTECT_AUDIT: 0x10,
  CRYPTPROTECT_VERIFY_PROTECTION: 0x40,
  CRYPTPROTECT_CRED_REGENERATE: 0x80,
  CRYPTPROTECT_SYSTEM: 0x20000000,
} as const;

export const ALGORITHMS = {
  CALG_MD2: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2,
  CALG_MD4: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4,
  CALG_MD5: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5,
  CALG_SHA: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA,
  CALG_SHA1: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1,
  CALG_RSA_SIGN: ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY,
  CALG_DSS_SIGN: ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY,
  CALG_NO_SIGN: ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY,
  CALG_RSA_KEYX: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY,
  CALG_DES: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES,
  CALG_3DES_112: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES_112,
  CALG_3DES: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES,
  CALG_DESX: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DESX,
  CALG_RC2: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC2,
  CALG_RC4: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_RC4,
  CALG_SEAL: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_SEAL,
  CALG_DH_SF: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_SANDF,
  CALG_DH_EPHEM: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EPHEM,
  CALG_AGREEDKEY_ANY: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_AGREED_KEY_ANY,
  CALG_KEA_KEYX: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_KEA,
  CALG_HUGHES_MD5: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_MD5,
  CALG_SKIPJACK: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SKIPJACK,
  CALG_TEK: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_TEK,
  CALG_SSL3_SHAMD5: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5,
  CALG_SSL3_MASTER: ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL3_MASTER,
  CALG_SCHANNEL_MASTER_HASH:
    ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MASTER_HASH,
  CALG_SCHANNEL_MAC_KEY:
    ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY,
  CALG_SCHANNEL_ENC_KEY:
    ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY,
  CALG_PCT1_MASTER: ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_PCT1_MASTER,
  CALG_SSL2_MASTER: ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL2_MASTER,
  CALG_TLS1_MASTER: ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_TLS1_MASTER,
  CALG_RC5: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC5,
  CALG_HMAC: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC,
  CALG_TLS1PRF: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF,
  CALG_HASH_REPLACE_OWF: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF,
  CALG_AES_128: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_128,
  CALG_AES_192: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_192,
  CALG_AES_256: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
  CALG_AES: ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES,
  CALG_SHA_256: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
  CALG_SHA_384: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384,
  CALG_SHA_512: ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512,
  CALG_ECDH: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH,
  CALG_ECMQV: ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_ECMQV,
  CALG_ECDSA: ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA,
} as const;

/** Reverse lookup: algorithm value -> name */
const ALGORITHMS_BY_VALUE: Record<number, string> = {};
for (const [name, val] of Object.entries(ALGORITHMS)) {
  ALGORITHMS_BY_VALUE[val] = name;
}

export function algorithmName(value: number): string {
  return ALGORITHMS_BY_VALUE[value] ?? `UNKNOWN(0x${value.toString(16)})`;
}

export const CREDENTIAL_FLAGS = {
  CRED_FLAGS_PASSWORD_FOR_CERT: 0x1,
  CRED_FLAGS_PROMPT_NOW: 0x2,
  CRED_FLAGS_USERNAME_TARGET: 0x4,
  CRED_FLAGS_OWF_CRED_BLOB: 0x8,
  CRED_FLAGS_REQUIRE_CONFIRMATION: 0x10,
  CRED_FLAGS_WILDCARD_MATCH: 0x20,
  CRED_FLAGS_VSM_PROTECTED: 0x40,
  CRED_FLAGS_NGC_CERT: 0x80,
} as const;

export const CREDENTIAL_TYPE = {
  CRED_TYPE_GENERIC: 0x1,
  CRED_TYPE_DOMAIN_PASSWORD: 0x2,
  CRED_TYPE_DOMAIN_CERTIFICATE: 0x3,
  CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: 0x4,
  CRED_TYPE_GENERIC_CERTIFICATE: 0x5,
  CRED_TYPE_DOMAIN_EXTENDED: 0x6,
  CRED_TYPE_MAXIMUM: 0x7,
  CRED_TYPE_MAXIMUM_EX: 0x8,
} as const;

const CREDENTIAL_TYPE_BY_VALUE: Record<number, string> = {};
for (const [name, val] of Object.entries(CREDENTIAL_TYPE)) {
  CREDENTIAL_TYPE_BY_VALUE[val] = name;
}

export const CREDENTIAL_PERSIST = {
  CRED_PERSIST_NONE: 0x0,
  CRED_PERSIST_SESSION: 0x1,
  CRED_PERSIST_LOCAL_MACHINE: 0x2,
  CRED_PERSIST_ENTERPRISE: 0x3,
} as const;

const CREDENTIAL_PERSIST_BY_VALUE: Record<number, string> = {};
for (const [name, val] of Object.entries(CREDENTIAL_PERSIST)) {
  CREDENTIAL_PERSIST_BY_VALUE[val] = name;
}

// ---------------------------------------------------------------------------
// ALGORITHMS_DATA: maps algorithm value -> [keyLen, hashAlg, cipherAlg, ivLen, blockSize?]
//
// In Python: {algVal: (keyLen, HashModule, Mode, IVLen, BlockSize)}
// We store: {algVal: {keyLen, hashAlg, cipherAlg, ivLen, blockSize}}
// ---------------------------------------------------------------------------

interface AlgorithmData {
  keyLen: number;
  hashAlg: string; // 'sha1' | 'sha512'
  cipherAlg?: string; // 'des-ede3-cbc' | 'aes-256-cbc'
  ivLen?: number;
  blockSize?: number;
}

export const ALGORITHMS_DATA: Record<number, AlgorithmData> = {
  [ALGORITHMS.CALG_SHA]: {
    keyLen: 160 / 8,
    hashAlg: 'sha1',
    blockSize: 512 / 8,
  },
  [ALGORITHMS.CALG_HMAC]: {
    keyLen: 160 / 8,
    hashAlg: 'sha512',
    blockSize: 512 / 8,
  },
  [ALGORITHMS.CALG_3DES]: {
    keyLen: 192 / 8,
    hashAlg: 'des-ede3-cbc',
    cipherAlg: 'des-ede3-cbc',
    ivLen: 64 / 8,
  },
  [ALGORITHMS.CALG_SHA_512]: {
    keyLen: 128 / 8,
    hashAlg: 'sha512',
    blockSize: 1024 / 8,
  },
  [ALGORITHMS.CALG_AES_256]: {
    keyLen: 256 / 8,
    hashAlg: 'aes-256-cbc',
    cipherAlg: 'aes-256-cbc',
    ivLen: 128 / 8,
  },
};

// ---------------------------------------------------------------------------
// Helper: convert Windows FILETIME (100-ns intervals since 1601-01-01) to unix timestamp
// ---------------------------------------------------------------------------

const EPOCH_DIFF = 116444736000000000n; // 100-ns intervals between 1601 and 1970

export function getUnixTime(filetime: number | bigint): number {
  const ft = BigInt(filetime);
  return Number((ft - EPOCH_DIFF) / 10000000n);
}

/** Binary GUID -> canonical string (mixed-endian). */
export function binToString(guid: Buffer): string {
  const d1 = guid.readUInt32LE(0);
  const d2 = guid.readUInt16LE(4);
  const d3 = guid.readUInt16LE(6);
  const d4 = guid.readUInt16BE(8);
  const d5 = guid.readUInt16BE(10);
  const d6 = guid.readUInt32BE(12);
  return (
    `${d1.toString(16).padStart(8, '0').toUpperCase()}-` +
    `${d2.toString(16).padStart(4, '0').toUpperCase()}-` +
    `${d3.toString(16).padStart(4, '0').toUpperCase()}-` +
    `${d4.toString(16).padStart(4, '0').toUpperCase()}-` +
    `${d5.toString(16).padStart(4, '0').toUpperCase()}` +
    `${d6.toString(16).padStart(8, '0').toUpperCase()}`
  );
}

/** Format a raw SID buffer as canonical string (S-1-...). */
function formatSidCanonical(data: Buffer): string {
  // SID: revision (1 byte), subAuthCount (1 byte), identifierAuth (6 bytes BE), subAuths (4 bytes LE each)
  const revision = data.readUInt8(0);
  const subAuthorityCount = data.readUInt8(1);
  // Identifier authority: 6 bytes big-endian
  const identAuth =
    data[2]! === 0 && data[3]! === 0
      ? data.readUInt32BE(4) // small authority value
      : Number(data.readBigUInt64BE(0) & 0xffffffffffffn); // 48-bit
  let sid = `S-${revision}-${identAuth}`;
  for (let i = 0; i < subAuthorityCount; i++) {
    sid += `-${data.readUInt32LE(8 + i * 4)}`;
  }
  return sid;
}

// ---------------------------------------------------------------------------
// HMAC helper: returns digest for given hash algorithm
// ---------------------------------------------------------------------------

function hmacDigest(key: Buffer, data: Buffer, hashAlg: string): Buffer {
  return createHmac(hashAlg, key).update(data).digest();
}

function hashDigest(data: Buffer, hashAlg: string): Buffer {
  return createHash(hashAlg).update(data).digest();
}

function hashBlockSize(hashAlg: string): number {
  if (hashAlg === 'sha1') return 64;
  if (hashAlg === 'sha256') return 64;
  if (hashAlg === 'sha384') return 128;
  if (hashAlg === 'sha512') return 64;
  return 64;
}

/** Cipher decrypt helper. */
function cipherDecrypt(alg: string, key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const decipher = createDecipheriv(alg, key, iv);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

/** Cipher encrypt helper. */
function cipherEncrypt(alg: string, key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = createCipheriv(alg, key, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/** Remove PKCS#7 padding. */
function unpad(data: Buffer, blockSize: number): Buffer {
  if (data.length === 0) return data;
  const padLen = data[data.length - 1]!;
  if (padLen < 1 || padLen > blockSize) return data;
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) return data;
  }
  return data.subarray(0, data.length - padLen);
}

/** Get the hash algorithm name for a given CALG value (for HMAC operations). */
function getHashAlgName(algValue: number): string {
  if (algValue === ALGORITHMS.CALG_HMAC || algValue === ALGORITHMS.CALG_SHA) return 'sha1';
  const data = ALGORITHMS_DATA[algValue];
  if (data) {
    // Return the hash alg name if it's a hash type
    if (data.hashAlg === 'sha1' || data.hashAlg === 'sha512' || data.hashAlg === 'sha256') {
      return data.hashAlg;
    }
  }
  return 'sha1';
}

/** Get the block size for the hash algorithm referenced by a CALG value. */
function getHashBlockSize(algValue: number): number {
  const data = ALGORITHMS_DATA[algValue];
  if (data?.blockSize) return data.blockSize;
  return 64;
}

/** Get the digest size for a hash algorithm. */
function getHashDigestSize(hashAlg: string): number {
  switch (hashAlg) {
    case 'sha1':
      return 20;
    case 'sha256':
      return 32;
    case 'sha384':
      return 48;
    case 'sha512':
      return 64;
    case 'md5':
      return 16;
    default:
      return 20;
  }
}

// ---------------------------------------------------------------------------
// DPAPI Structures
// ---------------------------------------------------------------------------

export class MasterKeyFile extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['unk1', '<L=0'],
    ['unk2', '<L=0'],
    ['Guid', "72s=b''"],
    ['Unkown', '<L=0'],
    ['Policy', '<L=0'],
    ['Flags', '<L=0'],
    ['MasterKeyLen', '<Q=0'],
    ['BackupKeyLen', '<Q=0'],
    ['CredHistLen', '<Q=0'],
    ['DomainKeyLen', '<Q=0'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[MASTERKEYFILE]');
    const version = Number(this.get('Version'));
    const flags = Number(this.get('Flags'));
    const policy = Number(this.get('Policy'));
    const mkLen = Number(this.get('MasterKeyLen'));
    const bkLen = Number(this.get('BackupKeyLen'));
    const chLen = Number(this.get('CredHistLen'));
    const dkLen = Number(this.get('DomainKeyLen'));
    const guidBuf = this.get('Guid') as Buffer;
    lines.push(`Version     : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`Guid        : ${guidBuf.toString('utf16le')}`);
    lines.push(`Flags       : ${flags.toString(16).padStart(8, ' ')} (${flags})`);
    lines.push(`Policy      : ${policy.toString(16).padStart(8, ' ')} (${policy})`);
    lines.push(
      `MasterKeyLen: ${mkLen.toString(16).padStart(8, '0')} (${mkLen})`,
    );
    lines.push(
      `BackupKeyLen: ${bkLen.toString(16).padStart(8, '0')} (${bkLen})`,
    );
    lines.push(
      `CredHistLen : ${chLen.toString(16).padStart(8, '0')} (${chLen})`,
    );
    lines.push(
      `DomainKeyLen: ${dkLen.toString(16).padStart(8, '0')} (${dkLen})`,
    );
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class MasterKey extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Salt', '16s=b""'],
    ['MasterKeyIterationCount', '<L=0'],
    ['HashAlgo', '<L=0'],
    ['CryptAlgo', '<L=0'],
    ['data', ':'],
  ];

  decryptedKey: Buffer | null = null;

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    this.decryptedKey = null;
  }

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[MASTERKEY]');
    const version = Number(this.get('Version'));
    const salt = this.get('Salt') as Buffer;
    const rounds = Number(this.get('MasterKeyIterationCount'));
    const hashAlgo = Number(this.get('HashAlgo'));
    const cryptAlgo = Number(this.get('CryptAlgo'));
    const dataField = this.get('data') as Buffer;
    lines.push(`Version     : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`Salt        : ${salt.toString('hex')}`);
    lines.push(`Rounds      : ${rounds.toString(16).padStart(8, ' ')} (${rounds})`);
    lines.push(
      `HashAlgo    : ${hashAlgo.toString(16).padStart(8, '0')} (${hashAlgo}) (${algorithmName(hashAlgo)})`,
    );
    lines.push(
      `CryptAlgo   : ${cryptAlgo.toString(16).padStart(8, '0')} (${cryptAlgo}) (${algorithmName(cryptAlgo)})`,
    );
    lines.push(`data        : ${dataField.toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }

  /** PBKDF1-like key derivation used by DPAPI master key. */
  pbkdf1DeriveKey(
    passphrase: Buffer,
    salt: Buffer,
    keylen: number,
    count: number,
    hashFunction: (p: Buffer, s: Buffer) => Buffer,
  ): Buffer {
    let keyMaterial = Buffer.alloc(0);
    let i = 1;
    while (keyMaterial.length < keylen) {
      const uSalt = Buffer.concat([salt, Buffer.alloc(4)]);
      uSalt.writeUInt32BE(i, salt.length);
      i += 1;
      let derived = Buffer.from(hashFunction(passphrase, uSalt));
      for (let r = 0; r < count - 1; r++) {
        const actual = Buffer.from(hashFunction(passphrase, derived));
        // XOR derived and actual
        const xored = Buffer.alloc(actual.length);
        for (let j = 0; j < actual.length; j++) {
          xored[j] = derived[j]! ^ actual[j]!;
        }
        derived = xored;
      }
      keyMaterial = Buffer.concat([keyMaterial, derived]);
    }
    return keyMaterial.subarray(0, keylen);
  }

  decrypt(key: Buffer): Buffer | null {
    const hashAlgoVal = Number(this.get('HashAlgo'));
    const cryptAlgoVal = Number(this.get('CryptAlgo'));

    // For CALG_HMAC, use SHA1 as the underlying hash
    const hashAlg = hashAlgoVal === ALGORITHMS.CALG_HMAC ? 'sha1' : getHashAlgName(hashAlgoVal);

    const prf = (p: Buffer, s: Buffer): Buffer => hmacDigest(p, s, hashAlg);

    const cryptData = ALGORITHMS_DATA[cryptAlgoVal];
    if (!cryptData || !cryptData.cipherAlg || cryptData.ivLen == null) {
      console.warn(`Unsupported crypt algorithm: ${algorithmName(cryptAlgoVal)}`);
      return null;
    }

    const derivedBlob = this.pbkdf1DeriveKey(
      key,
      this.get('Salt') as Buffer,
      cryptData.keyLen + cryptData.ivLen,
      Number(this.get('MasterKeyIterationCount')),
      prf,
    );

    const cryptKey = derivedBlob.subarray(0, cryptData.keyLen);
    const iv = derivedBlob.subarray(cryptData.keyLen, cryptData.keyLen + cryptData.ivLen);

    const cleartext = cipherDecrypt(cryptData.cipherAlg, cryptKey, iv, this.get('data') as Buffer);

    const decryptedKey = cleartext.subarray(cleartext.length - 64);
    const hmacSalt = cleartext.subarray(0, 16);
    const hashData = ALGORITHMS_DATA[hashAlgoVal];
    const hmacLen = hashData?.keyLen ?? 20;
    const hmac = cleartext.subarray(16, 16 + hmacLen);

    const hmacKey = hmacDigest(key, hmacSalt, hashAlg);
    const hmacCalculated = hmacDigest(hmacKey, decryptedKey, hashAlg);

    if (hmacCalculated.subarray(0, hmacLen).equals(hmac)) {
      this.decryptedKey = decryptedKey;
      return decryptedKey;
    }
    return null;
  }
}

export class CredHist extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Guid', "16s=b''"],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[CREDHIST]');
    const version = Number(this.get('Version'));
    const guid = this.get('Guid') as Buffer;
    lines.push(`Version       : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`Guid          : ${binToString(guid)}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class CREDHIST_ENTRY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['HashAlgo', '<L=0'],
    ['Rounds', '<L=0'],
    ['SidLen', '<L=0'],
    ['_Sid', '_-Sid', 'self["SidLen"]'],
    ['CryptAlgo', '<L=0'],
    ['shaHashLen', '<L=0'],
    ['ntHashLen', '<L=0'],
    ['Salt', '16s=b""'],
    ['Sid', ':'],
    [
      '_data',
      '_-data',
      '(self["shaHashLen"]+self["ntHashLen"]) + (-(self["shaHashLen"]+self["ntHashLen"])) % 16',
    ],
    ['data', ':'],
    ['Version2', '<L=0'],
    ['Guid', '16s=b""'],
  ];

  sid = '';
  pwdhash: Buffer | null = null;
  nthash: Buffer | null = null;

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data) {
      const sidBuf = this.get('Sid') as Buffer;
      const withPrefix = Buffer.concat([Buffer.from([0x05, 0x00, 0x00, 0x00]), sidBuf]);
      this.sid = formatSidCanonical(withPrefix);
    }
    this.pwdhash = null;
    this.nthash = null;
  }

  /** PBKDF1-like key derivation. */
  pbkdf1DeriveKey(
    passphrase: Buffer,
    salt: Buffer,
    keylen: number,
    count: number,
    hashFunction: (p: Buffer, s: Buffer) => Buffer,
  ): Buffer {
    let keyMaterial = Buffer.alloc(0);
    let i = 1;
    while (keyMaterial.length < keylen) {
      const uSalt = Buffer.concat([salt, Buffer.alloc(4)]);
      uSalt.writeUInt32BE(i, salt.length);
      i += 1;
      let derived = Buffer.from(hashFunction(passphrase, uSalt));
      for (let r = 0; r < count - 1; r++) {
        const actual = Buffer.from(hashFunction(passphrase, derived));
        const xored = Buffer.alloc(actual.length);
        for (let j = 0; j < actual.length; j++) {
          xored[j] = derived[j]! ^ actual[j]!;
        }
        derived = xored;
      }
      keyMaterial = Buffer.concat([keyMaterial, derived]);
    }
    return keyMaterial.subarray(0, keylen);
  }

  decrypt(key: Buffer): void {
    const hashAlgoVal = Number(this.get('HashAlgo'));
    const cryptAlgoVal = Number(this.get('CryptAlgo'));

    const hashAlg = hashAlgoVal === ALGORITHMS.CALG_HMAC ? 'sha1' : getHashAlgName(hashAlgoVal);
    const prf = (p: Buffer, s: Buffer): Buffer => hmacDigest(p, s, hashAlg);

    const cryptData = ALGORITHMS_DATA[cryptAlgoVal];
    if (!cryptData || !cryptData.cipherAlg || cryptData.ivLen == null) return;

    const derivedBlob = this.pbkdf1DeriveKey(
      key,
      this.get('Salt') as Buffer,
      cryptData.keyLen + cryptData.ivLen,
      Number(this.get('Rounds')),
      prf,
    );

    const cryptKey = derivedBlob.subarray(0, cryptData.keyLen);
    const iv = derivedBlob.subarray(cryptData.keyLen, cryptData.keyLen + cryptData.ivLen);

    const cleartext = cipherDecrypt(cryptData.cipherAlg, cryptKey, iv, this.get('data') as Buffer);

    const shaHashLen = Number(this.get('shaHashLen'));
    const ntHashSize = 16;
    this.pwdhash = cleartext.subarray(0, shaHashLen);
    this.nthash = cleartext.subarray(shaHashLen, shaHashLen + ntHashSize);

    const remaining = cleartext.subarray(shaHashLen + ntHashSize);
    const dataLen = (this.get('data') as Buffer).length;
    const expectedZeros = Buffer.alloc(dataLen - shaHashLen - ntHashSize, 0);
    if (!remaining.equals(expectedZeros)) {
      this.pwdhash = null;
      this.nthash = null;
    }
  }

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[CREDHIST ENTRY]');
    const version = Number(this.get('Version'));
    const hashAlgo = Number(this.get('HashAlgo'));
    const rounds = Number(this.get('Rounds'));
    const cryptAlgo = Number(this.get('CryptAlgo'));
    const shaHashLen = Number(this.get('shaHashLen'));
    const ntHashLen = Number(this.get('ntHashLen'));
    const salt = this.get('Salt') as Buffer;
    const version2 = Number(this.get('Version2'));
    const guid = this.get('Guid') as Buffer;
    lines.push(
      `Version    : 0x${version.toString(16).padStart(8, '0')} (${version})`,
    );
    lines.push(
      `HashAlgo   : 0x${hashAlgo.toString(16).padStart(8, '0')} (${hashAlgo}) (${algorithmName(hashAlgo)})`,
    );
    lines.push(`Rounds     : ${rounds}`);
    lines.push(
      `CryptAlgo  : 0x${cryptAlgo.toString(16).padStart(8, '0')} (${cryptAlgo}) (${algorithmName(cryptAlgo)})`,
    );
    lines.push(
      `shaHashLen : 0x${shaHashLen.toString(16).padStart(8, '0')} (${shaHashLen})`,
    );
    lines.push(
      `ntHashLen  : 0x${ntHashLen.toString(16).padStart(8, '0')} (${ntHashLen})`,
    );
    lines.push(`Salt       : ${salt.toString('hex')}`);
    lines.push(`SID        : ${this.sid}`);
    lines.push(
      `Version2   : 0x${version2.toString(16).padStart(8, '0')} (${version2})`,
    );
    lines.push(`Guid       : ${binToString(guid)}`);
    if (this.pwdhash !== null && this.nthash !== null) {
      lines.push(`pwdHash    : ${this.pwdhash.toString('hex')}`);
      lines.push(`ntHash     : ${this.nthash.toString('hex')}`);
    } else {
      lines.push(`Data       : ${(this.get('data') as Buffer).toString('hex')}`);
    }
    for (const l of lines) console.debug(l);
    return lines;
  }

  summarize(): string[] {
    const lines: string[] = [];
    lines.push('[CREDHIST ENTRY]');
    const guid = this.get('Guid') as Buffer;
    lines.push(`Guid       : ${binToString(guid)}`);
    if (this.pwdhash !== null && this.nthash !== null) {
      lines.push(`pwdHash    : ${this.pwdhash.toString('hex')}`);
      lines.push(`ntHash     : ${this.nthash.toString('hex')}`);
    } else {
      lines.push(`Data       : ${(this.get('data') as Buffer).toString('hex')}`);
    }
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class CREDHIST_FILE {
  credhistEntries: Record<string, CREDHIST_ENTRY> = {};
  credhistEntriesList: CREDHIST_ENTRY[] = [];
  version: number;
  currentGuid: Buffer;

  constructor(raw: Buffer) {
    this.version = raw.readUInt32LE(0);
    this.currentGuid = raw.subarray(4, 20);

    let i = 0;
    let nextLen = raw.readUInt32LE(raw.length - i - 4);
    i += 4;
    while (nextLen !== 0) {
      const entryData = raw.subarray(raw.length - (i + nextLen - 4), raw.length - i);
      const chEntry = new CREDHIST_ENTRY(entryData);
      i += nextLen - 4;
      this.credhistEntries[binToString(chEntry.get('Guid') as Buffer)] = chEntry;
      this.credhistEntriesList.push(chEntry);
      nextLen = raw.readUInt32LE(raw.length - i - 4);
      i += 4;
    }
  }

  decryptEntryByIndex(entryIndex: number, key: Buffer): void {
    this.credhistEntriesList[entryIndex]!.decrypt(key);
  }

  decryptEntryByGuid(guid: string, key: Buffer): void {
    this.credhistEntries[guid]!.decrypt(key);
  }

  decrypt(key: Buffer): void {
    let keys = [key];
    for (let i = 0; i < this.credhistEntriesList.length; i++) {
      const e = this.credhistEntriesList[i]!;
      for (const k of keys) {
        e.decrypt(k);
        if (e.pwdhash !== null) break;
      }
      if (e.pwdhash === null) {
        console.warn(`Error decrypting entry #${i}`);
        return;
      }
      keys = deriveKeysFromUserkey(e.sid, e.pwdhash);
    }
  }

  dump(): string[] {
    const lines: string[] = [];
    lines.push('[CREDHIST FILE]');
    lines.push(
      `Version        : 0x${this.version.toString(16).padStart(8, '0')} (${this.version})`,
    );
    lines.push(`Current Guid   : ${binToString(this.currentGuid)}`);
    for (let i = 0; i < this.credhistEntriesList.length; i++) {
      lines.push(`[Entry #${i}]`);
      lines.push(...this.credhistEntriesList[i]!.dump());
    }
    for (const l of lines) console.debug(l);
    return lines;
  }

  summarize(): string[] {
    const lines: string[] = [];
    lines.push('[CREDHIST FILE]');
    lines.push(
      `Version        : 0x${this.version.toString(16).padStart(8, '0')} (${this.version})`,
    );
    lines.push(`Current Guid   : ${binToString(this.currentGuid)}`);
    for (let i = 0; i < this.credhistEntriesList.length; i++) {
      lines.push(`[Entry #${i}]`);
      lines.push(...this.credhistEntriesList[i]!.summarize());
    }
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class DomainKey extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['SecretLen', '<L=0'],
    ['AccessCheckLen', '<L=0'],
    ['Guid', '16s=b""'],
    ['_SecretData', '_-SecretData', 'self["SecretLen"]'],
    ['SecretData', ':'],
    ['_AccessCheck', '_-AccessCheck', 'self["AccessCheckLen"]'],
    ['AccessCheck', ':'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[DOMAINKEY]');
    const version = Number(this.get('Version'));
    const secretLen = Number(this.get('SecretLen'));
    const accessCheckLen = Number(this.get('AccessCheckLen'));
    const guid = this.get('Guid') as Buffer;
    const secretData = this.get('SecretData') as Buffer;
    const accessCheck = this.get('AccessCheck') as Buffer;
    lines.push(`Version       : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`Guid          : ${binToString(guid)}`);
    lines.push(`SecretLen     : ${secretLen.toString(16).padStart(8, ' ')} (${secretLen})`);
    lines.push(
      `AccessCheckLen: ${accessCheckLen.toString(16).padStart(8, '0')} (${accessCheckLen})`,
    );
    lines.push(`SecretData    : ${secretData.toString('hex')}`);
    lines.push(`AccessCheck   : ${accessCheck.toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class DPAPI_SYSTEM extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['MachineKey', '20s=b""'],
    ['UserKey', '20s=b""'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[DPAPI_SYSTEM]');
    const version = Number(this.get('Version'));
    const machineKey = this.get('MachineKey') as Buffer;
    const userKey = this.get('UserKey') as Buffer;
    lines.push(`Version    : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`MachineKey : 0x${machineKey.toString('hex')}`);
    lines.push(`UserKey    : 0x${userKey.toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class CredentialFile extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Size', '<L=0'],
    ['Unknown', '<L=0'],
    ['_Data', '_-Data', 'self["Size"]'],
    ['Data', ':'],
  ];
}

export class DPAPI_BLOB extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['GuidCredential', '16s=b""'],
    ['MasterKeyVersion', '<L=0'],
    ['GuidMasterKey', '16s=b""'],
    ['Flags', '<L=0'],
    ['DescriptionLen', '<L=0'],
    ['_Description', '_-Description', 'self["DescriptionLen"]'],
    ['Description', ':'],
    ['CryptAlgo', '<L=0'],
    ['CryptAlgoLen', '<L=0'],
    ['SaltLen', '<L=0'],
    ['_Salt', '_-Salt', 'self["SaltLen"]'],
    ['Salt', ':'],
    ['HMacKeyLen', '<L=0'],
    ['_HMacKey', '_-HMacKey', 'self["HMacKeyLen"]'],
    ['HMacKey', ':'],
    ['HashAlgo', '<L=0'],
    ['HashAlgoLen', '<L=0'],
    ['HMacLen', '<L=0'],
    ['_HMac', '_-HMac', 'self["HMacLen"]'],
    ['HMac', ':'],
    ['DataLen', '<L=0'],
    ['_Data', '_-Data', 'self["DataLen"]'],
    ['Data', ':'],
    ['SignLen', '<L=0'],
    ['_Sign', '_-Sign', 'self["SignLen"]'],
    ['Sign', ':'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[BLOB]');
    const version = Number(this.get('Version'));
    const guidCred = this.get('GuidCredential') as Buffer;
    const mkVersion = Number(this.get('MasterKeyVersion'));
    const guidMK = this.get('GuidMasterKey') as Buffer;
    const flags = Number(this.get('Flags'));
    const desc = this.get('Description') as Buffer;
    const cryptAlgo = Number(this.get('CryptAlgo'));
    const salt = this.get('Salt') as Buffer;
    const hmacKey = this.get('HMacKey') as Buffer;
    const hashAlgo = Number(this.get('HashAlgo'));
    const hmac = this.get('HMac') as Buffer;
    const data = this.get('Data') as Buffer;
    const sign = this.get('Sign') as Buffer;
    lines.push(`Version          : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`Guid Credential  : ${binToString(guidCred)}`);
    lines.push(
      `MasterKeyVersion : ${mkVersion.toString(16).padStart(8, ' ')} (${mkVersion})`,
    );
    lines.push(`Guid MasterKey   : ${binToString(guidMK)}`);
    lines.push(
      `Flags            : ${flags.toString(16).padStart(8, ' ')} (${getFlags(FLAGS, flags)})`,
    );
    lines.push(`Description      : ${desc.toString('utf16le')}`);
    lines.push(
      `CryptAlgo        : ${cryptAlgo.toString(16).padStart(8, '0')} (${cryptAlgo}) (${algorithmName(cryptAlgo)})`,
    );
    lines.push(`Salt             : ${salt.toString('hex')}`);
    lines.push(`HMacKey          : ${hmacKey.toString('hex')}`);
    lines.push(
      `HashAlgo         : ${hashAlgo.toString(16).padStart(8, '0')} (${hashAlgo}) (${algorithmName(hashAlgo)})`,
    );
    lines.push(`HMac             : ${hmac.toString('hex')}`);
    lines.push(`Data             : ${data.toString('hex')}`);
    lines.push(`Sign             : ${sign.toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }

  deriveKey(sessionKey: Buffer): Buffer {
    function fixparity(deskey: Buffer): Buffer {
      const temp = Buffer.alloc(deskey.length);
      for (let i = 0; i < deskey.length; i++) {
        const t = deskey[i]!.toString(2).padStart(8, '0');
        const top7 = t.slice(0, 7);
        const onesCount = top7.split('').filter((c) => c === '1').length;
        if (onesCount % 2 === 0) {
          temp[i] = parseInt(top7 + '1', 2);
        } else {
          temp[i] = parseInt(top7 + '0', 2);
        }
      }
      return temp;
    }

    const hashAlgoVal = Number(this.get('HashAlgo'));
    const cryptAlgoVal = Number(this.get('CryptAlgo'));
    const hashAlg = getHashAlgName(hashAlgoVal);
    const hashBlockSz = getHashBlockSize(hashAlgoVal);

    let derivedKey: Buffer;
    if (sessionKey.length > hashBlockSz) {
      derivedKey = hmacDigest(sessionKey, Buffer.alloc(0), hashAlg);
    } else {
      derivedKey = sessionKey;
    }

    const cryptData = ALGORITHMS_DATA[cryptAlgoVal];
    if (cryptData && derivedKey.length < cryptData.keyLen) {
      // Extend the key
      const extendedKey = Buffer.concat([derivedKey, Buffer.alloc(hashBlockSz)]);
      const ipad = Buffer.alloc(hashBlockSz);
      const opad = Buffer.alloc(hashBlockSz);
      for (let i = 0; i < hashBlockSz; i++) {
        ipad[i] = (extendedKey[i] ?? 0) ^ 0x36;
        opad[i] = (extendedKey[i] ?? 0) ^ 0x5c;
      }
      derivedKey = Buffer.concat([
        hashDigest(ipad, hashAlg),
        hashDigest(opad, hashAlg),
      ]);
      derivedKey = fixparity(derivedKey);
    }

    return derivedKey;
  }

  decrypt(key: Buffer, entropy?: Buffer | null): Buffer | null {
    const hashAlgoVal = Number(this.get('HashAlgo'));
    const cryptAlgoVal = Number(this.get('CryptAlgo'));
    const hashAlg = getHashAlgName(hashAlgoVal);

    const keyHash = createHash('sha1').update(key).digest();

    const hmacObj = createHmac(hashAlg, keyHash);
    hmacObj.update(this.get('Salt') as Buffer);
    if (entropy != null) {
      hmacObj.update(entropy);
    }
    const sessionKey = hmacObj.digest();

    // Derive the key
    const derivedKey = this.deriveKey(sessionKey);

    const cryptData = ALGORITHMS_DATA[cryptAlgoVal];
    if (!cryptData || !cryptData.cipherAlg || cryptData.ivLen == null) {
      console.warn(`Unsupported crypt algorithm: ${algorithmName(cryptAlgoVal)}`);
      return null;
    }

    const iv = Buffer.alloc(cryptData.ivLen, 0);
    const encData = this.get('Data') as Buffer;
    const decrypted = cipherDecrypt(
      cryptData.cipherAlg,
      derivedKey.subarray(0, cryptData.keyLen),
      iv,
      encData,
    );

    // Determine block size for unpadding
    let blockSize: number;
    if (cryptData.cipherAlg === 'des-ede3-cbc') {
      blockSize = 8;
    } else if (cryptData.cipherAlg.startsWith('aes-')) {
      blockSize = 16;
    } else {
      blockSize = 8;
    }
    const cleartext = unpad(decrypted, blockSize);

    // Now check the signature
    const rawDataBuf = this.rawData!;
    const signBuf = this.get('Sign') as Buffer;
    const toSign = rawDataBuf.subarray(20, rawDataBuf.length - signBuf.length - 4);

    // Calculate the different HMACKeys
    const hashDigestSz = getHashDigestSize(hashAlg);
    const keyHash2 = Buffer.concat([keyHash, Buffer.alloc(hashBlockSize(hashAlg))]);
    const ipad = Buffer.alloc(hashBlockSize(hashAlg));
    const opad = Buffer.alloc(hashBlockSize(hashAlg));
    for (let i = 0; i < hashBlockSize(hashAlg); i++) {
      ipad[i] = (keyHash2[i] ?? 0) ^ 0x36;
      opad[i] = (keyHash2[i] ?? 0) ^ 0x5c;
    }

    const hmacBuf = this.get('HMac') as Buffer;

    const a = createHash(hashAlg).update(ipad).update(hmacBuf);
    const hmacCalc1Inner = createHash(hashAlg).update(opad).update(a.digest());
    if (entropy != null) {
      hmacCalc1Inner.update(entropy);
    }
    hmacCalc1Inner.update(toSign);
    const hmacCalculated1 = hmacCalc1Inner.digest();

    const hmacCalc3 = createHmac(hashAlg, keyHash);
    hmacCalc3.update(hmacBuf);
    if (entropy != null) {
      hmacCalc3.update(entropy);
    }
    hmacCalc3.update(toSign);
    const hmacCalculated3 = hmacCalc3.digest();

    if (hmacCalculated1.equals(signBuf) || hmacCalculated3.equals(signBuf)) {
      return cleartext;
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Vault structures
// ---------------------------------------------------------------------------

export class VAULT_ATTRIBUTE extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Id', '<L=0'],
    ['Unknown1', '<L=0'],
    ['Unknown2', '<L=0'],
    ['Unknown3', '<L=0'],
  ];

  static padding: FieldDescriptor[] = [['Pad', '6s=b""']];

  static id100: FieldDescriptor[] = [['Unknown5', '<L=0']];

  static extended: FieldDescriptor[] = [
    ['Size', '<L=0'],
    ['IVPresent', '<B=0'],
    ['IVSize', '<L=0'],
    ['_IV', '_-IV', 'self["IVSize"] ? self["IVSize"] : 0'],
    ['IV', ':'],
    [
      '_Data',
      '_-Data',
      'self["IVPresent"] ? self["Size"]-self["IVSize"]-5 : self["Size"]-1',
    ],
    ['Data', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    // Must call super(null) first, then dynamically set structure, then parse
    super(null, alignment);

    const base: FieldDescriptor[] = [
      ['Id', '<L=0'],
      ['Unknown1', '<L=0'],
      ['Unknown2', '<L=0'],
      ['Unknown3', '<L=0'],
    ];

    if (data && data.length > 20) {
      if (data.subarray(16, 22).equals(Buffer.alloc(6, 0))) {
        base.push(['Pad', '6s=b""']);
      }
      if (data.readUInt32LE(0) >= 100) {
        base.push(['Unknown5', '<L=0']);
      }
      if (data.subarray(16).length >= 9) {
        base.push(
          ['Size', '<L=0'],
          ['IVPresent', '<B=0'],
          ['IVSize', '<L=0'],
          ['_IV', '_-IV', 'self["IVSize"] ? self["IVSize"] : 0'],
          ['IV', ':'],
          [
            '_Data',
            '_-Data',
            'self["IVPresent"] ? self["Size"]-self["IVSize"]-5 : self["Size"]-1',
          ],
          ['Data', ':'],
        );
      }
    }

    this.structure = base;
    if (data != null) {
      this.rawData = Buffer.from(data);
      this.fromString(Buffer.from(data));
    }
  }

  override dump(): string[] {
    const lines: string[] = [];
    const id = Number(this.get('Id'));
    lines.push(`[ATTRIBUTE ${id}]`);
    if (this.rawData && this.rawData.length > 28) {
      if (this.has('Size')) {
        lines.push(`Size   : 0x${Number(this.get('Size')).toString(16)}`);
      }
      if (this.has('IVPresent') && Number(this.get('IVPresent')) > 0) {
        lines.push(`IVSize : 0x${Number(this.get('IVSize')).toString(16)}`);
        lines.push(`IV     : ${(this.get('IV') as Buffer).toString('hex')}`);
      }
      if (this.has('Data')) {
        lines.push(`Data   : ${(this.get('Data') as Buffer).toString('hex')}`);
      }
    }
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class VAULT_ATTRIBUTE_MAP_ENTRY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Id', '<L=0'],
    ['Offset', '<L=0'],
    ['Unknown1', '<L=0'],
  ];

  override dump(): string[] {
    const id = Number(this.get('Id'));
    const offset = Number(this.get('Offset'));
    const line = `[MAP ENTRY ${id} @ 0x${offset.toString(16).padStart(8, '0')}]`;
    console.debug(line);
    return [line];
  }
}

export class VAULT_VCRD extends Structure {
  static override structure: FieldDescriptor[] = [
    ['SchemaGuid', '16s=b""'],
    ['Unknown0', '<L=0'],
    ['LastWritten', '<Q=0'],
    ['Unknown1', '<L=0'],
    ['Unknown2', '<L=0'],
    ['FriendlyNameLen', '<L=0'],
    ['_FriendlyName', '_-FriendlyName', 'self["FriendlyNameLen"]'],
    ['FriendlyName', ':'],
    ['AttributesMapsSize', '<L=0'],
    ['_AttributeMaps', '_-AttributeMaps', 'self["AttributesMapsSize"]'],
    ['AttributeMaps', ':'],
    ['Data', ':'],
  ];

  mapEntries: VAULT_ATTRIBUTE_MAP_ENTRY[] = [];
  attributesLen: number[] = [];
  attributes: VAULT_ATTRIBUTE[] = [];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data != null) {
      // Process the MAP entries
      this.mapEntries = [];
      let mapData = this.get('AttributeMaps') as Buffer;
      const emptyEntry = new VAULT_ATTRIBUTE_MAP_ENTRY();
      const entrySize = emptyEntry.length;
      const mapSize = Number(this.get('AttributesMapsSize'));
      const numEntries = Math.floor(mapSize / entrySize);
      for (let i = 0; i < numEntries; i++) {
        const entry = new VAULT_ATTRIBUTE_MAP_ENTRY(mapData);
        this.mapEntries.push(entry);
        mapData = mapData.subarray(entrySize);
      }

      this.attributesLen = [];
      for (let i = 1; i < this.mapEntries.length; i++) {
        this.attributesLen.push(
          Number(this.mapEntries[i]!.get('Offset')) -
            Number(this.mapEntries[i - 1]!.get('Offset')),
        );
      }
      const lastEntry = this.mapEntries[this.mapEntries.length - 1]!;
      this.attributesLen.push(this.rawData!.length - Number(lastEntry.get('Offset')));

      this.attributes = [];
      for (let i = 0; i < this.mapEntries.length; i++) {
        const entry = this.mapEntries[i]!;
        const offset = Number(entry.get('Offset'));
        const attrData = this.rawData!.subarray(offset, offset + this.attributesLen[i]!);
        const attribute = new VAULT_ATTRIBUTE(attrData);
        this.attributes.push(attribute);
      }

      // Remaining data
      const lastAttr = this.attributes[this.attributes.length - 1]!;
      const lastOffset = Number(lastEntry.get('Offset'));
      this.set(
        'Data',
        this.rawData!.subarray(lastOffset + lastAttr.getData().length),
      );
    }
  }

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[VCRD]');
    const schemaGuid = this.get('SchemaGuid') as Buffer;
    const lastWritten = Number(this.get('LastWritten'));
    const friendlyName = this.get('FriendlyName') as Buffer;
    lines.push(`SchemaGuid  : ${binToString(schemaGuid)}`);
    lines.push(
      `LastWritten : ${new Date(getUnixTime(lastWritten) * 1000).toISOString()}`,
    );
    lines.push(`FriendlyName: ${friendlyName.toString('utf16le')}`);
    for (let i = 0; i < this.mapEntries.length; i++) {
      lines.push(...this.mapEntries[i]!.dump());
      lines.push(...this.attributes[i]!.dump());
    }
    lines.push(`Remaining   : ${(this.get('Data') as Buffer).toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class VAULT_VPOL extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Guid', '16s=b""'],
    ['DescriptionLen', '<L=0'],
    ['_Description', '_-Description', 'self["DescriptionLen"]'],
    ['Description', ':'],
    ['Unknown', '12s=b""'],
    ['Size', '<L=0'],
    ['Guid2', '16s=b""'],
    ['Guid3', '16s=b""'],
    ['KeySize', '<L=0'],
    ['_Blob', '_-Blob', 'self["KeySize"]'],
    ['Blob', ':', DPAPI_BLOB],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[VAULT_VPOL]');
    const version = Number(this.get('Version'));
    const guid = this.get('Guid') as Buffer;
    const desc = this.get('Description') as Buffer;
    const size = Number(this.get('Size'));
    const guid2 = this.get('Guid2') as Buffer;
    const guid3 = this.get('Guid3') as Buffer;
    const keySize = Number(this.get('KeySize'));
    lines.push(`Version      : ${version.toString(16).padStart(8, ' ')} (${version})`);
    lines.push(`Guid         : ${binToString(guid)}`);
    lines.push(`Description  : ${desc.toString('utf16le')}`);
    lines.push(`Size         : 0x${size.toString(16).padStart(8, '0')} (${size})`);
    lines.push(`Guid2        : ${binToString(guid2)}`);
    lines.push(`Guid3        : ${binToString(guid3)}`);
    lines.push(`KeySize      : 0x${keySize.toString(16).padStart(8, '0')} (${keySize})`);
    const blob = this.get('Blob') as unknown as DPAPI_BLOB;
    lines.push(...blob.dump());
    for (const l of lines) console.debug(l);
    return lines;
  }
}

// from bcrypt.h
export class BCRYPT_KEY_DATA_BLOB_HEADER extends Structure {
  static override structure: FieldDescriptor[] = [
    ['dwMagic', '<L=0'],
    ['dwVersion', '<L=0'],
    ['cbKeyData', '<L=0'],
    ['_bKey', '_-bKey', 'self["cbKeyData"]'],
    ['bKey', ':'],
  ];
}

export class BCRYPT_KSSM_DATA_BLOB_HEADER extends Structure {
  static override structure: FieldDescriptor[] = [
    ['cbLength', '<L=0'],
    ['dwKeyMagic', '<L=0'],
    ['dwUnknown2', '<L=0'],
    ['dwUnknown3', '<L=0'],
    ['dwKeyBitLen', '<L=0'],
    ['cbKeyLength', '<L=0'],
  ];
}

export class BCRYPT_KEY_WRAP extends Structure {
  static structureKDBM: FieldDescriptor[] = [
    ['Size', '<L=0'],
    ['Version', '<L=0'],
    ['Unknown2', '<L=0'],
    ['_bKeyBlob', '_-bKeyBlob', 'self["Size"]'],
    ['bKeyBlob', ':', BCRYPT_KEY_DATA_BLOB_HEADER],
  ];

  static structureKSSM: FieldDescriptor[] = [
    ['Size', '<L=0'],
    ['Version', '<L=0'],
    ['Unknown2', '<L=0'],
    ['_bKeyBlob', '_-bKeyBlob', 'self["Size"]-8'],
    ['bKeyBlob', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    // Must call super(null) first, then dynamically set structure, then parse
    super(null, alignment);

    let struct: FieldDescriptor[];
    if (data && data.length >= 16) {
      if (data[0] === 0x24 || data[0] === 0x34) {
        struct = BCRYPT_KEY_WRAP.structureKDBM;
      } else {
        struct = BCRYPT_KEY_WRAP.structureKSSM;
      }
    } else {
      struct = BCRYPT_KEY_WRAP.structureKSSM;
    }

    this.structure = struct;
    if (data != null) {
      this.rawData = Buffer.from(data);
      this.fromString(Buffer.from(data));
    }
  }
}

export class VAULT_VPOL_KEYS extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Key1', ':', BCRYPT_KEY_WRAP],
    ['Key2', ':', BCRYPT_KEY_WRAP],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[VAULT_VPOL_KEYS]');
    const key1 = this.get('Key1') as unknown as BCRYPT_KEY_WRAP;
    const key2 = this.get('Key2') as unknown as BCRYPT_KEY_WRAP;
    if (Number(key1.get('Size')) > 0x24) {
      lines.push('Key1:');
      lines.push(hexdump(key1.get('bKeyBlob') as Buffer));
      lines.push('Key2:');
      lines.push(hexdump(key2.get('bKeyBlob') as Buffer));
    } else {
      const blob1 = key1.get('bKeyBlob') as unknown as BCRYPT_KEY_DATA_BLOB_HEADER;
      const blob2 = key2.get('bKeyBlob') as unknown as BCRYPT_KEY_DATA_BLOB_HEADER;
      lines.push(`Key1: 0x${(blob1.get('bKey') as Buffer).toString('hex')}`);
      lines.push(`Key2: 0x${(blob2.get('bKey') as Buffer).toString('hex')}`);
    }
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class VAULT_INTERNET_EXPLORER extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Count', '<L=0'],
    ['Unknown', '<L=0'],
    ['Id1', '<L=0'],
    ['UsernameLen', '<L=0'],
    ['_Username', '_-Username', 'self["UsernameLen"]'],
    ['Username', ':'],
    ['Id2', '<L=0'],
    ['ResourceLen', '<L=0'],
    ['_Resource', '_-Resource', 'self["ResourceLen"]'],
    ['Resource', ':'],
    ['Id3', '<L=0'],
    ['PasswordLen', '<L=0'],
    ['_Password', '_-Password', 'self["PasswordLen"]'],
    ['Password', ':'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[Internet Explorer]');
    lines.push(`Username        : ${(this.get('Username') as Buffer).toString('utf16le')}`);
    lines.push(`Resource        : ${(this.get('Resource') as Buffer).toString('utf16le')}`);
    lines.push(`Password        : ${(this.get('Password') as Buffer).toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class VAULT_WIN_BIO_KEY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Count', '<L=0'],
    ['Unknown', '<L=0'],
    ['Id1', '<L=0'],
    ['SidLen', '<L=0'],
    ['_Sid', '_-Sid', 'self["SidLen"]'],
    ['Sid', ':'],
    ['Id2', '<L=0'],
    ['NameLen', '<L=0'],
    ['_Name', '_-Name', 'self["NameLen"]'],
    ['Name', ':'],
    ['Id3', '<L=0'],
    ['BioKeyLen', '<L=0'],
    ['_BioKey', '_-BioKey', 'self["BioKeyLen"]'],
    ['BioKey', ':'],
  ];

  override fromString(data: Buffer): this {
    super.fromString(data);
    // Parse the bio key from UTF-16LE hex string
    const bioKeyBuf = this.get('BioKey') as Buffer;
    const bioKeyHex = bioKeyBuf.toString('utf16le').replace(/\0$/, '');
    const bioKeyData = Buffer.from(bioKeyHex, 'hex');
    const bioKey = new BCRYPT_KEY_DATA_BLOB_HEADER(bioKeyData);
    this.set('BioKey', bioKey as unknown as Buffer);
    return this;
  }

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[WINDOWS BIOMETRIC KEY]');
    const sid = this.get('Sid') as Buffer;
    const sidWithPrefix = Buffer.concat([Buffer.from([0x05, 0x00, 0x00, 0x00]), sid]);
    lines.push(`Sid          : ${formatSidCanonical(sidWithPrefix)}`);
    lines.push(`Friendly Name: ${(this.get('Name') as Buffer).toString('utf16le')}`);
    const bioKey = this.get('BioKey') as unknown as BCRYPT_KEY_DATA_BLOB_HEADER;
    lines.push(`Biometric Key: 0x${(bioKey.get('bKey') as Buffer).toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class NGC_LOCAL_ACCOOUNT extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['UnlockKeySize', '<L=0'],
    ['IVSize', '<L=0'],
    ['CipherTextSize', '<L=0'],
    ['MustBeZeroTest', '<L=0'],
    ['_UnlockKey', '_-UnlockKey', 'self["UnlockKeySize"]'],
    ['UnlockKey', ':'],
    ['_IV', '_-IV', 'self["IVSize"]'],
    ['IV', ':'],
    ['_CipherText', '_-CipherText', 'self["CipherTextSize"]'],
    ['CipherText', ':'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[NGC LOCAL ACCOOUNT]');
    lines.push(`UnlockKey    : ${(this.get('UnlockKey') as Buffer).toString('hex')}`);
    lines.push(`IV           : ${(this.get('IV') as Buffer).toString('hex')}`);
    lines.push(`CipherText   : ${(this.get('CipherText') as Buffer).toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class VAULT_NGC_ACCOOUNT extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Count', '<L=0'],
    ['Unknown', '<L=0'],
    ['Id1', '<L=0'],
    ['SidLen', '<L=0'],
    ['_Sid', '_-Sid', 'self["SidLen"]'],
    ['Sid', ':'],
    ['Id2', '<L=0'],
    ['NameLen', '<L=0'],
    ['_Name', '_-Name', 'self["NameLen"]'],
    ['Name', ':'],
    ['Id3', '<L=0'],
    ['BlobLen', '<L=0'],
    ['_Blob', '_-Blob', 'self["BlobLen"]'],
    ['Blob', ':', NGC_LOCAL_ACCOOUNT],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[NGC VAULT]');
    const sid = this.get('Sid') as Buffer;
    const sidWithPrefix = Buffer.concat([Buffer.from([0x05, 0x00, 0x00, 0x00]), sid]);
    lines.push(`Sid          : ${formatSidCanonical(sidWithPrefix)}`);
    lines.push(`Friendly Name: ${(this.get('Name') as Buffer).toString('utf16le')}`);
    const blob = this.get('Blob') as unknown as NGC_LOCAL_ACCOOUNT;
    lines.push(...blob.dump());
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export const VAULT_KNOWN_SCHEMAS: Record<string, typeof Structure> = {
  'WinBio Key': VAULT_WIN_BIO_KEY,
  'NGC Local Accoount Logon Vault Credential': VAULT_NGC_ACCOOUNT,
  'Internet Explorer': VAULT_INTERNET_EXPLORER,
};

export class CREDENTIAL_ATTRIBUTE extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Flags', '<L=0'],
    ['KeyWordSize', '<L=0'],
    ['_KeyWord', '_-KeyWord', 'self["KeyWordSize"]'],
    ['KeyWord', ':'],
    ['DataSize', '<L=0'],
    ['_Data', '_-Data', 'self["DataSize"]'],
    ['Data', ':'],
  ];

  override dump(): string[] {
    const lines: string[] = [];
    lines.push(`KeyWord : ${(this.get('KeyWord') as Buffer).toString('utf16le')}`);
    lines.push('Data    : ');
    lines.push(hexdump(this.get('Data') as Buffer));
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class CREDENTIAL_BLOB extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Flags', '<L=0'],
    ['Size', '<L=0'],
    ['Unknown0', '<L=0'],
    ['Type', '<L=0'],
    ['Flags2', '<L=0'],
    ['LastWritten', '<Q=0'],
    ['Unknown2', '<L=0'],
    ['Persist', '<L=0'],
    ['AttrCount', '<L=0'],
    ['Unknown3', '<Q=0'],
    ['TargetSize', '<L=0'],
    ['_Target', '_-Target', 'self["TargetSize"]'],
    ['Target', ':'],
    ['TargetAliasSize', '<L=0'],
    ['_TargetAlias', '_-TargetAlias', 'self["TargetAliasSize"]'],
    ['TargetAlias', ':'],
    ['DescriptionSize', '<L=0'],
    ['_Description', '_-Description', 'self["DescriptionSize"]'],
    ['Description', ':'],
    ['UnknownSize', '<L=0'],
    ['_Unknown', '_-Unknown', 'self["UnknownSize"]'],
    ['Unknown', ':'],
    ['UsernameSize', '<L=0'],
    ['_Username', '_-Username', 'self["UsernameSize"]'],
    ['Username', ':'],
    ['Unknown3Size', '<L=0'],
    ['_Unknown3', '_-Unknown3', 'self["Unknown3Size"]'],
    ['Unknown3', ':'],
    ['Remaining', ':'],
  ];

  credAttributes: CREDENTIAL_ATTRIBUTE[] = [];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    this.credAttributes = [];
    if (data != null) {
      let remaining = this.get('Remaining') as Buffer;
      const attrCount = Number(this.get('AttrCount'));
      for (let i = 0; i < attrCount; i++) {
        const attr = new CREDENTIAL_ATTRIBUTE(remaining);
        this.credAttributes.push(attr);
        remaining = remaining.subarray(attr.getData().length);
      }
    }
  }

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[CREDENTIAL]');
    const lastWritten = Number(this.get('LastWritten'));
    const flags = Number(this.get('Flags'));
    const persist = Number(this.get('Persist'));
    const type = Number(this.get('Type'));
    lines.push(
      `LastWritten : ${new Date(getUnixTime(lastWritten) * 1000).toISOString()}`,
    );
    lines.push(
      `Flags       : 0x${flags.toString(16).padStart(8, '0')} (${getFlags(CREDENTIAL_FLAGS, flags)})`,
    );
    lines.push(
      `Persist     : 0x${persist.toString(16).padStart(8, '0')} (${CREDENTIAL_PERSIST_BY_VALUE[persist] ?? 'UNKNOWN'})`,
    );
    lines.push(
      `Type        : 0x${type.toString(16).padStart(8, '0')} (${CREDENTIAL_TYPE_BY_VALUE[type] ?? 'UNKNOWN'})`,
    );
    lines.push(`Target      : ${(this.get('Target') as Buffer).toString('utf16le')}`);
    lines.push(`Description : ${(this.get('Description') as Buffer).toString('utf16le')}`);
    lines.push(`Unknown     : ${(this.get('Unknown') as Buffer).toString('utf16le')}`);
    lines.push(`Username    : ${(this.get('Username') as Buffer).toString('utf16le')}`);
    try {
      lines.push(`Unknown     : ${(this.get('Unknown3') as Buffer).toString('utf16le')}`);
    } catch {
      lines.push(`Unknown     : ${(this.get('Unknown3') as Buffer).toString('latin1')}`);
    }
    for (const entry of this.credAttributes) {
      lines.push(...entry.dump());
    }
    for (const l of lines) console.debug(l);
    return lines;
  }
}

export class P_BACKUP_KEY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Data', ':'],
  ];
}

export class PREFERRED_BACKUP_KEY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['KeyLength', '<L=0'],
    ['CertificateLength', '<L=0'],
    ['Data', ':'],
  ];
}

export class PVK_FILE_HDR extends Structure {
  static override structure: FieldDescriptor[] = [
    ['dwMagic', '<L=0'],
    ['dwVersion', '<L=0'],
    ['dwKeySpec', '<L=0'],
    ['dwEncryptType', '<L=0'],
    ['cbEncryptData', '<L=0'],
    ['cbPvk', '<L=0'],
  ];
}

export class PUBLICKEYSTRUC extends Structure {
  static override structure: FieldDescriptor[] = [
    ['bType', '<B=0'],
    ['bVersion', '<B=0'],
    ['reserved', '<H=0'],
    ['aiKeyAlg', '<L=0'],
  ];
}

export class RSAPUBKEY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['magic', '<L=0'],
    ['bitlen', '<L=0'],
    ['pubexp', '<L=0'],
  ];
}

export class PUBLIC_KEY_BLOB extends Structure {
  static override structure: FieldDescriptor[] = [
    ['publickeystruc', ':', PUBLICKEYSTRUC],
    ['rsapubkey', ':', RSAPUBKEY],
    ['_modulus', '_-modulus', 'self["rsapubkey"]["bitlen"] / 8'],
  ];
}

export class PRIVATE_KEY_BLOB extends Structure {
  static override structure: FieldDescriptor[] = [
    ['publickeystruc', ':', PUBLICKEYSTRUC],
    ['rsapubkey', ':', RSAPUBKEY],
    ['_modulus', '_-modulus', 'self["rsapubkey"]["bitlen"] / 8'],
    ['modulus', ':'],
    ['_prime1', '_-prime1', 'self["rsapubkey"]["bitlen"] / 16'],
    ['prime1', ':'],
    ['_prime2', '_-prime2', 'self["rsapubkey"]["bitlen"] / 16'],
    ['prime2', ':'],
    ['_exponent1', '_-exponent1', 'self["rsapubkey"]["bitlen"] / 16'],
    ['exponent1', ':'],
    ['_exponent2', '_-exponent2', 'self["rsapubkey"]["bitlen"] / 16'],
    ['exponent2', ':'],
    ['_coefficient', '_-coefficient', 'self["rsapubkey"]["bitlen"] / 16'],
    ['coefficient', ':'],
    ['_privateExponent', '_-privateExponent', 'self["rsapubkey"]["bitlen"] / 8'],
    ['privateExponent', ':'],
  ];
}

export class SIMPLE_KEY_BLOB extends Structure {
  static override structure: FieldDescriptor[] = [
    ['publickeystruc', ':', PUBLICKEYSTRUC],
    ['algid', '<L=0'],
    ['encryptedkey', ':'],
  ];
}

export class DPAPI_DOMAIN_RSA_MASTER_KEY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['cbMasterKey', '<L=0'],
    ['cbSuppKey', '<L=0'],
    ['buffer', ':'],
  ];
}

/** Convert bytes to bigint (big-endian unsigned). */
function bytesToLong(buf: Buffer): bigint {
  let result = 0n;
  for (let i = 0; i < buf.length; i++) {
    result = (result << 8n) | BigInt(buf[i]!);
  }
  return result;
}

/** Convert bigint to bytes (big-endian, given byte length). */
function longToBytes(n: bigint, length: number): Buffer {
  const buf = Buffer.alloc(length);
  let val = n;
  for (let i = length - 1; i >= 0; i--) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return buf;
}

/**
 * Parse a PRIVATE_KEY_BLOB into an RSA key object.
 * Returns an object with the key components for RSA operations.
 */
export function privatekeyblobToPkcs1(key: PRIVATE_KEY_BLOB): {
  n: bigint;
  e: bigint;
  d: bigint;
  p: bigint;
  q: bigint;
} {
  const modulusBuf = key.get('modulus') as Buffer;
  const prime1Buf = key.get('prime1') as Buffer;
  const prime2Buf = key.get('prime2') as Buffer;
  const privateExpBuf = key.get('privateExponent') as Buffer;
  const rsapubkey = key.get('rsapubkey') as unknown as RSAPUBKEY;
  const pubexp = Number(rsapubkey.get('pubexp'));

  // Microsoft stores these in little-endian order, so reverse for big-endian
  const n = bytesToLong(Buffer.from(modulusBuf).reverse());
  const p = bytesToLong(Buffer.from(prime1Buf).reverse());
  const q = bytesToLong(Buffer.from(prime2Buf).reverse());
  const d = bytesToLong(Buffer.from(privateExpBuf).reverse());
  const e = BigInt(pubexp);

  return { n, e, d, p, q };
}

// ---------------------------------------------------------------------------
// Key derivation functions
// ---------------------------------------------------------------------------

/**
 * Derive keys from a user's password and SID.
 * Returns [SHA1-based key, MD4-based key, Protected Users key].
 */
export function deriveKeysFromUser(sid: string, password: string): Buffer[] {
  const passwordBuf = Buffer.from(password, 'utf16le');
  const sha1Hash = createHash('sha1').update(passwordBuf).digest();
  const md4Digest = md4Hash(passwordBuf);

  const sidNullUtf16 = Buffer.from(sid + '\0', 'utf16le');

  const key1 = createHmac('sha1', sha1Hash).update(sidNullUtf16).digest();
  const key2 = createHmac('sha1', md4Digest).update(sidNullUtf16).digest();

  // For Protected users
  const sidUtf16 = Buffer.from(sid, 'utf16le');
  const tmpKey = pbkdf2Sync(md4Digest, sidUtf16, 10000, 32, 'sha256');
  const tmpKey2 = pbkdf2Sync(tmpKey, sidUtf16, 1, 16, 'sha256');
  const key3 = createHmac('sha1', tmpKey2).update(sidNullUtf16).digest().subarray(0, 20);

  return [key1, key2, key3];
}

/**
 * Derive keys from a user's password hash and SID.
 */
export function deriveKeysFromUserkey(sid: string, pwdhash: Buffer): Buffer[] {
  const sidNullUtf16 = Buffer.from(sid + '\0', 'utf16le');

  if (pwdhash.length === 20) {
    // SHA1
    const key1 = createHmac('sha1', pwdhash).update(sidNullUtf16).digest();
    return [key1];
  }

  // Assume MD4
  const key1 = createHmac('sha1', pwdhash).update(sidNullUtf16).digest();

  // For Protected users
  const sidUtf16 = Buffer.from(sid, 'utf16le');
  const tmpKey = pbkdf2Sync(pwdhash, sidUtf16, 10000, 32, 'sha256');
  const tmpKey2 = pbkdf2Sync(tmpKey, sidUtf16, 1, 16, 'sha256');
  const key2 = createHmac('sha1', tmpKey2).update(sidNullUtf16).digest().subarray(0, 20);

  return [key1, key2];
}

// ===========================================================================
// DPAPI-NG (from dpapi_ng.py)
// ===========================================================================

export const KDS_SERVICE_LABEL = Buffer.from('KDS service\0', 'utf16le');
export const KEK_PUBLIC_KEY_LABEL = Buffer.from('KDS public key\0', 'utf16le');

// ---------------------------------------------------------------------------
// SP800-108 Counter Mode KDF (modified for impacket, accepting null bytes)
// ---------------------------------------------------------------------------

export function SP800_108_Counter(
  master: Buffer,
  keyLen: number,
  prf: (secret: Buffer, input: Buffer) => Buffer,
  numKeys = 1,
  label: Buffer = Buffer.alloc(0),
  context: Buffer = Buffer.alloc(0),
): Buffer | Buffer[] {
  const keyLenEnc = Buffer.alloc(4);
  keyLenEnc.writeUInt32BE(keyLen * numKeys * 8, 0);
  const outputLen = keyLen * numKeys;

  let i = 1;
  let dk = Buffer.alloc(0);
  while (dk.length < outputLen) {
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(i, 0);
    const info = Buffer.concat([counterBuf, label, Buffer.from([0x00]), context, keyLenEnc]);
    dk = Buffer.concat([dk, prf(master, info)]);
    i += 1;
    if (i > 0xffffffff) {
      throw new Error('Overflow in SP800 108 counter');
    }
  }

  if (numKeys === 1) {
    return dk.subarray(0, keyLen);
  }
  const keys: Buffer[] = [];
  for (let idx = 0; idx < outputLen; idx += keyLen) {
    keys.push(dk.subarray(idx, idx + keyLen));
  }
  return keys;
}

// ---------------------------------------------------------------------------
// DPAPI-NG Structures
// ---------------------------------------------------------------------------

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

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[KEY IDENTIFIER]');
    lines.push(`Version:\t\t${this.get('Version')}`);
    lines.push(`Magic:\t\t0x${Number(this.get('Magic')).toString(16)}`);
    lines.push(`Flags:\t\t${this.get('Flags')}`);
    lines.push(`L0Index:\t\t${this.get('L0Index')}`);
    lines.push(`L1Index:\t\t${this.get('L1Index')}`);
    lines.push(`L2Index:\t\t${this.get('L2Index')}`);
    lines.push(`RootKeyId:\t\t${(this.get('RootKeyId') as Buffer).toString('hex')}`);
    lines.push(`Unknown:\t\t${(this.get('Unknown') as Buffer).toString('hex')}`);
    lines.push(`Domain:\t\t${(this.get('Domain') as Buffer).toString('utf16le')}`);
    lines.push(`Forest:\t\t${(this.get('Forest') as Buffer).toString('utf16le')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }

  isPublicKey(): boolean {
    return (Number(this.get('Flags')) & 1) !== 0;
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

  override dump(): string[] {
    const lines: string[] = [];
    lines.push('[ENCRYPTED PASSWORD BLOB]');
    const upper = Number(this.get('Timestamp_upper'));
    const lower = Number(this.get('Timestamp_lower'));
    lines.push(`Timestamp_upper:\t\t${upper}`);
    lines.push(`Timestamp_lower:\t\t${lower}`);
    lines.push(`Update Timestamp:\t\t${(upper * 0x100000000 + lower)}`);
    lines.push(`Length:\t\t${this.get('Length')}`);
    lines.push(`Flags:\t\t${this.get('Flags')}`);
    lines.push(`Blob:\t\t${(this.get('Blob') as Buffer).toString('hex')}`);
    for (const l of lines) console.debug(l);
    return lines;
  }
}

// ---------------------------------------------------------------------------
// DPAPI-NG GroupKeyEnvelope and related structures
// These are simplified representations; the full GKE structure is complex.
// We provide the essential fields for KDF operations.
// ---------------------------------------------------------------------------

export class GroupKeyEnvelope extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Magic', '<L=0'],
    ['Flags', '<L=0'],
    ['L0Index', '<L=0'],
    ['L1Index', '<L=0'],
    ['L2Index', '<L=0'],
    ['RootKeyId', '16s=b""'],
    ['cbKdfPara', '<L=0'],
    ['cbSecAlgo', '<L=0'],
    ['cbSecPara', '<L=0'],
    ['PrivKeyLength', '<L=0'],
    ['cbL1Key', '<L=0'],
    ['cbL2Key', '<L=0'],
    ['_KdfPara', '_-KdfPara', 'self["cbKdfPara"]'],
    ['KdfPara', ':'],
    ['_SecAlgo', '_-SecAlgo', 'self["cbSecAlgo"]'],
    ['SecAlgo', ':'],
    ['_SecPara', '_-SecPara', 'self["cbSecPara"]'],
    ['SecPara', ':'],
    ['_L1Key', '_-L1Key', 'self["cbL1Key"]'],
    ['L1Key', ':'],
    ['_L2Key', '_-L2Key', 'self["cbL2Key"]'],
    ['L2Key', ':'],
  ];
}

/** Helper to extract hash name from KdfPara (which is a sub-structure with a HashName field). */
function getKdfParaHashName(gke: GroupKeyEnvelope): string {
  const kdfPara = gke.get('KdfPara') as Buffer;
  // KdfPara typically contains: cbLength (4), HashName (utf16le string)
  // We extract the hash name starting after the length field
  if (kdfPara.length > 4) {
    return kdfPara.subarray(4).toString('utf16le');
  }
  return kdfPara.toString('utf16le');
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

function intToU32BE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(n, 0);
  return buf;
}

/** Compute KDF hash (NIST SP 800-56C). */
export function computeKdfHash(
  length: number,
  keyMaterial: Buffer,
  otherinfo: Buffer,
): Buffer {
  const output: Buffer[] = [Buffer.alloc(0)];
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

/** Compute KDF context from key GUID and L0/L1/L2 indices. */
export function computeKdfContext(
  keyGuid: Buffer,
  l0: number,
  l1: number,
  l2: number,
): Buffer {
  const l0Buf = Buffer.alloc(4);
  l0Buf.writeInt32LE(l0, 0);
  const l1Buf = Buffer.alloc(4);
  l1Buf.writeInt32LE(l1, 0);
  const l2Buf = Buffer.alloc(4);
  l2Buf.writeInt32LE(l2, 0);
  return Buffer.concat([keyGuid, l0Buf, l1Buf, l2Buf]);
}

/** KDF using HMAC with SP800-108 Counter Mode. */
export function kdf(
  hashAlgStr: string,
  secret: Buffer,
  label: Buffer,
  context: Buffer,
  length: number,
): Buffer {
  let hashAlg: string;
  if (hashAlgStr.includes('SHA512')) {
    hashAlg = 'sha512';
  } else if (hashAlgStr.includes('SHA256')) {
    hashAlg = 'sha256';
  } else {
    hashAlg = 'sha512';
  }

  const prf = (s: Buffer, x: Buffer): Buffer => createHmac(hashAlg, s).update(x).digest();

  return SP800_108_Counter(secret, length, prf, 1, label, context) as Buffer;
}

/** Compute L2 key from KeyIdentifier and GroupKeyEnvelope. */
export function computeL2Key(
  keyId: KeyIdentifier,
  gke: GroupKeyEnvelope,
): Buffer {
  let l1 = Number(gke.get('L1Index'));
  let l1Key = gke.get('L1Key') as Buffer;
  let l2 = Number(gke.get('L2Index'));
  let l2Key = gke.get('L2Key') as Buffer;

  const reseedL2Initial = l2 === 31 || l1 !== Number(keyId.get('L1Index'));

  const kdfParam = getKdfParaHashName(gke);

  if (l2 !== 31 && l1 !== Number(keyId.get('L1Index'))) {
    l1 -= 1;
  }

  let reseedL2 = reseedL2Initial;
  while (l1 !== Number(keyId.get('L1Index'))) {
    reseedL2 = true;
    l1 -= 1;

    l1Key = kdf(
      kdfParam,
      l1Key,
      KDS_SERVICE_LABEL,
      computeKdfContext(
        gke.get('RootKeyId') as Buffer,
        Number(gke.get('L0Index')),
        l1,
        -1,
      ),
      64,
    );
  }

  if (reseedL2) {
    l2 = 31;
    l2Key = kdf(
      kdfParam,
      l1Key,
      KDS_SERVICE_LABEL,
      computeKdfContext(
        gke.get('RootKeyId') as Buffer,
        Number(gke.get('L0Index')),
        l1,
        l2,
      ),
      64,
    );
  }

  while (l2 !== Number(keyId.get('L2Index'))) {
    l2 -= 1;

    l2Key = kdf(
      kdfParam,
      l2Key,
      KDS_SERVICE_LABEL,
      computeKdfContext(
        gke.get('RootKeyId') as Buffer,
        Number(gke.get('L0Index')),
        l1,
        l2,
      ),
      64,
    );
  }

  return l2Key;
}

/** Generate KEK secret from public key (DH and ECDH P-256/P-384/P-521). */
export function generateKekSecretFromPubkey(
  gke: GroupKeyEnvelope,
  keyId: KeyIdentifier,
  l2Key: Buffer,
): { kekSecret: Buffer; kekContext: Buffer } | null {
  const kdfParam = getKdfParaHashName(gke);
  const secAlgo = (gke.get('SecAlgo') as Buffer).toString('utf16le');

  const privateKey = kdf(
    kdfParam,
    l2Key,
    KDS_SERVICE_LABEL,
    gke.get('SecAlgo') as Buffer,
    Math.ceil(Number(gke.get('PrivKeyLength')) / 8),
  );

  if (secAlgo.replace(/\0/g, '') === 'DH') {
    // FFCDHKey parsing: the Unknown field contains the public key data
    const pubKeyData = keyId.get('Unknown') as Buffer;
    // FFCDHKey structure: KeyLength (4), FieldOrder (KeyLength bytes), Generator (KeyLength bytes), PubKey (KeyLength bytes)
    const keyLength = pubKeyData.readUInt32LE(0);
    const fieldOrder = pubKeyData.subarray(4, 4 + keyLength);
    // PubKey starts after FieldOrder + Generator
    const pubKey = pubKeyData.subarray(4 + keyLength * 2, 4 + keyLength * 3);

    const pubKeyInt = bytesToLong(pubKey);
    const privKeyInt = bytesToLong(privateKey);
    const fieldOrderInt = bytesToLong(fieldOrder);

    // Modular exponentiation
    const sharedSecretInt = modPow(pubKeyInt, privKeyInt, fieldOrderInt);
    const byteLen = Math.ceil(Number(sharedSecretInt.toString(2).length) / 8);
    const sharedSecret = longToBytes(sharedSecretInt, byteLen);

    const kekContext = KEK_PUBLIC_KEY_LABEL;
    const otherinfo = Buffer.concat([
      Buffer.from('SHA512\0', 'utf16le'),
      kekContext,
      KDS_SERVICE_LABEL,
    ]);

    const kekSecret = computeKdfHash(32, sharedSecret, otherinfo);
    return { kekSecret, kekContext };
  } else if (secAlgo.includes('ECDH_P')) {
    const pubKeyData = keyId.get('Unknown') as Buffer;
    // ECDHKey structure: Magic (4s), KeyLength (4), X (KeyLength), Y (KeyLength)
    const keyLength = pubKeyData.readUInt32LE(4);
    const x = pubKeyData.subarray(8, 8 + keyLength);
    const y = pubKeyData.subarray(8 + keyLength, 8 + keyLength * 2);

    let curveName: string;
    if (secAlgo.includes('ECDH_P256')) {
      curveName = 'prime256v1';
    } else if (secAlgo.includes('ECDH_P384')) {
      curveName = 'secp384r1';
    } else if (secAlgo.includes('ECDH_P521')) {
      curveName = 'secp521r1';
    } else {
      return null;
    }

    const peerPubKey = Buffer.concat([Buffer.from([0x04]), x, y]);
    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(privateKey);
    const sharedSecret = ecdh.computeSecret(peerPubKey);

    const kekContext = KEK_PUBLIC_KEY_LABEL;
    const otherinfo = Buffer.concat([
      Buffer.from('SHA512\0', 'utf16le'),
      kekContext,
      KDS_SERVICE_LABEL,
    ]);
    const kekSecret = computeKdfHash(32, sharedSecret, otherinfo);
    return { kekSecret, kekContext };
  }
  return null;
}

/** Modular exponentiation: base^exp mod mod. */
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

/** Compute KEK (Key Encryption Key) from GroupKeyEnvelope and KeyIdentifier. */
export function computeKek(
  gke: GroupKeyEnvelope,
  keyId: KeyIdentifier,
): Buffer {
  const l2Key = computeL2Key(keyId, gke);
  const kdfParam = getKdfParaHashName(gke);

  let kekSecret: Buffer;
  let kekContext: Buffer;

  if (keyId.isPublicKey()) {
    const result = generateKekSecretFromPubkey(gke, keyId, l2Key);
    if (!result) throw new Error('Failed to generate KEK secret from public key');
    kekSecret = result.kekSecret;
    kekContext = result.kekContext;
  } else {
    kekSecret = l2Key;
    kekContext = keyId.get('Unknown') as Buffer;
  }

  return kdf(kdfParam, kekSecret, KDS_SERVICE_LABEL, kekContext, 32);
}

/** AES Key Unwrap (RFC 3394). */
export function aesUnwrap(wrappingKey: Buffer, wrappedKey: Buffer): Buffer | null {
  const aiv = Buffer.from([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);
  const r: Buffer[] = [];
  for (let i = 0; i < wrappedKey.length; i += 8) {
    r.push(Buffer.from(wrappedKey.subarray(i, i + 8)));
  }
  let a = r.shift()!;
  const n = r.length;

  const decipher = createDecipheriv('aes-256-ecb', wrappingKey, null);
  decipher.setAutoPadding(false);

  for (let j = 5; j >= 0; j--) {
    for (let i = n - 1; i >= 0; i--) {
      const t = BigInt(n * j + i + 1);
      const aBigInt = bytesToLong(a) ^ t;
      const aBytes = longToBytes(aBigInt, 8);
      const atr = Buffer.concat([aBytes, r[i]!]);
      const b = Buffer.concat([decipher.update(atr)]);
      a = Buffer.from(b.subarray(0, 8));
      r[i] = Buffer.from(b.subarray(b.length - 8));
    }
  }

  if (a.equals(aiv)) {
    return Buffer.concat(r);
  }
  return null;
}

/** Unwrap CEK (Content Encryption Key). */
export function unwrapCek(kek: Buffer, encryptedCek: Buffer): Buffer {
  const result = aesUnwrap(kek, encryptedCek);
  if (result === null) {
    throw new Error('Could not unwrap key');
  }
  return result;
}

/** Decrypt plaintext using AES-GCM. */
export function decryptPlaintext(
  cek: Buffer,
  iv: Buffer,
  encryptedBlob: Buffer,
): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', cek, iv);
  return Buffer.concat([decipher.update(encryptedBlob)]);
}
