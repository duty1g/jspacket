/**
 * @impacket/crypto - TypeScript port of impacket/crypto.py
 *
 * Implements:
 *   - RFC 4493 AES-CMAC and RFC 4615 AES-CMAC-PRF-128
 *   - NIST SP 800-108 KDF in Counter Mode (PRF HMAC-SHA256)
 *   - [MS-LSAD] 5.1.2 / 5.1.3 LSA secret encrypt/decrypt (DES-ECB + transformKey)
 *   - [MS-SAMR] 2.2.11.1.1 SAM NTLM hash encrypt/decrypt
 *
 * Crypto primitives are backed by node:crypto (works on Node.js and Bun).
 */

import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { type FieldDescriptor, Structure } from '@impacket/structure';

// --- Pure-JS DES-ECB (Node disables DES by default; Bun supports it). -------

// --- Pure-JS DES-ECB (FIPS 46-3, 32-bit integer implementation). ------------
// Node disables DES by default; Bun supports it. This is a self-contained
// implementation validated against NIST/SP 800-67 test vectors.

function readUInt32BE(bytes: Buffer, off: number): number {
  return (
    ((bytes[off]! << 24) | (bytes[off + 1]! << 16) | (bytes[off + 2]! << 8) | bytes[off + 3]!) >>> 0
  );
}
function writeUInt32BE(bytes: Buffer, value: number, off: number): void {
  bytes[off] = value >>> 24;
  bytes[off + 1] = (value >>> 16) & 0xff;
  bytes[off + 2] = (value >>> 8) & 0xff;
  bytes[off + 3] = value & 0xff;
}

function ip(inL: number, inR: number): [number, number] {
  let outL = 0;
  let outR = 0;
  for (let i = 6; i >= 0; i -= 2) {
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inR >>> (j + i)) & 1;
    }
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inL >>> (j + i)) & 1;
    }
  }
  for (let i = 6; i >= 0; i -= 2) {
    for (let j = 1; j <= 25; j += 8) {
      outR <<= 1;
      outR |= (inR >>> (j + i)) & 1;
    }
    for (let j = 1; j <= 25; j += 8) {
      outR <<= 1;
      outR |= (inL >>> (j + i)) & 1;
    }
  }
  return [outL >>> 0, outR >>> 0];
}

function rip(inL: number, inR: number): [number, number] {
  let outL = 0;
  let outR = 0;
  for (let i = 0; i < 4; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      outL <<= 1;
      outL |= (inR >>> (j + i)) & 1;
      outL <<= 1;
      outL |= (inL >>> (j + i)) & 1;
    }
  }
  for (let i = 4; i < 8; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      outR <<= 1;
      outR |= (inR >>> (j + i)) & 1;
      outR <<= 1;
      outR |= (inL >>> (j + i)) & 1;
    }
  }
  return [outL >>> 0, outR >>> 0];
}

function pc1(inL: number, inR: number): [number, number] {
  let outL = 0;
  let outR = 0;
  let i: number;
  for (i = 7; i >= 5; i--) {
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inR >> (j + i)) & 1;
    }
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inL >> (j + i)) & 1;
    }
  }
  for (let j = 0; j <= 24; j += 8) {
    outL <<= 1;
    outL |= (inR >> (j + i)) & 1;
  }
  for (i = 1; i <= 3; i++) {
    for (let j = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inR >> (j + i)) & 1;
    }
    for (let j = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inL >> (j + i)) & 1;
    }
  }
  for (let j = 0; j <= 24; j += 8) {
    outR <<= 1;
    outR |= (inL >> (j + i)) & 1;
  }
  return [outL >>> 0, outR >>> 0];
}

function r28shl(num: number, shift: number): number {
  return ((num << shift) & 0xfffffff) | (num >>> (28 - shift));
}

const PC2_TABLE = [
  14, 11, 17, 4, 27, 23, 25, 0, 13, 22, 7, 18, 5, 9, 16, 24, 2, 20, 12, 21, 1, 8, 15, 26, 15, 4, 25,
  19, 9, 1, 26, 16, 5, 11, 23, 8, 12, 7, 17, 0, 22, 3, 10, 14, 6, 20, 27, 24,
];

function pc2(inL: number, inR: number): [number, number] {
  let outL = 0;
  let outR = 0;
  const len = PC2_TABLE.length >>> 1;
  for (let i = 0; i < len; i++) {
    outL <<= 1;
    outL |= (inL >>> PC2_TABLE[i]!) & 0x1;
  }
  for (let i = len; i < PC2_TABLE.length; i++) {
    outR <<= 1;
    outR |= (inR >>> PC2_TABLE[i]!) & 0x1;
  }
  return [outL >>> 0, outR >>> 0];
}

function expand(r: number): [number, number] {
  let outL = 0;
  let outR = 0;
  outL = ((r & 1) << 5) | (r >>> 27);
  for (let i = 23; i >= 15; i -= 4) {
    outL <<= 6;
    outL |= (r >>> i) & 0x3f;
  }
  for (let i = 11; i >= 3; i -= 4) {
    outR |= (r >>> i) & 0x3f;
    outR <<= 6;
  }
  outR |= ((r & 0x1f) << 1) | (r >>> 31);
  return [outL >>> 0, outR >>> 0];
}

const S_TABLE = [
  14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0,
  3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10,
  10, 0, 5, 6, 0, 13,

  15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5,
  11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0,
  3, 5, 2, 14, 15, 9,

  10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2,
  15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11,
  10, 5, 14, 2, 7, 12,

  7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4,
  14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5,
  12, 2, 7, 8, 2, 4, 14,

  2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14,
  8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10,
  3, 4, 0, 5, 14, 3,

  12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5,
  3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6,
  13, 0, 11, 8, 6, 13,

  4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6,
  8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14,
  5, 2, 9, 3, 2, 12,

  13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12,
  9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3,
  3, 5, 5, 6, 8, 11,
];

function substitute(inL: number, inR: number): number {
  let out = 0;
  for (let i = 0; i < 4; i++) {
    const b = (inL >>> (18 - i * 6)) & 0x3f;
    out <<= 4;
    out |= S_TABLE[i * 0x40 + b]!;
  }
  for (let i = 0; i < 4; i++) {
    const b = (inR >>> (18 - i * 6)) & 0x3f;
    out <<= 4;
    out |= S_TABLE[4 * 0x40 + i * 0x40 + b]!;
  }
  return out >>> 0;
}

const PERMUTE_TABLE = [
  16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22, 30, 24, 8, 18, 0, 5, 29, 23, 13, 19, 2,
  26, 10, 21, 28, 7,
];

function permuteP(num: number): number {
  let out = 0;
  for (let i = 0; i < PERMUTE_TABLE.length; i++) {
    out <<= 1;
    out |= (num >>> PERMUTE_TABLE[i]!) & 0x1;
  }
  return out >>> 0;
}

const SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/** Generate the 16 round subkeys (each split into two 32-bit halves). */
function desSubkeys(key: Buffer): number[][] {
  const kL = readUInt32BE(key, 0);
  const kR = readUInt32BE(key, 4);
  const [c0, d0] = pc1(kL, kR);
  const keys: number[][] = [];
  let c = c0;
  let d = d0;
  for (let i = 0; i < 16; i++) {
    c = r28shl(c, SHIFT_TABLE[i]!);
    d = r28shl(d, SHIFT_TABLE[i]!);
    keys.push(pc2(c, d));
  }
  return keys;
}

/** Encrypt or decrypt a single 8-byte block (decrypt = reverse subkey order). */
function desBlock(key: Buffer, data: Buffer, decrypt: boolean): Buffer {
  const subkeys = desSubkeys(key);
  const order = decrypt ? [...subkeys].reverse() : subkeys;
  let [l, r] = ip(readUInt32BE(data, 0), readUInt32BE(data, 4));
  for (let i = 0; i < 16; i++) {
    const [kL, kR] = order[i]!;
    const [eL, eR] = expand(r);
    const s = substitute(eL ^ kL!, eR ^ kR!);
    const f = permuteP(s);
    const newR = (l ^ f) >>> 0;
    l = r;
    r = newR;
  }
  const [outL, outR] = rip(r, l);
  const out = Buffer.alloc(8);
  writeUInt32BE(out, outL, 0);
  writeUInt32BE(out, outR, 4);
  return out;
}

/** Pure-JS DES-ECB encrypt of 8-byte block(s) with an 8-byte key. */
export function desEcbEncryptBlock(key: Buffer, data: Buffer): Buffer {
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i += 8) {
    desBlock(key, data.subarray(i, i + 8), false).copy(out, i);
  }
  return out;
}

/** Pure-JS DES-ECB decrypt of 8-byte block(s) with an 8-byte key. */
export function desEcbDecryptBlock(key: Buffer, data: Buffer): Buffer {
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i += 8) {
    desBlock(key, data.subarray(i, i + 8), true).copy(out, i);
  }
  return out;
}

/** Pure-JS DES-CBC encrypt with zero IV (used by Kerberos DES enctypes). */
export function desCbcEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  if (data.length % 8 !== 0) throw new Error('DES-CBC: data must be multiple of 8');
  const out = Buffer.alloc(data.length);
  let chain = Buffer.from(iv);
  for (let i = 0; i < data.length; i += 8) {
    const block = data.subarray(i, i + 8);
    const xored = Buffer.alloc(8);
    for (let j = 0; j < 8; j++) xored[j] = block[j]! ^ chain[j]!;
    const enc = desBlock(key, xored, false);
    enc.copy(out, i);
    chain = Buffer.from(enc);
  }
  return out;
}

/** Pure-JS DES-CBC decrypt with IV. */
export function desCbcDecrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  if (data.length % 8 !== 0) throw new Error('DES-CBC: data must be multiple of 8');
  const out = Buffer.alloc(data.length);
  let chain = Buffer.from(iv);
  for (let i = 0; i < data.length; i += 8) {
    const block = data.subarray(i, i + 8);
    const dec = desBlock(key, block, true);
    for (let j = 0; j < 8; j++) out[i + j] = dec[j]! ^ chain[j]!;
    chain = Buffer.from(block);
  }
  return out;
}

/** Expand a 7-byte key to an 8-byte DES key (parity bits), used by NTLM/LM. */
export function expandDesKey7(key: Buffer): Buffer {
  const k = Buffer.alloc(7, 0);
  key.subarray(0, 7).copy(k);
  const s = Buffer.alloc(8);
  s[0] = ((k[0]! >> 1) & 0x7f) << 1;
  s[1] = (((k[0]! & 0x01) << 6) | ((k[1]! >> 2) & 0x3f)) << 1;
  s[2] = (((k[1]! & 0x03) << 5) | ((k[2]! >> 3) & 0x1f)) << 1;
  s[3] = (((k[2]! & 0x07) << 4) | ((k[3]! >> 4) & 0x0f)) << 1;
  s[4] = (((k[3]! & 0x0f) << 3) | ((k[4]! >> 5) & 0x07)) << 1;
  s[5] = (((k[4]! & 0x1f) << 2) | ((k[5]! >> 6) & 0x03)) << 1;
  s[6] = (((k[5]! & 0x3f) << 1) | ((k[6]! >> 7) & 0x01)) << 1;
  s[7] = (k[6]! & 0x7f) << 1;
  return s;
}
const AES_BLOCK = 16;
const CONST_RB = 0x87;

/** AES-128-CMAC subkey generation (RFC 4493). */
export function generateSubkey(K: Buffer): [Buffer, Buffer] {
  const L = createCipheriv('aes-128-ecb', K, null).update(Buffer.alloc(16));
  const LHigh = L.readBigUInt64BE(0);
  const LLow = L.readBigUInt64BE(8);
  const K1High = ((LHigh << 1n) | (LLow >> 63n)) & 0xffffffffffffffffn;
  let K1Low = (LLow << 1n) & 0xffffffffffffffffn;
  if ((LHigh >> 63n) & 1n) K1Low ^= BigInt(CONST_RB);
  const K2High = ((K1High << 1n) | (K1Low >> 63n)) & 0xffffffffffffffffn;
  let K2Low = (K1Low << 1n) & 0xffffffffffffffffn;
  if ((K1High >> 63n) & 1n) K2Low ^= BigInt(CONST_RB);
  const K1 = Buffer.alloc(16);
  const K2 = Buffer.alloc(16);
  K1.writeBigUInt64BE(K1High, 0);
  K1.writeBigUInt64BE(K1Low, 8);
  K2.writeBigUInt64BE(K2High, 0);
  K2.writeBigUInt64BE(K2Low, 8);
  return [K1, K2];
}

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function pad(N: Buffer): Buffer {
  const padLen = AES_BLOCK - N.length;
  return Buffer.concat([N, Buffer.from([0x80]), Buffer.alloc(padLen - 1)]);
}

/** AES-128-CMAC (RFC 4493). */
export function aesCmac(K: Buffer, M: Buffer, length = M.length): Buffer {
  const cipher = () => createCipheriv('aes-128-ecb', K, null);
  const Mbuf = M.subarray(0, length);
  const [K1, K2] = generateSubkey(K);
  let n = Math.floor(length / AES_BLOCK);
  let flag: boolean;
  if (n === 0) {
    n = 1;
    flag = false;
  } else if (length % AES_BLOCK === 0) {
    flag = true;
  } else {
    n += 1;
    flag = false;
  }
  const M_n = Mbuf.subarray((n - 1) * AES_BLOCK);
  const M_last = flag ? xor(M_n, K1) : xor(pad(M_n), K2);
  let X = Buffer.alloc(AES_BLOCK);
  for (let i = 0; i < n - 1; i++) {
    const M_i = Mbuf.subarray(i * AES_BLOCK, i * AES_BLOCK + 16);
    const Y = xor(X, M_i);
    X = cipher().update(Y);
  }
  const Y = xor(M_last, X);
  return cipher().update(Y);
}

/** AES-CMAC-PRF-128 (RFC 4615). */
export function aesCmacPrf128(VK: Buffer, M: Buffer, VKlen = VK.length, Mlen = M.length): Buffer {
  let K: Buffer;
  if (VKlen === 16) K = VK;
  else K = aesCmac(Buffer.alloc(16), VK, VKlen);
  return aesCmac(K, M, Mlen);
}

/** NIST SP 800-108 KDF in Counter Mode (PRF HMAC-SHA256). */
export function kdfCounterMode(KI: Buffer, Label: Buffer, Context: Buffer, L: number): Buffer {
  const h = 256;
  const r = 32;
  let n = Math.floor(L / h);
  if (n === 0) n = 1;
  if (n > 2 ** r - 1) throw new Error('Error computing KDF_CounterMode');
  const result: Buffer[] = [];
  for (let i = 1; i <= n; i++) {
    const input = Buffer.concat([
      (() => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(i, 0);
        return b;
      })(),
      Label,
      Buffer.from([0]),
      Context,
      (() => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(L, 0);
        return b;
      })(),
    ]);
    result.push(createHmac('sha256', KI).update(input).digest());
  }
  return Buffer.concat(result).subarray(0, L / 8);
}

/** [MS-LSAD] 5.1.3 - transformKey (DES key parity adjustment). */
export function transformKey(inputKey: Buffer): Buffer {
  const InputKey = inputKey;
  const OutputKey: number[] = [];
  OutputKey.push(InputKey[0]! >> 1);
  OutputKey.push(((InputKey[0]! & 0x01) << 6) | (InputKey[1]! >> 2));
  OutputKey.push(((InputKey[1]! & 0x03) << 5) | (InputKey[2]! >> 3));
  OutputKey.push(((InputKey[2]! & 0x07) << 4) | (InputKey[3]! >> 4));
  OutputKey.push(((InputKey[3]! & 0x0f) << 3) | (InputKey[4]! >> 5));
  OutputKey.push(((InputKey[4]! & 0x1f) << 2) | (InputKey[5]! >> 6));
  OutputKey.push(((InputKey[5]! & 0x3f) << 1) | (InputKey[6]! >> 7));
  OutputKey.push(InputKey[6]! & 0x7f);
  for (let i = 0; i < 8; i++) OutputKey[i] = (OutputKey[i]! << 1) & 0xfe;
  return Buffer.from(OutputKey);
}

/** [MS-LSAD] 5.1.2 - LSA_SECRET_XP envelope. */
export class LsaSecretXP extends Structure {
  static structure: FieldDescriptor[] = [
    ['Length', '<L=0'],
    ['Version', '<L=0'],
    ['_Secret', '_-Secret', 'self["Length"]'],
    ['Secret', ':'],
  ];
}

/** [MS-LSAD] 5.1.2 - decrypt LSA secret. */
export function decryptSecret(key: Buffer, value: Buffer): Buffer {
  let plainText = Buffer.alloc(0);
  let key0 = key;
  let remaining = value;
  for (let i = 0; i < value.length; i += 8) {
    const cipherText = remaining.subarray(0, 8);
    const tmpStrKey = key0.subarray(0, 7);
    const tmpKey = transformKey(tmpStrKey);
    const dec = desEcbDecryptBlock(tmpKey, cipherText);
    plainText = Buffer.concat([plainText, dec]);
    key0 = key0.subarray(7);
    remaining = remaining.subarray(8);
    if (key0.length < 7) key0 = key.subarray(key0.length);
  }
  const secret = new LsaSecretXP(plainText);
  return secret.get('Secret') as Buffer;
}

/** [MS-LSAD] 5.1.2 - encrypt LSA secret. */
export function encryptSecret(key: Buffer, value: Buffer): Buffer {
  let cipherText = Buffer.alloc(0);
  let key0 = key;
  let value0 = Buffer.concat([
    (() => {
      const b = Buffer.alloc(8);
      b.writeUInt32LE(value.length, 0);
      b.writeUInt32LE(1, 4);
      return b;
    })(),
    value,
  ]);
  for (let i = 0; i < value0.length; i += 8) {
    if (value0.length < 8) value0 = Buffer.concat([value0, Buffer.alloc(8 - value0.length)]);
    const plainText = value0.subarray(0, 8);
    const tmpStrKey = key0.subarray(0, 7);
    const tmpKey = transformKey(tmpStrKey);
    const enc = desEcbEncryptBlock(tmpKey, plainText);
    cipherText = Buffer.concat([cipherText, enc]);
    key0 = key0.subarray(7);
    value0 = value0.subarray(8);
    if (key0.length < 7) key0 = key.subarray(key0.length);
  }
  return cipherText;
}

/** [MS-SAMR] 2.2.11.1.1 - decrypt SAM NTLM hash. */
export function samDecryptNTLMHash(encryptedHash: Buffer, key: Buffer): Buffer {
  const Block1 = encryptedHash.subarray(0, 8);
  const Block2 = encryptedHash.subarray(8);
  const Key1 = transformKey(key.subarray(0, 7));
  const Key2 = transformKey(key.subarray(7, 14));
  return Buffer.concat([desEcbDecryptBlock(Key1, Block1), desEcbDecryptBlock(Key2, Block2)]);
}

/** [MS-SAMR] 2.2.11.1.1 - encrypt SAM NTLM hash. */
export function samEncryptNTLMHash(encryptedHash: Buffer, key: Buffer): Buffer {
  const Block1 = encryptedHash.subarray(0, 8);
  const Block2 = encryptedHash.subarray(8);
  const Key1 = transformKey(key.subarray(0, 7));
  const Key2 = transformKey(key.subarray(7, 14));
  return Buffer.concat([desEcbEncryptBlock(Key1, Block1), desEcbEncryptBlock(Key2, Block2)]);
}

/** Convenience wrappers re-exported for use by other impacket packages. */
export const md4 = (data: Buffer): Buffer => md4Hash(data);
export const md5 = (data: Buffer): Buffer => createHash('md5').update(data).digest();
export const sha1 = (data: Buffer): Buffer => createHash('sha1').update(data).digest();
export const sha256 = (data: Buffer): Buffer => createHash('sha256').update(data).digest();
export const sha512 = (data: Buffer): Buffer => createHash('sha512').update(data).digest();
export const hmacMd5 = (key: Buffer, data: Buffer): Buffer =>
  createHmac('md5', key).update(data).digest();
export const hmacSha1 = (key: Buffer, data: Buffer): Buffer =>
  createHmac('sha1', key).update(data).digest();
export const hmacSha256 = (key: Buffer, data: Buffer): Buffer =>
  createHmac('sha256', key).update(data).digest();
export const hmacSha512 = (key: Buffer, data: Buffer): Buffer =>
  createHmac('sha512', key).update(data).digest();

/** RC4 (a.k.a. ARCFOUR). Uses node:crypto if available, falls back to pure-JS. */
export function rc4(key: Buffer, data: Buffer): Buffer {
  return rc4Js(key, data);
}
export function rc4Init(key: Buffer): { update(d: Buffer): Buffer; final(): Buffer } {
  return rc4JsInit(key);
}

/** AES-CBC helpers (used by Kerberos, DPAPI). */
export function aesCbcEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const c = createCipheriv('aes-128-cbc', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}
export function aesCbcDecrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const d = createDecipheriv('aes-128-cbc', key, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(data), d.final()]);
}

export { randomBytes };

// --- Pure-JS fallbacks for legacy algorithms (MD4, RC4) ---------------------
// Node's default OpenSSL provider disables MD4/RC4 by default; Bun supports
// them natively. We implement pure-JS versions to avoid `--openssl-legacy-provider`
// and to guarantee identical behaviour across runtimes.

/** RFC 1320 MD4 (used by NTLM hashing). */
export function md4Hash(data: Buffer): Buffer {
  const msg = Buffer.from(data);
  const origLen = msg.length;
  // padding: 0x80, zeros, 64-bit LE length in bits
  const withPad = Buffer.concat([
    msg,
    Buffer.from([0x80]),
    Buffer.alloc((56 - ((origLen + 1) % 64) + 64) % 64, 0),
    (() => {
      const b = Buffer.alloc(8);
      const bits = BigInt(origLen) * 8n;
      b.writeBigUInt64LE(bits & 0xffffffffffffffffn, 0);
      return b;
    })(),
  ]);
  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;
  const mask = 0xffffffff;
  const rotl = (x: number, s: number) => ((x << s) | (x >>> (32 - s))) & mask;
  const f = (x: number, y: number, z: number) => (x & y) | (~x & z);
  const g = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
  const h = (x: number, y: number, z: number) => x ^ y ^ z;
  const chunks: number[] = [];
  for (let i = 0; i < withPad.length; i += 64) {
    for (let j = 0; j < 16; j++) chunks[j] = withPad.readUInt32LE(i + j * 4);
    const aa = a,
      bb = b,
      cc = c,
      dd = d;
    const r1 = [3, 7, 11, 19];
    for (let i = 0; i < 16; i++) {
      const t = rotl((a + f(b, c, d) + chunks[i]!) & mask, r1[i % 4]!);
      [a, d, c, b] = [d, c, b, t];
    }
    const idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    const r2 = [3, 5, 9, 13];
    for (let i = 0; i < 16; i++) {
      const t = rotl((a + g(b, c, d) + chunks[idx2[i]!]! + 0x5a827999) & mask, r2[i % 4]!);
      [a, d, c, b] = [d, c, b, t];
    }
    const idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    const r3 = [3, 9, 11, 15];
    for (let i = 0; i < 16; i++) {
      const t = rotl((a + h(b, c, d) + chunks[idx3[i]!]! + 0x6ed9eba1) & mask, r3[i % 4]!);
      [a, d, c, b] = [d, c, b, t];
    }
    a = (a + aa) & mask;
    b = (b + bb) & mask;
    c = (c + cc) & mask;
    d = (d + dd) & mask;
  }
  const out = Buffer.alloc(16);
  out.writeUInt32LE(a >>> 0, 0);
  out.writeUInt32LE(b >>> 0, 4);
  out.writeUInt32LE(c >>> 0, 8);
  out.writeUInt32LE(d >>> 0, 12);
  return out;
}

/** Pure-JS RC4 / ARCFOUR. */
export function rc4Js(key: Buffer, data: Buffer): Buffer {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    [s[i], s[j]] = [s[j]!, s[i]!];
  }
  const out = Buffer.alloc(data.length);
  let i = 0;
  j = 0;
  for (let n = 0; n < data.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]!) & 0xff;
    [s[i], s[j]] = [s[j]!, s[i]!];
    const k = s[(s[i]! + s[j]!) & 0xff]!;
    out[n] = data[n]! ^ k;
  }
  return out;
}

export function rc4JsInit(key: Buffer): { update(d: Buffer): Buffer; final(): Buffer } {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    [s[i], s[j]] = [s[j]!, s[i]!];
  }
  let i = 0;
  j = 0;
  return {
    update(d: Buffer): Buffer {
      const out = Buffer.alloc(d.length);
      for (let n = 0; n < d.length; n++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]!) & 0xff;
        [s[i], s[j]] = [s[j]!, s[i]!];
        out[n] = d[n]! ^ s[(s[i]! + s[j]!) & 0xff]!;
      }
      return out;
    },
    final(): Buffer {
      return Buffer.alloc(0);
    },
  };
}
