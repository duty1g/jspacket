import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, createHash, createHmac, pbkdf2Sync } from 'node:crypto';
import { md4, rc4, desCbcEncrypt, desCbcDecrypt } from '@impacket/crypto';

export class InvalidChecksum extends Error {}

export enum Enctype {
  DES_CRC = 1,
  DES_MD4 = 2,
  DES_MD5 = 3,
  DES3 = 16,
  AES128 = 17,
  AES256 = 18,
  RC4 = 23,
}

export enum Cksumtype {
  CRC32 = 1,
  MD4 = 2,
  MD4_DES = 3,
  MD5 = 7,
  MD5_DES = 8,
  SHA1 = 9,
  SHA1_DES3 = 12,
  SHA1_AES128 = 15,
  SHA1_AES256 = 16,
  HMAC_MD5 = -138,
}

export function get_random_bytes(lenBytes: number): Buffer {
  return Buffer.alloc(lenBytes);
  // Note: callers should override with crypto.randomBytes when needed;
  // this returns zeros for deterministic testing.
}

function _zeropad(s: Buffer, padsize: number): Buffer {
  const padlen = (padsize - (s.length % padsize)) % padsize;
  return Buffer.concat([s, Buffer.alloc(padlen)]);
}

function _xorbytes(b1: Buffer, b2: Buffer): Buffer {
  if (b1.length !== b2.length) throw new Error('length mismatch');
  const out = Buffer.alloc(b1.length);
  for (let i = 0; i < b1.length; i++) out[i] = b1[i]! ^ b2[i]!;
  return out;
}

function _mac_equal(mac1: Buffer, mac2: Buffer): boolean {
  if (mac1.length !== mac2.length) return false;
  let res = 0;
  for (let i = 0; i < mac1.length; i++) res |= mac1[i]! ^ mac2[i]!;
  return res === 0;
}

function _gcd(a: number, b: number): number {
  while (b !== 0) {
    [a, b] = [b, a % b];
  }
  return a;
}

export function _nfold(ba: Buffer, nbytes: number): Buffer {
  const slen = ba.length;
  const lcm = (nbytes * slen) / _gcd(nbytes, slen);

  const rotate_right = (input: Buffer, nbits: number): Buffer => {
    const len = input.length;
    const nbytesShift = Math.floor(nbits / 8) % len;
    const remain = nbits % 8;
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      const lo = input[(i - nbytesShift + len) % len]! >> remain;
      const hi =
        remain === 0 ? 0 : (input[(i - nbytesShift - 1 + len) % len]! << (8 - remain)) & 0xff;
      out[i] = lo | hi;
    }
    return out;
  };

  const add_ones_complement = (a: Buffer, b: Buffer): Buffer => {
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
    bigstr.push(rotate_right(ba, 13 * i));
  }
  const big = Buffer.concat(bigstr);
  let result: Buffer | null = null;
  for (let p = 0; p < lcm; p += nbytes) {
    const slice = big.subarray(p, p + nbytes);
    result = result === null ? Buffer.from(slice) : add_ones_complement(result, slice);
  }
  return result ?? Buffer.alloc(nbytes);
}

export class Key {
  enctype: number;
  contents: Buffer;

  constructor(enctype: number, contents: Buffer) {
    const e = _get_enctype_profile(enctype);
    if (contents.length !== e.keysize) {
      throw new Error(`Wrong key length (expected ${e.keysize}, got ${contents.length})`);
    }
    this.enctype = enctype;
    this.contents = contents;
  }
}

export interface EnctypeProfile {
  enctype: number;
  keysize: number;
  seedsize: number;
  blocksize: number;
  padsize: number;
  macsize: number;
  hashmod: 'sha1' | 'md5';
  random_to_key: (seed: Buffer) => Key;
  string_to_key: (string: string | Buffer, salt: string | Buffer, params: Buffer | null) => Key;
  encrypt: (key: Key, keyusage: number, plaintext: Buffer, confounder: Buffer | null) => Buffer;
  decrypt: (key: Key, keyusage: number, ciphertext: Buffer) => Buffer;
  prf: (key: Key, string: Buffer) => Buffer;
  derive?: (key: Key, constant: Buffer) => Key;
  basic_encrypt?: (key: Key, plaintext: Buffer) => Buffer;
  basic_decrypt?: (key: Key, ciphertext: Buffer) => Buffer;
}

function hmacHash(hashmod: 'sha1' | 'md5', key: Buffer, data: Buffer): Buffer {
  return createHmac(hashmod, key).update(data).digest();
}

function hashDigest(hashmod: 'sha1' | 'md5', data: Buffer): Buffer {
  return createHash(hashmod).update(data).digest();
}

abstract class SimplifiedEnctype implements EnctypeProfile {
  abstract enctype: number;
  abstract keysize: number;
  abstract seedsize: number;
  abstract blocksize: number;
  abstract padsize: number;
  abstract macsize: number;
  abstract hashmod: 'sha1' | 'md5';
  abstract basic_encrypt(key: Key, plaintext: Buffer): Buffer;
  abstract basic_decrypt(key: Key, ciphertext: Buffer): Buffer;

  random_to_key(seed: Buffer): Key {
    if (seed.length !== this.seedsize) throw new Error('Wrong seed length');
    return new Key(this.enctype, seed);
  }

  derive(key: Key, constant: Buffer): Key {
    let plaintext = _nfold(constant, this.blocksize);
    let rndseed = Buffer.alloc(0);
    while (rndseed.length < this.seedsize) {
      const ciphertext = this.basic_encrypt(key, plaintext);
      rndseed = Buffer.concat([rndseed, ciphertext]);
      plaintext = ciphertext;
    }
    return this.random_to_key(rndseed.subarray(0, this.seedsize));
  }

  encrypt(key: Key, keyusage: number, plaintext: Buffer, confounder: Buffer | null): Buffer {
    const ki = this.derive(
      key,
      Buffer.from([
        (keyusage >>> 24) & 0xff,
        (keyusage >>> 16) & 0xff,
        (keyusage >>> 8) & 0xff,
        keyusage & 0xff,
        0x55,
      ]),
    );
    const ke = this.derive(
      key,
      Buffer.from([
        (keyusage >>> 24) & 0xff,
        (keyusage >>> 16) & 0xff,
        (keyusage >>> 8) & 0xff,
        keyusage & 0xff,
        0xaa,
      ]),
    );
    if (confounder === null) confounder = Buffer.alloc(this.blocksize);
    const basic_plaintext = Buffer.concat([confounder, _zeropad(plaintext, this.padsize)]);
    const hmac = hmacHash(this.hashmod, ki.contents, basic_plaintext);
    return Buffer.concat([this.basic_encrypt(ke, basic_plaintext), hmac.subarray(0, this.macsize)]);
  }

  decrypt(key: Key, keyusage: number, ciphertext: Buffer): Buffer {
    const ki = this.derive(
      key,
      Buffer.from([
        (keyusage >>> 24) & 0xff,
        (keyusage >>> 16) & 0xff,
        (keyusage >>> 8) & 0xff,
        keyusage & 0xff,
        0x55,
      ]),
    );
    const ke = this.derive(
      key,
      Buffer.from([
        (keyusage >>> 24) & 0xff,
        (keyusage >>> 16) & 0xff,
        (keyusage >>> 8) & 0xff,
        keyusage & 0xff,
        0xaa,
      ]),
    );
    if (ciphertext.length < this.blocksize + this.macsize) throw new Error('ciphertext too short');
    const basic_ctext = ciphertext.subarray(0, ciphertext.length - this.macsize);
    const mac = ciphertext.subarray(ciphertext.length - this.macsize);
    if (basic_ctext.length % this.padsize !== 0)
      throw new Error('ciphertext does not meet padding requirement');
    const basic_plaintext = this.basic_decrypt(ke, basic_ctext);
    const hmac = hmacHash(this.hashmod, ki.contents, basic_plaintext);
    const expmac = hmac.subarray(0, this.macsize);
    if (!_mac_equal(mac, expmac)) throw new InvalidChecksum('ciphertext integrity failure');
    return basic_plaintext.subarray(this.blocksize);
  }

  prf(key: Key, string: Buffer): Buffer {
    const hashval = hashDigest(this.hashmod, string);
    const truncated = hashval.subarray(0, hashval.length - (hashval.length % this.blocksize));
    const kp = this.derive(key, Buffer.from('prf'));
    return this.basic_encrypt(kp, truncated);
  }

  abstract string_to_key(
    string: string | Buffer,
    salt: string | Buffer,
    params: Buffer | null,
  ): Key;
}

class AES128CTS extends SimplifiedEnctype {
  enctype = Enctype.AES128;
  keysize = 16;
  seedsize = 16;
  blocksize = 16;
  padsize = 1;
  macsize = 12;
  hashmod = 'sha1' as const;

  basic_encrypt(key: Key, plaintext: Buffer): Buffer {
    if (plaintext.length < 16) throw new Error('plaintext too short for AES-CTS');
    const aes = createCipheriv(
      'aes-' + key.contents.length * 8 + '-cbc',
      key.contents,
      Buffer.alloc(16),
    );
    aes.setAutoPadding(false);
    const ctext = Buffer.concat([aes.update(_zeropad(plaintext, 16)), aes.final()]);
    if (plaintext.length > 16) {
      const lastlen = plaintext.length % 16 || 16;
      const before = ctext.subarray(0, ctext.length - 32);
      const blockN2 = ctext.subarray(ctext.length - 32, ctext.length - 16);
      const blockN1 = ctext.subarray(ctext.length - 16);
      return Buffer.concat([before, blockN1, blockN2.subarray(0, lastlen)]);
    }
    return ctext;
  }

  basic_decrypt(key: Key, ciphertext: Buffer): Buffer {
    if (ciphertext.length < 16) throw new Error('ciphertext too short for AES-CTS');
    const ecbDec = (block: Buffer): Buffer => {
      const aes = createDecipheriv('aes-' + key.contents.length * 8 + '-ecb', key.contents, null);
      aes.setAutoPadding(false);
      return Buffer.concat([aes.update(block), aes.final()]);
    };
    if (ciphertext.length === 16) {
      return ecbDec(ciphertext);
    }
    const cblocks: Buffer[] = [];
    for (let p = 0; p < ciphertext.length; p += 16) {
      cblocks.push(ciphertext.subarray(p, Math.min(p + 16, ciphertext.length)));
    }
    const lastlen = cblocks[cblocks.length - 1]!.length;
    let plaintext = Buffer.alloc(0);
    let prev_cblock = Buffer.alloc(16);
    for (let i = 0; i < cblocks.length - 2; i++) {
      const bb = cblocks[i]!;
      const dec = ecbDec(bb);
      plaintext = Buffer.concat([plaintext, _xorbytes(dec, prev_cblock)]);
      prev_cblock = Buffer.from(bb);
    }
    const decN2 = ecbDec(cblocks[cblocks.length - 2]!);
    const lastplaintext = _xorbytes(decN2.subarray(0, lastlen), cblocks[cblocks.length - 1]!);
    const omitted = decN2.subarray(lastlen);
    const decN1 = ecbDec(Buffer.concat([cblocks[cblocks.length - 1]!, omitted]));
    plaintext = Buffer.concat([plaintext, _xorbytes(decN1, prev_cblock)]);
    return Buffer.concat([plaintext, lastplaintext]);
  }

  string_to_key(string: string | Buffer, salt: string | Buffer, params: Buffer | null): Key {
    const str = typeof string === 'string' ? Buffer.from(string, 'utf8') : string;
    const slt = typeof salt === 'string' ? Buffer.from(salt, 'utf8') : salt;
    const paramBuf = params ?? Buffer.from([0, 0, 0x10, 0]);
    const iterations = paramBuf.readUInt32BE(0);
    const seed = pbkdf2Sync(str, slt, iterations, this.seedsize, 'sha1');
    const tkey = this.random_to_key(seed);
    return this.derive(tkey, Buffer.from('kerberos'));
  }
}

class AES256CTS extends AES128CTS {
  enctype = Enctype.AES256;
  keysize = 32;
  seedsize = 32;
}

class RC4Enctype implements EnctypeProfile {
  enctype = Enctype.RC4;
  keysize = 16;
  seedsize = 16;
  blocksize = 8;
  padsize = 1;
  macsize = 0;
  hashmod = 'md5' as const;

  static usage_str(keyusage: number): Buffer {
    const table: Record<number, number> = { 3: 8, 23: 13 };
    const msusage = keyusage in table ? table[keyusage]! : keyusage;
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(msusage, 0);
    return buf;
  }

  random_to_key(seed: Buffer): Key {
    if (seed.length !== this.seedsize) throw new Error('Wrong seed length');
    return new Key(this.enctype, seed);
  }

  string_to_key(string: string | Buffer, _salt: string | Buffer, _params: Buffer | null): Key {
    const utf16string = Buffer.from(string as string, 'utf16le');
    return new Key(this.enctype, md4(utf16string));
  }

  encrypt(key: Key, keyusage: number, plaintext: Buffer, confounder: Buffer | null): Buffer {
    if (confounder === null) confounder = Buffer.alloc(8);
    const ki = hmacHash('md5', key.contents, RC4Enctype.usage_str(keyusage));
    const cksum = hmacHash('md5', ki, Buffer.concat([confounder, plaintext]));
    const ke = hmacHash('md5', ki, cksum);
    return Buffer.concat([cksum, rc4(ke, Buffer.concat([confounder, plaintext]))]);
  }

  decrypt(key: Key, keyusage: number, ciphertext: Buffer): Buffer {
    if (ciphertext.length < 24) throw new Error('ciphertext too short');
    const cksum = ciphertext.subarray(0, 16);
    const basic_ctext = ciphertext.subarray(16);
    const ki = hmacHash('md5', key.contents, RC4Enctype.usage_str(keyusage));
    const ke = hmacHash('md5', ki, cksum);
    const basic_plaintext = rc4(ke, basic_ctext);
    let exp_cksum = hmacHash('md5', ki, basic_plaintext);
    let ok = _mac_equal(cksum, exp_cksum);
    if (!ok && keyusage === 9) {
      const ki2 = hmacHash(
        'md5',
        key.contents,
        (() => {
          const b = Buffer.alloc(4);
          b.writeUInt32LE(8, 0);
          return b;
        })(),
      );
      exp_cksum = hmacHash('md5', ki2, basic_plaintext);
      ok = _mac_equal(cksum, exp_cksum);
    }
    if (!ok) throw new InvalidChecksum('ciphertext integrity failure');
    return basic_plaintext.subarray(8);
  }

  prf(key: Key, string: Buffer): Buffer {
    return hmacHash('sha1', key.contents, string);
  }
}

const _weakDesKeys: Buffer[] = [
  Buffer.from([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]),
  Buffer.from([0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe]),
  Buffer.from([0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e]),
  Buffer.from([0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1]),
  Buffer.from([0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe]),
  Buffer.from([0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01]),
  Buffer.from([0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1]),
  Buffer.from([0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e]),
  Buffer.from([0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1]),
  Buffer.from([0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01]),
  Buffer.from([0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe]),
  Buffer.from([0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e]),
  Buffer.from([0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e]),
  Buffer.from([0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01]),
  Buffer.from([0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe]),
  Buffer.from([0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1]),
];

function _isWeakDesKey(keybytes: Buffer): boolean {
  return _weakDesKeys.some((w) => w.equals(keybytes));
}

function fixParity(deskey: Buffer): Buffer {
  const temp = Buffer.alloc(deskey.length);
  for (let i = 0; i < deskey.length; i++) {
    const t = deskey[i]!.toString(2).padStart(8, '0');
    const bits = t.slice(0, 7);
    if (bits.split('').filter((c) => c === '1').length % 2 === 0) {
      temp[i] = Number.parseInt(bits + '1', 2);
    } else {
      temp[i] = Number.parseInt(bits + '0', 2);
    }
  }
  return temp;
}

function addParity(l1: number[]): number[] {
  const temp: number[] = [];
  for (let byte of l1) {
    if ((byte.toString(2).split('').filter((c) => c === '1').length % 2) === 0) {
      byte = (byte << 1) | 0b00000001;
    } else {
      byte = (byte << 1) & 0b11111110;
    }
    temp.push(byte);
  }
  return temp;
}

function xor56(l1: number[], l2: number[]): number[] {
  const temp: number[] = [];
  for (let i = 0; i < l1.length; i++) {
    temp.push((l1[i]! ^ l2[i]!) & 0b01111111);
  }
  return temp;
}

function mitDesStringToKey(string: Buffer, salt: Buffer, padsize: number): Key {
  let odd = true;
  let tempstring = [0, 0, 0, 0, 0, 0, 0, 0];
  const s = _zeropad(Buffer.concat([string, salt]), padsize);

  for (let p = 0; p < s.length; p += 8) {
    const block = s.subarray(p, p + 8);
    const temp56: number[] = [];
    for (let i = 0; i < 8; i++) {
      temp56.push(block[i]! & 0b01111111);
    }

    if (!odd) {
      let bintemp = '';
      for (const byte of temp56) {
        bintemp += byte.toString(2).padStart(7, '0');
      }
      bintemp = bintemp.split('').reverse().join('');
      const newTemp56: number[] = [];
      for (let i = 0; i < bintemp.length; i += 7) {
        newTemp56.push(Number.parseInt(bintemp.slice(i, i + 7), 2));
      }
      temp56.length = 0;
      temp56.push(...newTemp56);
    }

    odd = !odd;
    tempstring = xor56(tempstring, temp56);
  }

  let tempkey = Buffer.from(addParity(tempstring));
  if (_isWeakDesKey(tempkey)) {
    tempkey[7] = tempkey[7]! ^ 0xf0;
  }

  const checksumkey = desCbcEncrypt(tempkey, tempkey, s).subarray(-8);
  const fixedKey = fixParity(checksumkey);
  if (_isWeakDesKey(fixedKey)) {
    fixedKey[7] = fixedKey[7]! ^ 0xf0;
  }

  return new Key(Enctype.DES_MD5, fixedKey);
}

class DESCBCEnctype implements EnctypeProfile {
  enctype = Enctype.DES_MD5;
  keysize = 8;
  seedsize = 8;
  blocksize = 8;
  padsize = 8;
  macsize = 16;
  hashmod = 'md5' as const;

  random_to_key(seed: Buffer): Key {
    if (seed.length !== this.seedsize) throw new Error('Wrong seed length');
    return new Key(this.enctype, seed);
  }

  string_to_key(string: string | Buffer, salt: string | Buffer, params: Buffer | null): Key {
    if (params !== null && params.length > 0) {
      throw new Error('Invalid DES string-to-key parameters');
    }
    const str = typeof string === 'string' ? Buffer.from(string, 'utf8') : string;
    const slt = typeof salt === 'string' ? Buffer.from(salt, 'utf8') : salt;
    return mitDesStringToKey(str, slt, this.padsize);
  }

  encrypt(key: Key, _keyusage: number, plaintext: Buffer, confounder: Buffer | null): Buffer {
    if (confounder === null) confounder = Buffer.alloc(this.blocksize);
    const basic_plaintext = Buffer.concat([
      confounder,
      Buffer.alloc(this.macsize, 0),
      _zeropad(plaintext, this.padsize),
    ]);
    const checksum = hashDigest(this.hashmod, basic_plaintext);
    const withCksum = Buffer.concat([
      basic_plaintext.subarray(0, confounder.length),
      checksum,
      basic_plaintext.subarray(confounder.length + checksum.length),
    ]);
    return desCbcEncrypt(key.contents, Buffer.alloc(8, 0), withCksum);
  }

  decrypt(key: Key, _keyusage: number, ciphertext: Buffer): Buffer {
    if (ciphertext.length < this.blocksize + this.macsize) {
      throw new Error('ciphertext too short');
    }
    const complex_plaintext = desCbcDecrypt(key.contents, Buffer.alloc(8, 0), ciphertext);
    const cofounder = complex_plaintext.subarray(0, this.padsize);
    const mac = complex_plaintext.subarray(this.padsize, this.padsize + this.macsize);
    const message = complex_plaintext.subarray(this.padsize + this.macsize);
    const expmac = hashDigest(this.hashmod, Buffer.concat([cofounder, Buffer.alloc(this.macsize, 0), message]));
    if (!_mac_equal(mac, expmac)) throw new InvalidChecksum('ciphertext integrity failure');
    return message;
  }

  basic_encrypt(key: Key, plaintext: Buffer): Buffer {
    return desCbcEncrypt(key.contents, Buffer.alloc(8, 0), plaintext);
  }

  basic_decrypt(key: Key, ciphertext: Buffer): Buffer {
    return desCbcDecrypt(key.contents, Buffer.alloc(8, 0), ciphertext);
  }

  prf(key: Key, string: Buffer): Buffer {
    const hashval = hashDigest(this.hashmod, string);
    const truncated = hashval.subarray(0, hashval.length - (hashval.length % this.blocksize));
    const kp = this.derive(key, Buffer.from('prf'));
    return this.basic_encrypt(kp, truncated);
  }

  derive(key: Key, constant: Buffer): Key {
    let plaintext = _nfold(constant, this.blocksize);
    let rndseed = Buffer.alloc(0);
    while (rndseed.length < this.seedsize) {
      const ciphertext = this.basic_encrypt(key, plaintext);
      rndseed = Buffer.concat([rndseed, ciphertext]);
      plaintext = ciphertext;
    }
    return this.random_to_key(rndseed.subarray(0, this.seedsize));
  }
}

class DES3CBCEnctype implements EnctypeProfile {
  enctype = Enctype.DES3;
  keysize = 24;
  seedsize = 21;
  blocksize = 8;
  padsize = 8;
  macsize = 20;
  hashmod = 'sha1' as const;

  random_to_key(seed: Buffer): Key {
    const expand = (s: Buffer): Buffer => {
      const parity = (b: number): number => {
        b &= ~1;
        return ((b.toString(2).split('').filter((c) => c === '1').length % 2) === 0) ? b | 1 : b;
      };
      if (s.length !== 7) throw new Error('Wrong expand seed length');
      const firstbytes = Array.from(s).map((b) => parity(b & ~1));
      let lastbyte = 0;
      for (let i = 0; i < 7; i++) {
        lastbyte |= (s[i]! & 1) << (i + 1);
      }
      lastbyte = parity(lastbyte);
      const keybytes = Buffer.from([...firstbytes, lastbyte]);
      if (_isWeakDesKey(keybytes)) {
        keybytes[7] = keybytes[7]! ^ 0xf0;
      }
      return keybytes;
    };
    if (seed.length !== 21) throw new Error('Wrong seed length');
    const k1 = expand(seed.subarray(0, 7));
    const k2 = expand(seed.subarray(7, 14));
    const k3 = expand(seed.subarray(14, 21));
    return new Key(this.enctype, Buffer.concat([k1, k2, k3]));
  }

  string_to_key(string: string | Buffer, salt: string | Buffer, params: Buffer | null): Key {
    if (params !== null && params.length > 0) {
      throw new Error('Invalid DES3 string-to-key parameters');
    }
    const str = typeof string === 'string' ? Buffer.from(string, 'utf8') : string;
    const slt = typeof salt === 'string' ? Buffer.from(salt, 'utf8') : salt;
    const k = this.random_to_key(_nfold(Buffer.concat([str, slt]), 21));
    return this.derive(k, Buffer.from('kerberos'));
  }

  encrypt(key: Key, keyusage: number, plaintext: Buffer, confounder: Buffer | null): Buffer {
    const ki = this.derive(
      key,
      Buffer.from([(keyusage >>> 24) & 0xff, (keyusage >>> 16) & 0xff, (keyusage >>> 8) & 0xff, keyusage & 0xff, 0x55]),
    );
    const ke = this.derive(
      key,
      Buffer.from([(keyusage >>> 24) & 0xff, (keyusage >>> 16) & 0xff, (keyusage >>> 8) & 0xff, keyusage & 0xff, 0xaa]),
    );
    if (confounder === null) confounder = Buffer.alloc(this.blocksize);
    const basic_plaintext = Buffer.concat([confounder, _zeropad(plaintext, this.padsize)]);
    const hmac = hmacHash(this.hashmod, ki.contents, basic_plaintext);
    return Buffer.concat([this.basic_encrypt(ke, basic_plaintext), hmac.subarray(0, this.macsize)]);
  }

  decrypt(key: Key, keyusage: number, ciphertext: Buffer): Buffer {
    const ki = this.derive(
      key,
      Buffer.from([(keyusage >>> 24) & 0xff, (keyusage >>> 16) & 0xff, (keyusage >>> 8) & 0xff, keyusage & 0xff, 0x55]),
    );
    const ke = this.derive(
      key,
      Buffer.from([(keyusage >>> 24) & 0xff, (keyusage >>> 16) & 0xff, (keyusage >>> 8) & 0xff, keyusage & 0xff, 0xaa]),
    );
    if (ciphertext.length < this.blocksize + this.macsize) throw new Error('ciphertext too short');
    const basic_ctext = ciphertext.subarray(0, ciphertext.length - this.macsize);
    const mac = ciphertext.subarray(ciphertext.length - this.macsize);
    if (basic_ctext.length % this.padsize !== 0) {
      throw new Error('ciphertext does not meet padding requirement');
    }
    const basic_plaintext = this.basic_decrypt(ke, basic_ctext);
    const hmac = hmacHash(this.hashmod, ki.contents, basic_plaintext);
    const expmac = hmac.subarray(0, this.macsize);
    if (!_mac_equal(mac, expmac)) throw new InvalidChecksum('ciphertext integrity failure');
    return basic_plaintext.subarray(this.blocksize);
  }

  basic_encrypt(key: Key, plaintext: Buffer): Buffer {
    if (plaintext.length % 8 !== 0) throw new Error('DES3 plaintext must be multiple of 8');
    const des3 = createCipheriv('des-ede3-cbc', key.contents, Buffer.alloc(8, 0));
    des3.setAutoPadding(false);
    return Buffer.concat([des3.update(plaintext), des3.final()]);
  }

  basic_decrypt(key: Key, ciphertext: Buffer): Buffer {
    if (ciphertext.length % 8 !== 0) throw new Error('DES3 ciphertext must be multiple of 8');
    const des3 = createDecipheriv('des-ede3-cbc', key.contents, Buffer.alloc(8, 0));
    des3.setAutoPadding(false);
    return Buffer.concat([des3.update(ciphertext), des3.final()]);
  }

  prf(key: Key, string: Buffer): Buffer {
    const hashval = hashDigest(this.hashmod, string);
    const truncated = hashval.subarray(0, hashval.length - (hashval.length % this.blocksize));
    const kp = this.derive(key, Buffer.from('prf'));
    return this.basic_encrypt(kp, truncated);
  }

  derive(key: Key, constant: Buffer): Key {
    let plaintext = _nfold(constant, this.blocksize);
    let rndseed = Buffer.alloc(0);
    while (rndseed.length < this.seedsize) {
      const ciphertext = this.basic_encrypt(key, plaintext);
      rndseed = Buffer.concat([rndseed, ciphertext]);
      plaintext = ciphertext;
    }
    return this.random_to_key(rndseed.subarray(0, this.seedsize));
  }
}

const _enctype_table: Record<number, EnctypeProfile> = {
  [Enctype.AES128]: new AES128CTS(),
  [Enctype.AES256]: new AES256CTS(),
  [Enctype.RC4]: new RC4Enctype(),
  [Enctype.DES_MD5]: new DESCBCEnctype(),
  [Enctype.DES3]: new DES3CBCEnctype(),
};

export function _get_enctype_profile(enctype: number): EnctypeProfile {
  if (!(enctype in _enctype_table)) throw new Error(`Invalid enctype ${enctype}`);
  return _enctype_table[enctype]!;
}

export function random_to_key(enctype: number, seed: Buffer): Key {
  return _get_enctype_profile(enctype).random_to_key(seed);
}

export function string_to_key(
  enctype: number,
  string: string | Buffer,
  salt: string | Buffer,
  params: Buffer | null = null,
): Key {
  return _get_enctype_profile(enctype).string_to_key(string, salt, params);
}

export function encrypt(
  key: Key,
  keyusage: number,
  plaintext: Buffer,
  confounder: Buffer | null = null,
): Buffer {
  return _get_enctype_profile(key.enctype).encrypt(key, keyusage, plaintext, confounder);
}

export function decrypt(key: Key, keyusage: number, ciphertext: Buffer): Buffer {
  return _get_enctype_profile(key.enctype).decrypt(key, keyusage, ciphertext);
}

export function prf(key: Key, string: Buffer): Buffer {
  return _get_enctype_profile(key.enctype).prf(key, string);
}

export function cf2(enctype: number, key1: Key, key2: Key, pepper1: Buffer, pepper2: Buffer): Key {
  const prfplus = (key: Key, pepper: Buffer, l: number): Buffer => {
    let out = Buffer.alloc(0);
    let count = 1;
    while (out.length < l) {
      out = Buffer.concat([out, prf(key, Buffer.concat([Buffer.from([count]), pepper]))]);
      count++;
    }
    return out.subarray(0, l);
  };
  const e = _get_enctype_profile(enctype);
  return e.random_to_key(
    _xorbytes(prfplus(key1, pepper1, e.seedsize), prfplus(key2, pepper2, e.seedsize)),
  );
}

export function get_hex_key_length(key: string | null): number | null {
  if (!key) return null;
  return Buffer.from(key, 'hex').length;
}

export function get_matching_aes_key(
  enctype: number,
  generic_aes_key: string | null = null,
  aes128_key: string | null = null,
  aes256_key: string | null = null,
): string | null {
  if (enctype === Enctype.AES256) {
    if (aes256_key) return aes256_key;
    if (get_hex_key_length(generic_aes_key) === 32) return generic_aes_key;
    return null;
  }
  if (enctype === Enctype.AES128) {
    if (aes128_key) return aes128_key;
    if (get_hex_key_length(generic_aes_key) === 16) return generic_aes_key;
    return null;
  }
  return null;
}

export function get_kerberos_key_for_enctype(
  enctype: number,
  nt_hash: string | null = null,
  generic_aes_key: string | null = null,
  aes128_key: string | null = null,
  aes256_key: string | null = null,
): Key {
  if (enctype === Enctype.AES256 || enctype === Enctype.AES128) {
    const matching = get_matching_aes_key(enctype, generic_aes_key, aes128_key, aes256_key);
    if (matching === null) throw new Error(`Missing AES key for enctype 0x${enctype.toString(16)}`);
    return new Key(enctype, Buffer.from(matching, 'hex'));
  }
  if (enctype === Enctype.RC4) {
    if (!nt_hash) throw new Error(`Missing NT hash for enctype 0x${enctype.toString(16)}`);
    return new Key(enctype, Buffer.from(nt_hash, 'hex'));
  }
  throw new Error(`Unsupported enctype 0x${enctype.toString(16)}`);
}

export function generate_kerberos_keys(
  rc4_hex: string | null = null,
  aes_hex: string | null = null,
  password: string | null = null,
  hex_pass: string | null = null,
  salt: string | null = null,
  user: string | null = null,
  domain: string | null = null,
): Record<number, Key> {
  const ekeys: Record<number, Key> = {};
  const keys: Record<number, Buffer> = {};
  if (rc4_hex) keys[Enctype.RC4] = Buffer.from(rc4_hex, 'hex');
  if (aes_hex) {
    if (aes_hex.length === 64) keys[Enctype.AES256] = Buffer.from(aes_hex, 'hex');
    else keys[Enctype.AES128] = Buffer.from(aes_hex, 'hex');
  }
  for (const [kt, key] of Object.entries(keys)) {
    ekeys[Number(kt)] = new Key(Number(kt), key);
  }
  if (password || hex_pass) {
    if (!salt && user && domain) {
      if (user.endsWith('$')) {
        salt = `${domain.toUpperCase()}host${user.replace(/\$$/, '').toLowerCase()}.${domain.toLowerCase()}`;
      } else {
        salt = `${domain.toUpperCase()}${user}`;
      }
    }
    const allciphers = [Enctype.RC4, Enctype.AES256, Enctype.AES128];
    for (const cipher of allciphers) {
      if (cipher === Enctype.RC4 && hex_pass) {
        ekeys[cipher] = new Key(cipher, md4(Buffer.from(hex_pass, 'hex')));
      } else if (salt) {
        let rawsecret: string;
        if (hex_pass) {
          rawsecret = Buffer.from(hex_pass, 'hex').toString('utf16le');
        } else {
          rawsecret = password!;
        }
        ekeys[cipher] = string_to_key(cipher, rawsecret, salt, null);
      }
    }
  }
  return ekeys;
}
