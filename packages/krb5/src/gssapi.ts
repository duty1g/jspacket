import { Buffer } from 'node:buffer';
import { createHash, createHmac } from 'node:crypto';
import { rc4 } from '@impacket/crypto';
import * as constants from './constants.js';
import * as crypto from './crypto.js';

export const GSS_C_DCE_STYLE = 0x1000;
export const GSS_C_DELEG_FLAG = 1;
export const GSS_C_MUTUAL_FLAG = 2;
export const GSS_C_REPLAY_FLAG = 4;
export const GSS_C_SEQUENCE_FLAG = 8;
export const GSS_C_CONF_FLAG = 0x10;
export const GSS_C_INTEG_FLAG = 0x20;

export const GSS_HMAC = 0x11;
export const GSS_RC4 = 0x10;

export const KG_USAGE_ACCEPTOR_SEAL = 22;
export const KG_USAGE_ACCEPTOR_SIGN = 23;
export const KG_USAGE_INITIATOR_SEAL = 24;
export const KG_USAGE_INITIATOR_SIGN = 25;

export const KRB5_AP_REQ = Buffer.from([0x01, 0x00]);
export const KRB_OID = Buffer.from('06092a864886f712010202', 'hex');

function _calculateMICPad(data: Buffer): Buffer {
  const pad = (4 - (data.length % 4)) & 0x3;
  return Buffer.alloc(pad, pad);
}

export class MechIndepToken {
  data: Buffer;
  token_oid: Buffer;

  constructor(data: Buffer, oid: Buffer = KRB_OID) {
    this.data = data;
    this.token_oid = oid;
  }

  static from_bytes(data: Buffer): MechIndepToken {
    if (data[0] !== 0x60) throw new Error('Incorrect token data!');
    const [length, off1] = MechIndepToken.get_length(data.subarray(1));
    const token_data = data.subarray(1 + off1, 1 + off1 + length);
    const [oid_length, off2] = MechIndepToken.get_length(token_data.subarray(1));
    const token_oid = token_data.subarray(0, 1 + off2 + oid_length);
    const remaining = token_data.subarray(1 + off2 + oid_length);
    return new MechIndepToken(Buffer.from(remaining), Buffer.from(token_oid));
  }

  static get_length(data: Buffer): [number, number] {
    if (data[0]! < 128) return [data[0]!, 1];
    const bytes_count = data[0]! - 128;
    let length = 0;
    for (let i = 1; i <= bytes_count; i++) {
      length = (length << 8) | data[i]!;
    }
    return [length, 1 + bytes_count];
  }

  static encode_length(length: number): Buffer {
    if (length < 128) return Buffer.from([length]);
    const lb = Buffer.alloc(Math.ceil((Math.log2(length) + 1) / 8));
    lb.writeUIntBE(length, 0, lb.length);
    return Buffer.concat([Buffer.from([128 + lb.length]), lb]);
  }

  to_bytes(): [Buffer, Buffer] {
    const temp = Buffer.concat([this.token_oid, this.data]);
    const header = Buffer.concat([
      Buffer.from([0x60]),
      MechIndepToken.encode_length(temp.length),
      temp,
    ]);
    return [header.subarray(0, header.length - this.data.length), this.data];
  }
}

export class CheckSumField {
  Lgth = 16;
  Bnd: Buffer = Buffer.alloc(0);
  Flags = 0;

  getData(): Buffer {
    const buf = Buffer.alloc(24);
    buf.writeUInt32LE(this.Lgth, 0);
    this.Bnd.copy(buf, 4, 0, 16);
    buf.writeUInt32LE(this.Flags, 20);
    return buf;
  }

  static SIZE = 24;
}

interface GSSAPIImpl {
  GSS_GetMIC(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    direction?: string,
  ): Buffer;
  GSS_Wrap(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    direction?: string,
    encrypt?: boolean,
    authData?: Buffer | null,
  ): [Buffer, Buffer];
  GSS_Unwrap(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    direction?: string,
    encrypt?: boolean,
    authData?: Buffer | null,
  ): [Buffer, Buffer];
}

export function GSSAPI(cipher: { enctype: number }): GSSAPIImpl {
  if (cipher.enctype === constants.EncryptionTypes.aes256_cts_hmac_sha1_96)
    return new GSSAPI_AES256();
  if (cipher.enctype === constants.EncryptionTypes.aes128_cts_hmac_sha1_96)
    return new GSSAPI_AES128();
  if (cipher.enctype === constants.EncryptionTypes.rc4_hmac) return new GSSAPI_RC4();
  throw new Error(`Unsupported etype 0x${cipher.enctype.toString(16)}`);
}

const GSS_GETMIC_HEADER = Buffer.from('602306092a864886f712010202', 'hex');
const GSS_WRAP_HEADER = Buffer.from('602b06092a864886f712010202', 'hex');

class GSSAPI_RC4 implements GSSAPIImpl {
  GSS_GetMIC(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    direction = 'init',
  ): Buffer {
    const pad = _calculateMICPad(data);
    data = Buffer.concat([data, pad]);

    const sgnAlg = GSS_HMAC;
    const sndSeq = Buffer.alloc(8);
    sndSeq.writeUInt32BE(sequenceNumber, 0);
    if (direction === 'init') {
      sndSeq.fill(0x00, 4);
    } else {
      sndSeq.fill(0xff, 4);
    }

    const tokenHeader = Buffer.alloc(8);
    tokenHeader.writeUInt16LE(0x0101, 0);
    tokenHeader.writeUInt16LE(sgnAlg, 2);
    tokenHeader.writeUInt32LE(0xffffffff, 4);

    const Ksign = createHmac('md5', sessionKey.contents)
      .update(Buffer.from('signaturekey\0'))
      .digest();
    let Sgn_Cksum = createHash('md5')
      .update(Buffer.concat([Buffer.from([15, 0, 0, 0]), tokenHeader, data]))
      .digest();
    Sgn_Cksum = createHmac('md5', Ksign).update(Sgn_Cksum).digest();
    const sgnCksum = Sgn_Cksum.subarray(0, 8);

    let Kseq = createHmac('md5', sessionKey.contents)
      .update(Buffer.from([0, 0, 0, 0]))
      .digest();
    Kseq = createHmac('md5', Kseq).update(sgnCksum).digest();
    const encSndSeq = rc4(Kseq, sndSeq);

    const token = Buffer.alloc(8 + 8 + 8);
    tokenHeader.copy(token, 0);
    encSndSeq.copy(token, 8);
    sgnCksum.copy(token, 16);

    return Buffer.concat([GSS_GETMIC_HEADER, token]);
  }

  GSS_Wrap(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    direction = 'init',
    encrypt = true,
    _authData: Buffer | null = null,
  ): [Buffer, Buffer] {
    const pad = (8 - (data.length % 8)) & 0x7;
    data = Buffer.concat([data, Buffer.alloc(pad, pad)]);

    const sgnAlg = GSS_HMAC;
    const sealAlg = GSS_RC4;
    const sndSeq = Buffer.alloc(8);
    sndSeq.writeUInt32BE(sequenceNumber, 0);
    if (direction === 'init') {
      sndSeq.fill(0x00, 4);
    } else {
      sndSeq.fill(0xff, 4);
    }

    const confounder = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) confounder[i] = Math.floor(Math.random() * 256);

    const tokenHeader = Buffer.alloc(8);
    tokenHeader.writeUInt16LE(0x0102, 0);
    tokenHeader.writeUInt16LE(sgnAlg, 2);
    tokenHeader.writeUInt16LE(sealAlg, 4);
    tokenHeader.writeUInt16LE(0xffff, 6);

    const Ksign = createHmac('md5', sessionKey.contents)
      .update(Buffer.from('signaturekey\0'))
      .digest();
    let Sgn_Cksum = createHash('md5')
      .update(Buffer.concat([Buffer.from([13, 0, 0, 0]), tokenHeader, confounder, data]))
      .digest();

    const Klocal = Buffer.from(sessionKey.contents.map((b) => b ^ 0xf0));
    let Kcrypt = createHmac('md5', Klocal)
      .update(Buffer.from([0, 0, 0, 0]))
      .digest();
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32BE(sequenceNumber, 0);
    Kcrypt = createHmac('md5', Kcrypt).update(seqBuf).digest();

    Sgn_Cksum = createHmac('md5', Ksign).update(Sgn_Cksum).digest();
    const sgnCksum = Sgn_Cksum.subarray(0, 8);

    let Kseq = createHmac('md5', sessionKey.contents)
      .update(Buffer.from([0, 0, 0, 0]))
      .digest();
    Kseq = createHmac('md5', Kseq).update(sgnCksum).digest();
    const encSndSeq = rc4(Kseq, sndSeq);

    let cipherText: Buffer;
    if (encrypt) {
      const rc4cipher = rc4(Kcrypt, Buffer.concat([confounder, data]));
      cipherText = rc4cipher.subarray(8);
    } else {
      cipherText = data;
    }

    const token = Buffer.alloc(8 + 8 + 8 + 8);
    tokenHeader.copy(token, 0);
    encSndSeq.copy(token, 8);
    sgnCksum.copy(token, 16);
    confounder.copy(token, 24);

    return [cipherText, Buffer.concat([GSS_WRAP_HEADER, token])];
  }

  GSS_Unwrap(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    direction = 'init',
    encrypt = true,
    authData: Buffer | null = null,
  ): [Buffer, Buffer] {
    return this.GSS_Wrap(sessionKey, data, sequenceNumber, direction, encrypt, authData);
  }
}

abstract class GSSAPI_AES implements GSSAPIImpl {
  abstract checkSumProfile(): crypto.EnctypeProfile;
  abstract cipherType(): crypto.EnctypeProfile;

  GSS_GetMIC(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    _direction = 'init',
  ): Buffer {
    const pad = _calculateMICPad(data);
    data = Buffer.concat([data, pad]);
    const checkSumProfile = this.checkSumProfile();

    const flags = 4;
    const sndSeq = Buffer.alloc(8);
    sndSeq.writeUInt32BE(sequenceNumber >>> 0, 0);
    sndSeq.writeUInt32BE(Math.floor(sequenceNumber / 0x100000000), 4);

    const tokenHeader = Buffer.alloc(16);
    tokenHeader.writeUInt16BE(0x0404, 0);
    tokenHeader[2] = flags;
    tokenHeader[3] = 0xff;
    tokenHeader.writeUInt32BE(0xffffffff, 4);

    const cksum = this.makeChecksum(
      checkSumProfile,
      sessionKey,
      KG_USAGE_INITIATOR_SIGN,
      Buffer.concat([data, tokenHeader]),
    );
    return Buffer.concat([tokenHeader, sndSeq, cksum.subarray(0, 12)]);
  }

  rotate(data: Buffer, numBytes: number): Buffer {
    numBytes %= data.length;
    const left = data.length - numBytes;
    return Buffer.concat([data.subarray(left), data.subarray(0, left)]);
  }

  unrotate(data: Buffer, numBytes: number): Buffer {
    numBytes %= data.length;
    return Buffer.concat([data.subarray(numBytes), data.subarray(0, numBytes)]);
  }

  GSS_Wrap(
    sessionKey: crypto.Key,
    data: Buffer,
    sequenceNumber: number,
    _direction = 'init',
    _encrypt = true,
  ): [Buffer, Buffer] {
    const cipher = this.cipherType();
    const pad = (cipher.blocksize - (data.length % cipher.blocksize)) & 15;
    data = Buffer.concat([data, Buffer.alloc(pad, 0xff)]);

    const rrc = 28;
    const flags = 6;

    const token = Buffer.alloc(16);
    token.writeUInt16BE(0x0504, 0);
    token[2] = flags;
    token[3] = 0xff;
    token.writeUInt16BE(pad, 4);
    token.writeUInt16BE(0, 6);
    token.writeUInt32BE(sequenceNumber >>> 0, 8);
    token.writeUInt32BE(Math.floor(sequenceNumber / 0x100000000), 12);

    const cipherText = cipher.encrypt(
      sessionKey,
      KG_USAGE_INITIATOR_SEAL,
      Buffer.concat([data, token]),
      null,
    );
    token.writeUInt16BE(rrc, 6);

    const rotated = this.rotate(cipherText, rrc + pad);

    const wrapSize = 16;
    const ret1 = rotated.subarray(wrapSize + rrc + pad);
    const ret2 = Buffer.concat([token, rotated.subarray(0, wrapSize + rrc + pad)]);
    return [ret1, ret2];
  }

  GSS_Unwrap(
    sessionKey: crypto.Key,
    data: Buffer,
    _sequenceNumber: number,
    _direction = 'init',
    _encrypt = true,
    authData: Buffer | null = null,
  ): [Buffer, Buffer] {
    const cipher = this.cipherType();
    if (authData === null) throw new Error('authData required for AES unwrap');
    const token = authData.subarray(8);
    const rrc = token.readUInt16BE(6);
    const ec = token.readUInt16BE(4);
    const wrapSize = 16;
    const rotated = Buffer.concat([authData.subarray(wrapSize + 8), data]);
    const cipherText = this.unrotate(rotated, rrc + ec);
    const plainText = cipher.decrypt(sessionKey, KG_USAGE_ACCEPTOR_SEAL, cipherText);
    return [plainText.subarray(0, plainText.length - (ec + wrapSize)), Buffer.alloc(0)];
  }

  makeChecksum(
    profile: crypto.EnctypeProfile,
    key: crypto.Key,
    keyusage: number,
    text: Buffer,
  ): Buffer {
    const kc = crypto._get_enctype_profile(profile.enctype);
    void kc;
    const kcKey = (kc as unknown as { derive: (k: crypto.Key, c: Buffer) => crypto.Key }).derive(
      key,
      Buffer.from([
        (keyusage >>> 24) & 0xff,
        (keyusage >>> 16) & 0xff,
        (keyusage >>> 8) & 0xff,
        keyusage & 0xff,
        0x99,
      ]),
    );
    const hmac = createHmac(profile.hashmod, kcKey.contents).update(text).digest();
    return hmac.subarray(0, profile.macsize);
  }
}

class GSSAPI_AES256 extends GSSAPI_AES {
  checkSumProfile() {
    return crypto._get_enctype_profile(constants.EncryptionTypes.aes256_cts_hmac_sha1_96);
  }
  cipherType() {
    return crypto._get_enctype_profile(constants.EncryptionTypes.aes256_cts_hmac_sha1_96);
  }
}

class GSSAPI_AES128 extends GSSAPI_AES {
  checkSumProfile() {
    return crypto._get_enctype_profile(constants.EncryptionTypes.aes128_cts_hmac_sha1_96);
  }
  cipherType() {
    return crypto._get_enctype_profile(constants.EncryptionTypes.aes128_cts_hmac_sha1_96);
  }
}
