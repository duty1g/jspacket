import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  PACTYPE,
  PAC_INFO_BUFFER,
  PAC_SIGNATURE_DATA,
  PAC_CLIENT_INFO,
  UPN_DNS_INFO,
  KERB_VALIDATION_INFO,
  KERB_SID_AND_ATTRIBUTES,
  GROUP_MEMBERSHIP,
  CHAR_FIXED_8_ARRAY,
  USER_SESSION_KEY,
  PAC_LOGON_INFO,
  PAC_CREDENTIALS_INFO,
  PAC_SERVER_CHECKSUM,
  PAC_PRIVSVR_CHECKSUM,
  PAC_CLIENT_INFO_TYPE,
  PAC_UPN_DNS_INFO,
  getPadLength,
  getBlockLength,
  buildPacType,
  signPac,
  orderedBufferTypes,
} from '../src/pac';
import { Enctype, Key } from '../src/crypto';
import { ChecksumTypes } from '../src/constants';

describe('pac', () => {
  it('PAC_INFO_BUFFER is 16 bytes', () => {
    const buf = new PAC_INFO_BUFFER();
    expect(buf.getData().length).toBe(16);
  });

  it('PAC_SIGNATURE_DATA round-trip', () => {
    const sig = new PAC_SIGNATURE_DATA();
    sig.set('SignatureType', ChecksumTypes.hmac_md5);
    sig.set('Signature', Buffer.alloc(16, 0x41));
    const data = sig.getData();
    const parsed = new PAC_SIGNATURE_DATA(data);
    expect(parsed.get('SignatureType')).toBe(ChecksumTypes.hmac_md5);
    expect((parsed.get('Signature') as Buffer).length).toBe(16);
    expect((parsed.get('Signature') as Buffer)[0]).toBe(0x41);
  });

  it('PAC_CLIENT_INFO round-trip', () => {
    const ci = new PAC_CLIENT_INFO();
    ci.set('ClientId', 0x0123456789ABCDEFn);
    const name = Buffer.from('testuser', 'utf16le');
    ci.set('NameLength', name.length);
    ci.set('Name', name);
    const data = ci.getData();
    const parsed = new PAC_CLIENT_INFO(data);
    expect(parsed.get('ClientId')).toBe(0x0123456789ABCDEFn);
    expect(parsed.get('NameLength')).toBe(name.length);
    expect((parsed.get('Name') as Buffer).toString('utf16le')).toBe('testuser');
  });

  it('UPN_DNS_INFO is 12 bytes', () => {
    const info = new UPN_DNS_INFO();
    expect(info.getData().length).toBe(12);
  });

  it('CHAR_FIXED_8_ARRAY is 8 bytes', () => {
    const arr = new CHAR_FIXED_8_ARRAY();
    expect(arr.getDataLen()).toBe(8);
  });

  it('USER_SESSION_KEY is 8 bytes', () => {
    const usk = new USER_SESSION_KEY();
    const data = usk.getData();
    expect(data.length).toBe(8);
  });

  it('GROUP_MEMBERSHIP has two ULONGs', () => {
    const gm = new GROUP_MEMBERSHIP();
    gm.set('RelativeId', 0x200);
    gm.set('Attributes', 0x7);
    const data = gm.getData();
    expect(data.length).toBe(8);
    expect(data.readUInt32LE(0)).toBe(0x200);
    expect(data.readUInt32LE(4)).toBe(0x7);
  });

  it('getPadLength and getBlockLength', () => {
    expect(getBlockLength(0)).toBe(0);
    expect(getBlockLength(1)).toBe(8);
    expect(getBlockLength(8)).toBe(8);
    expect(getBlockLength(9)).toBe(16);
    expect(getPadLength(0)).toBe(0);
    expect(getPadLength(1)).toBe(7);
    expect(getPadLength(8)).toBe(0);
    expect(getPadLength(9)).toBe(7);
  });

  it('orderedBufferTypes respects buffer_order', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(10)],
      [PAC_SERVER_CHECKSUM, Buffer.alloc(20)],
      [PAC_PRIVSVR_CHECKSUM, Buffer.alloc(16)],
    ]);
    const order = orderedBufferTypes(pacInfos, [PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_LOGON_INFO]);
    expect(order).toEqual([PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_LOGON_INFO]);
  });

  it('orderedBufferTypes defaults to insertion order', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(10)],
      [PAC_SERVER_CHECKSUM, Buffer.alloc(20)],
    ]);
    const order = orderedBufferTypes(pacInfos);
    expect(order).toEqual([PAC_LOGON_INFO, PAC_SERVER_CHECKSUM]);
  });

  it('orderedBufferTypes handles partial buffer_order', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(10)],
      [PAC_SERVER_CHECKSUM, Buffer.alloc(20)],
      [PAC_PRIVSVR_CHECKSUM, Buffer.alloc(16)],
    ]);
    const order = orderedBufferTypes(pacInfos, [PAC_SERVER_CHECKSUM]);
    expect(order[0]).toBe(PAC_SERVER_CHECKSUM);
    expect(order.length).toBe(3);
  });

  it('buildPacType produces valid PACTYPE header', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(10, 0xAA)],
      [PAC_SERVER_CHECKSUM, Buffer.alloc(20, 0xBB)],
      [PAC_PRIVSVR_CHECKSUM, Buffer.alloc(16, 0xCC)],
    ]);
    const pacType = buildPacType(pacInfos);
    expect(pacType.get('cBuffers')).toBe(3);
    expect(pacType.get('Version')).toBe(0);
    const buffers = pacType.get('Buffers') as Buffer;
    expect(buffers.length).toBe(3 * 16 + getBlockLength(10) + getBlockLength(20) + getBlockLength(16));
  });

  it('buildPacType with buffer_order respects order', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(10, 0xAA)],
      [PAC_SERVER_CHECKSUM, Buffer.alloc(20, 0xBB)],
    ]);
    const pacType = buildPacType(pacInfos, [PAC_SERVER_CHECKSUM, PAC_LOGON_INFO]);
    const buffers = pacType.get('Buffers') as Buffer;
    const firstInfo = new PAC_INFO_BUFFER(buffers.subarray(0, 16));
    expect(firstInfo.get('ulType')).toBe(PAC_SERVER_CHECKSUM);
  });

  it('signPac with RC4 (NT hash)', () => {
    const ntHash = Buffer.alloc(16, 0x42);
    const serverSig = new PAC_SIGNATURE_DATA();
    serverSig.set('SignatureType', ChecksumTypes.hmac_md5);
    serverSig.set('Signature', Buffer.alloc(16, 0));
    const privsvrSig = new PAC_SIGNATURE_DATA();
    privsvrSig.set('SignatureType', ChecksumTypes.hmac_md5);
    privsvrSig.set('Signature', Buffer.alloc(16, 0));

    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(100, 0x11)],
      [PAC_SERVER_CHECKSUM, serverSig.getData()],
      [PAC_PRIVSVR_CHECKSUM, privsvrSig.getData()],
    ]);

    const signedPac = signPac(pacInfos, { ntHash });
    const data = signedPac.getData();
    expect(data.length).toBeGreaterThan(100);

    const buffers = signedPac.get('Buffers') as Buffer;
    const numBuffers = signedPac.get('cBuffers') as number;
    const infoBuffers: PAC_INFO_BUFFER[] = [];
    for (let i = 0; i < numBuffers; i++) {
      infoBuffers.push(new PAC_INFO_BUFFER(buffers.subarray(i * 16, (i + 1) * 16)));
    }
    let serverSigOffset = -1;
    let privsvrSigOffset = -1;
    for (const ib of infoBuffers) {
      if (ib.get('ulType') === PAC_SERVER_CHECKSUM) serverSigOffset = ib.get('Offset') as number;
      if (ib.get('ulType') === PAC_PRIVSVR_CHECKSUM) privsvrSigOffset = ib.get('Offset') as number;
    }
    expect(serverSigOffset).toBeGreaterThan(0);
    expect(privsvrSigOffset).toBeGreaterThan(0);
    const serverSigData = buffers.subarray(Number(serverSigOffset) - 8);
    const serverSigParsed = new PAC_SIGNATURE_DATA(serverSigData);
    expect((serverSigParsed.get('Signature') as Buffer).some((b) => b !== 0)).toBe(true);
  });

  it('signPac throws if PAC_SERVER_CHECKSUM missing', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_PRIVSVR_CHECKSUM, Buffer.alloc(16)],
    ]);
    expect(() => signPac(pacInfos, { ntHash: Buffer.alloc(16) })).toThrow(
      'PAC_SERVER_CHECKSUM not found',
    );
  });

  it('signPac throws if PAC_PRIVSVR_CHECKSUM missing', () => {
    const pacInfos = new Map<number, Buffer>([
      [PAC_SERVER_CHECKSUM, Buffer.alloc(16)],
    ]);
    expect(() => signPac(pacInfos, { ntHash: Buffer.alloc(16) })).toThrow(
      'PAC_PRIVSVR_CHECKSUM not found',
    );
  });

  it('signPac with AES128 key', () => {
    const aesKey = Buffer.alloc(16, 0x55);
    const serverSig = new PAC_SIGNATURE_DATA();
    serverSig.set('SignatureType', ChecksumTypes.hmac_sha1_96_aes128);
    serverSig.set('Signature', Buffer.alloc(12, 0));
    const privsvrSig = new PAC_SIGNATURE_DATA();
    privsvrSig.set('SignatureType', ChecksumTypes.hmac_sha1_96_aes128);
    privsvrSig.set('Signature', Buffer.alloc(12, 0));

    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(100, 0x11)],
      [PAC_SERVER_CHECKSUM, serverSig.getData()],
      [PAC_PRIVSVR_CHECKSUM, privsvrSig.getData()],
    ]);

    const signedPac = signPac(pacInfos, { aesKey });
    const data = signedPac.getData();
    expect(data.length).toBeGreaterThan(100);
  });

  it('signPac with AES256 key', () => {
    const aesKey = Buffer.alloc(32, 0x66);
    const serverSig = new PAC_SIGNATURE_DATA();
    serverSig.set('SignatureType', ChecksumTypes.hmac_sha1_96_aes256);
    serverSig.set('Signature', Buffer.alloc(12, 0));
    const privsvrSig = new PAC_SIGNATURE_DATA();
    privsvrSig.set('SignatureType', ChecksumTypes.hmac_sha1_96_aes256);
    privsvrSig.set('Signature', Buffer.alloc(12, 0));

    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(100, 0x11)],
      [PAC_SERVER_CHECKSUM, serverSig.getData()],
      [PAC_PRIVSVR_CHECKSUM, privsvrSig.getData()],
    ]);

    const signedPac = signPac(pacInfos, { aesKey });
    const data = signedPac.getData();
    expect(data.length).toBeGreaterThan(100);
  });

  it('signPac infer AES signature type from length', () => {
    const aesKey = Buffer.alloc(32, 0x77);
    const serverSig = new PAC_SIGNATURE_DATA();
    serverSig.set('SignatureType', 0);
    serverSig.set('Signature', Buffer.alloc(12, 0));
    const privsvrSig = new PAC_SIGNATURE_DATA();
    privsvrSig.set('SignatureType', 0);
    privsvrSig.set('Signature', Buffer.alloc(12, 0));

    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(100, 0x11)],
      [PAC_SERVER_CHECKSUM, serverSig.getData()],
      [PAC_PRIVSVR_CHECKSUM, privsvrSig.getData()],
    ]);

    const signedPac = signPac(pacInfos, { aesKey, inferAesSignatureType: true });
    expect(signedPac.getData().length).toBeGreaterThan(100);
  });

  it('signPac accepts hex string keys', () => {
    const ntHashHex = '42424242424242424242424242424242';
    const serverSig = new PAC_SIGNATURE_DATA();
    serverSig.set('SignatureType', ChecksumTypes.hmac_md5);
    serverSig.set('Signature', Buffer.alloc(16, 0));
    const privsvrSig = new PAC_SIGNATURE_DATA();
    privsvrSig.set('SignatureType', ChecksumTypes.hmac_md5);
    privsvrSig.set('Signature', Buffer.alloc(16, 0));

    const pacInfos = new Map<number, Buffer>([
      [PAC_LOGON_INFO, Buffer.alloc(100, 0x11)],
      [PAC_SERVER_CHECKSUM, serverSig.getData()],
      [PAC_PRIVSVR_CHECKSUM, privsvrSig.getData()],
    ]);

    const signedPac = signPac(pacInfos, { ntHash: ntHashHex });
    expect(signedPac.getData().length).toBeGreaterThan(100);
  });

  it('PAC constants match MS-PAC', () => {
    expect(PAC_LOGON_INFO).toBe(1);
    expect(PAC_CREDENTIALS_INFO).toBe(2);
    expect(PAC_SERVER_CHECKSUM).toBe(6);
    expect(PAC_PRIVSVR_CHECKSUM).toBe(7);
    expect(PAC_CLIENT_INFO_TYPE).toBe(10);
    expect(PAC_UPN_DNS_INFO).toBe(12);
    expect(PAC_UPN_DNS_INFO).toBe(12);
    expect(PAC_PRIVSVR_CHECKSUM).toBe(7);
  });
});